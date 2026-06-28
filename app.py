import os
import json
import re
import time
import threading
from collections import defaultdict
from flask import Flask, render_template_string, jsonify, request, redirect, session, url_for, flash, Blueprint
import requests
from requests_oauthlib import OAuth2Session
from dotenv import load_dotenv
import hashlib
from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv()

app = Flask(__name__)
# Fix for Toolforge reverse proxy so OAuth redirects to HTTPS properly
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev_fallback_key")


def get_category_id(category_name):
    return hashlib.md5(category_name.encode('utf-8')).hexdigest()[:8]


app.jinja_env.globals.update(get_category_id=get_category_id)

auditor_bp = Blueprint('auditor', __name__)

# OAuth 2.0 Configuration
CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID")
CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET")
AUTHORIZATION_BASE_URL = 'https://meta.wikimedia.org/w/rest.php/oauth2/authorize'
TOKEN_URL = 'https://meta.wikimedia.org/w/rest.php/oauth2/access_token'
PROFILE_URL = 'https://meta.wikimedia.org/w/rest.php/oauth2/resource/profile'

# --- CONFIGURATION ---
API_URL = "https://commons.wikimedia.org/w/api.php"
META_API_URL = "https://meta.wikimedia.org/w/api.php"
USER_AGENT = "WLEAuditor/1.0 (ztools on Toolforge)"
HOME_DIR = os.environ.get("HOME", ".")
EVENTS_FILE = os.path.join(HOME_DIR, "events.json")
JSON_FILE = os.path.join(HOME_DIR, "removal_audit_log.json")

# The single owner account — only this user can manage roles
OWNER_USERNAME = "R1F4T"
# ---------------------

lock = threading.Lock()


def get_events_config():
    if not os.path.exists(EVENTS_FILE):
        default_config = {
            "ongoing": [],
            "archived": [],
            "event_details": {},   # category -> {tracked_users: [], ...}
            "allowed_managers": [] # users allowed to create/edit events
        }
        with open(EVENTS_FILE, 'w', encoding='utf-8') as f:
            json.dump(default_config, f, indent=4)
        return default_config
    with open(EVENTS_FILE, 'r', encoding='utf-8') as f:
        config = json.load(f)
    # Backwards compatibility
    if "event_details" not in config:
        config["event_details"] = {}
    if "allowed_managers" not in config:
        config["allowed_managers"] = []
    return config


def save_events_config(config):
    with open(EVENTS_FILE, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=4)


def get_existing_data():
    events = []
    seen_events = set()
    if os.path.exists(JSON_FILE):
        with open(JSON_FILE, mode='r', encoding='utf-8') as f:
            try:
                events = json.load(f)
            except json.JSONDecodeError:
                events = []
        for row in events:
            if "deleted" in row:
                del row["deleted"]
            # Backwards compatibility for events before we added 'category' field
            if "category" not in row:
                row["category"] = "Category:Unreviewed images from Wiki Loves Earth 2026 in Bangladesh"

            seen_events.add((row.get('timestamp'), row.get('file_title')))
    return events, seen_events


events, seen_events = get_existing_data()


def save_events():
    with open(JSON_FILE, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=4, ensure_ascii=False)


def get_leaderboard(category=None):
    """Returns leaderboard filtered by tracked_users if set for this event.
    Always reads from disk to stay consistent across restarts."""
    config = get_events_config()
    details = config.get("event_details", {}).get(category, {})
    tracked_users = details.get("tracked_users", [])

    # Always read fresh from disk so we never serve stale data
    fresh_events, _ = get_existing_data()

    lb = defaultdict(set)
    for ev in fresh_events:
        if category is None or ev.get("category") == category:
            user = ev["user"]
            if tracked_users and user not in tracked_users:
                continue
            lb[user].add(ev["file_title"])
    counts = {u: len(fs) for u, fs in lb.items()}
    sorted_counts = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    return [(i+1, u, c) for i, (u, c) in enumerate(sorted_counts)]


def catchup_missed_events():
    new_rows = 0
    config = get_events_config()
    with requests.Session() as session_req:
        for category in config["ongoing"]:
            rccontinue = None
            while True:
                params = {
                    "action": "query",
                    "format": "json",
                    "list": "recentchanges",
                    "rctype": "categorize",
                    "rctitle": category,
                    "rcprop": "user|comment|title|timestamp",
                    "rclimit": "max"
                }
                if rccontinue:
                    params["rccontinue"] = rccontinue

                try:
                    response = session_req.get(API_URL, params=params, headers={
                                               "User-Agent": USER_AGENT})
                    response.raise_for_status()
                    data = response.json()
                    if "query" in data and "recentchanges" in data["query"]:
                        for rc in data["query"]["recentchanges"]:
                            comment = rc.get("comment", "")
                            if "removed" in comment.lower():
                                timestamp = rc.get("timestamp")
                                user = rc.get("user", "Unknown")
                                match = re.search(r'\[\[(.*?)\]\]', comment)
                                file_name = match.group(
                                    1) if match else "Unknown"

                                with lock:
                                    if (timestamp, file_name) not in seen_events:
                                        events.append({
                                            "timestamp": timestamp,
                                            "user": user,
                                            "file_title": file_name,
                                            "category": category,
                                            "full_comment": comment
                                        })
                                        seen_events.add((timestamp, file_name))
                                        new_rows += 1

                    if "continue" in data and "rccontinue" in data["continue"]:
                        rccontinue = data["continue"]["rccontinue"]
                    else:
                        break
                except Exception as e:
                    print(f"Error during catch-up for {category}: {e}")
                    break

    if new_rows > 0:
        with lock:
            save_events()
    return new_rows


def listen_to_stream():
    """Connects to the Wikimedia EventStream and writes new removals to disk."""
    url = 'https://stream.wikimedia.org/v2/stream/recentchange'
    retry_delay = 5
    while True:
        try:
            print(f"[stream] Connecting to EventStream...", flush=True)
            with requests.get(
                url, stream=True,
                headers={'User-Agent': USER_AGENT, 'Accept': 'text/event-stream'},
                timeout=60
            ) as response:
                response.raise_for_status()
                retry_delay = 5  # reset on successful connect
                print(f"[stream] Connected. Listening...", flush=True)
                for line in response.iter_lines():
                    if line:
                        decoded_line = line.decode('utf-8')
                        if not decoded_line.startswith('data: '):
                            continue
                        try:
                            data = json.loads(decoded_line[6:])
                        except json.JSONDecodeError:
                            continue

                        if data.get('wiki') != 'commonswiki' or data.get('type') != 'categorize':
                            continue

                        title = data.get('title', '')
                        current_categories = get_events_config().get("ongoing", [])
                        if title not in current_categories:
                            continue

                        comment = data.get('comment', '')
                        if 'removed' not in comment.lower():
                            continue

                        user = data.get('user', 'Unknown')
                        timestamp = data.get('meta', {}).get(
                            'dt', time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
                        match = re.search(r'\[\[(.*?)\]\]', comment)
                        file_name = match.group(1) if match else 'Unknown'

                        with lock:
                            key = (timestamp, file_name)
                            if key not in seen_events:
                                events.append({
                                    "timestamp": timestamp,
                                    "user": user,
                                    "file_title": file_name,
                                    "category": title,
                                    "full_comment": comment
                                })
                                seen_events.add(key)
                                save_events()
                                print(f"[stream] Saved: {user} removed {file_name} from {title}", flush=True)
        except Exception as e:
            print(f"[stream] Error: {e}. Reconnecting in {retry_delay}s...", flush=True)
            time.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, 60)  # exponential backoff, max 60s


stream_thread = threading.Thread(target=listen_to_stream, daemon=True)
stream_thread.start()

# --- HELPERS ---

def is_owner():
    return session.get('username') == OWNER_USERNAME

def is_manager():
    username = session.get('username')
    if not username:
        return False
    if username == OWNER_USERNAME:
        return True
    config = get_events_config()
    return username in config.get('allowed_managers', [])

# --- ROUTES ---


@auditor_bp.route('/')
def index():
    config = get_events_config()
    ongoing = config['ongoing']

    return render_template_string(
        INDEX_TEMPLATE,
        ongoing=ongoing,
        selected_category=None
    )


@auditor_bp.route('/event/<event_id>')
def event_dashboard(event_id):
    config = get_events_config()
    ongoing = config['ongoing']

    selected_category = None
    for cat in ongoing + config.get('archived', []):
        if get_category_id(cat) == event_id:
            selected_category = cat
            break

    if not selected_category:
        return "Event not found", 404

    leaderboard_data = get_leaderboard(selected_category)
    details = config.get("event_details", {}).get(selected_category, {})
    tracked_users = details.get("tracked_users", [])

    return render_template_string(
        INDEX_TEMPLATE,
        leaderboard=leaderboard_data,
        ongoing=ongoing,
        selected_category=selected_category,
        tracked_users=tracked_users
    )


@auditor_bp.route('/login')
def login():
    wikimedia = OAuth2Session(
        CLIENT_ID, redirect_uri=url_for('callback', _external=True))
    authorization_url, state = wikimedia.authorization_url(
        AUTHORIZATION_BASE_URL)
    session['oauth_state'] = state
    return redirect(authorization_url)


@app.route('/auth/callback')
def callback():
    wikimedia = OAuth2Session(CLIENT_ID, state=session.get(
        'oauth_state'), redirect_uri=url_for('callback', _external=True))
    try:
        token = wikimedia.fetch_token(
            TOKEN_URL, client_secret=CLIENT_SECRET, authorization_response=request.url)
        session['oauth_token'] = token
    except Exception as e:
        return f"OAuth Token Exchange Failed: {e}"

    try:
        # Fetch username via MediaWiki API (works without identity grant)
        resp = wikimedia.get(
            API_URL,
            params={'action': 'query', 'meta': 'userinfo', 'format': 'json'},
            headers={'User-Agent': USER_AGENT}
        )
        if not resp.ok:
            return (f"OAuth API Failed: {resp.status_code} {resp.reason}<br>"
                    f"Response body: <pre>{resp.text}</pre>")
        data = resp.json()
        username = data.get('query', {}).get('userinfo', {}).get('name')
        if not username:
            return f"Could not retrieve username from API response: <pre>{resp.text}</pre>"
        session['username'] = username
        return redirect(url_for('auditor.admin'))
    except Exception as e:
        return f"OAuth Authentication Failed: {e}"


@auditor_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auditor.index'))


def login_required(f):
    from functools import wraps

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('auditor.login'))
        return f(*args, **kwargs)
    return decorated_function


def manager_required(f):
    from functools import wraps

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('auditor.login'))
        if not is_manager():
            flash("Access denied. You do not have permission to manage events.", "error")
            return redirect(url_for('auditor.index'))
        return f(*args, **kwargs)
    return decorated_function


def owner_required(f):
    from functools import wraps

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('auditor.login'))
        if not is_owner():
            flash("Access denied. Only the owner can perform this action.", "error")
            return redirect(url_for('auditor.admin'))
        return f(*args, **kwargs)
    return decorated_function


@auditor_bp.route('/admin', methods=['GET', 'POST'])
@manager_required
def admin():
    config = get_events_config()
    if request.method == 'POST':
        action = request.form.get('action')
        category = request.form.get('category', '').strip()

        if action == 'add' and category:
            if category not in config['ongoing'] and category not in config['archived']:
                config['ongoing'].append(category)
                if category not in config.get('event_details', {}):
                    config.setdefault('event_details', {})[category] = {"tracked_users": []}
                save_events_config(config)
                flash(f"Added '{category}' to ongoing events.", "success")
            else:
                flash("Event already exists.", "error")
        elif action == 'archive' and category:
            if category in config['ongoing']:
                config['ongoing'].remove(category)
                config['archived'].append(category)
                save_events_config(config)
                flash(f"Archived '{category}'.", "success")
        elif action == 'unarchive' and category:
            if category in config['archived']:
                config['archived'].remove(category)
                config['ongoing'].append(category)
                save_events_config(config)
                flash(f"Unarchived '{category}'.", "success")

        return redirect(url_for('auditor.admin'))

    return render_template_string(
        ADMIN_TEMPLATE,
        config=config,
        username=session['username'],
        is_owner=is_owner()
    )


@auditor_bp.route('/admin/event/<event_id>/users', methods=['GET', 'POST'])
@manager_required
def manage_event_users(event_id):
    config = get_events_config()
    target_category = None
    for cat in config['ongoing'] + config.get('archived', []):
        if get_category_id(cat) == event_id:
            target_category = cat
            break

    if not target_category:
        return "Event not found", 404

    details = config.setdefault('event_details', {}).setdefault(target_category, {"tracked_users": []})

    if request.method == 'POST':
        action = request.form.get('action')
        username = request.form.get('username', '').strip()
        if action == 'add_user' and username:
            if username not in details['tracked_users']:
                details['tracked_users'].append(username)
                save_events_config(config)
                flash(f"Added '{username}' to tracked users.", "success")
            else:
                flash(f"'{username}' is already tracked.", "error")
        elif action == 'remove_user' and username:
            if username in details['tracked_users']:
                details['tracked_users'].remove(username)
                save_events_config(config)
                flash(f"Removed '{username}' from tracked users.", "success")
        return redirect(url_for('auditor.manage_event_users', event_id=event_id))

    return render_template_string(
        MANAGE_USERS_TEMPLATE,
        category=target_category,
        event_id=event_id,
        tracked_users=details.get('tracked_users', []),
        username=session['username'],
        is_owner=is_owner()
    )


@auditor_bp.route('/admin/roles', methods=['GET', 'POST'])
@owner_required
def manage_roles():
    config = get_events_config()
    if request.method == 'POST':
        action = request.form.get('action')
        manager_name = request.form.get('manager_username', '').strip()
        if action == 'grant' and manager_name:
            if manager_name not in config.get('allowed_managers', []):
                config.setdefault('allowed_managers', []).append(manager_name)
                save_events_config(config)
                flash(f"Granted event manager role to '{manager_name}'.", "success")
            else:
                flash(f"'{manager_name}' is already a manager.", "error")
        elif action == 'revoke' and manager_name:
            if manager_name in config.get('allowed_managers', []):
                config['allowed_managers'].remove(manager_name)
                save_events_config(config)
                flash(f"Revoked event manager role from '{manager_name}'.", "success")
        return redirect(url_for('auditor.manage_roles'))

    return render_template_string(
        ROLES_TEMPLATE,
        config=config,
        username=session['username']
    )


@auditor_bp.route('/api/update', methods=['POST'])
def update_now():
    added = catchup_missed_events()
    return jsonify({"status": "success", "new_events": added})


@auditor_bp.route('/api/log')
def get_log():
    with lock:
        return jsonify(events)


@auditor_bp.route('/api/user-suggest')
def user_suggest():
    """Proxy to Meta-Wiki user autocomplete so the frontend can search usernames."""
    query = request.args.get('q', '')
    if not query or len(query) < 2:
        return jsonify([])
    try:
        resp = requests.get(
            META_API_URL,
            params={
                'action': 'query',
                'list': 'allusers',
                'auprefix': query,
                'aulimit': 10,
                'format': 'json'
            },
            headers={'User-Agent': USER_AGENT},
            timeout=5
        )
        data = resp.json()
        users = [u['name'] for u in data.get('query', {}).get('allusers', [])]
        return jsonify(users)
    except Exception as e:
        return jsonify([])


# --- TEMPLATES ---
INDEX_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Global Removal Leaderboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: 'Segoe UI', Tahoma, sans-serif; margin: 40px; background: #f4f4f9; color: #333; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h1 { color: #0056b3; border-bottom: 2px solid #0056b3; padding-bottom: 10px; margin-top: 0; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #0056b3; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        a { color: #0056b3; text-decoration: none; font-weight: bold; }
        a:hover { text-decoration: underline; }
        .header-bar { display: flex; justify-content: space-between; align-items: baseline; }
        select, button { padding: 8px; margin: 5px 0; border: 1px solid #ccc; border-radius: 4px; }
        .btn { background-color: #0056b3; color: white; border: none; cursor: pointer; }
        .btn:hover { background-color: #004494; }
        .cards-container { display: flex; gap: 15px; flex-wrap: wrap; margin-bottom: 20px; }
        .card { flex: 1; min-width: 250px; background: #eef; padding: 15px; border-radius: 8px; border: 2px solid transparent; text-align: center; cursor: pointer; transition: all 0.2s ease; display: flex; align-items: center; justify-content: center; text-decoration: none; color: #333; }
        .card:hover { transform: translateY(-2px); box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
        .card.active { background: #0056b3; color: white; border-color: #004494; font-weight: bold; }
        .tracked-badge { display: inline-block; background: #e8f4fd; color: #0056b3; border: 1px solid #b8d9f5; border-radius: 12px; padding: 2px 10px; font-size: 0.82em; margin-left: 6px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header-bar">
            <h1>Removal Leaderboard</h1>
            <a href="{{ url_for('auditor.admin') }}">Admin Dashboard</a>
        </div>
        
        {% if selected_category %}
        <div style="margin-bottom: 15px;">
            <a href="{{ url_for('auditor.index') }}" style="color: #666; font-weight: normal; font-size: 0.9em; text-decoration: none;">&larr; Back to Events</a>
        </div>
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #ddd; padding-bottom: 10px; margin-bottom: 20px;">
            <div>
                <h2 style="margin: 0; color: #333; font-size: 1.4em;">{{ selected_category }}</h2>
                {% if tracked_users %}
                <p style="margin: 6px 0 0; font-size: 0.85em; color: #666;">
                    Showing stats for:
                    {% for u in tracked_users %}
                    <span class="tracked-badge">{{ u }}</span>
                    {% endfor %}
                </p>
                {% endif %}
            </div>
            <button type="button" class="btn" onclick="forceUpdate()" id="updateBtn">Force Update API</button>
        </div>
        <table>
            <tr><th>Rank</th><th>User</th><th>Files Removed</th></tr>
            {% for rank, user, count in leaderboard %}
            <tr><td>{{ rank }}</td><td>{{ user }}</td><td>{{ count }}</td></tr>
            {% endfor %}
            {% if not leaderboard %}
            <tr><td colspan="3" style="text-align: center; color: #666;">No removals logged yet for this event.</td></tr>
            {% endif %}
        </table>
        {% else %}
        <h2 style="margin-top: 30px; margin-bottom: 20px; color: #444; font-size: 1.3em;">Active Campaigns</h2>
        <div class="cards-container">
            {% for cat in ongoing %}
            <a href="{{ url_for('auditor.event_dashboard', event_id=get_category_id(cat)) }}" class="card">
                <span style="font-size: 1.1em; font-weight: 500;">{{ cat.replace('Category:', '') }}</span>
            </a>
            {% endfor %}
            {% if not ongoing %}
            <div style="text-align: center; padding: 40px; background: #fff; border-radius: 8px; border: 1px solid #eee; width: 100%;">
                <p style="color: #777;">No active events configured.</p>
            </div>
            {% endif %}
        </div>
        {% endif %}
        <p style="margin-top:20px; font-size: 0.9em;"><a href="{{ url_for('auditor.get_log') }}" target="_blank">View Raw JSON Log</a></p>
    </div>
    <script>
        function forceUpdate() {
            const btn = document.getElementById('updateBtn');
            btn.disabled = true;
            btn.innerText = 'Updating...';
            fetch('{{ url_for("auditor.update_now") }}', { method: 'POST' })
            .then(res => res.json())
            .then(data => {
                alert('Found ' + data.new_events + ' new removals!');
                window.location.reload();
            })
            .catch(err => {
                alert('Update failed: ' + err);
                btn.disabled = false;
                btn.innerText = 'Force Update API';
            });
        }
    </script>
</body>
</html>
"""

ADMIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Admin Dashboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: 'Segoe UI', Tahoma, sans-serif; margin: 40px; background: #f4f4f9; color: #333; }
        .container { max-width: 860px; margin: 0 auto; background: white; padding: 24px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h1 { color: #d83434; border-bottom: 2px solid #d83434; padding-bottom: 10px; margin-top: 0; }
        h3 { margin-top: 28px; border-bottom: 1px solid #eee; padding-bottom: 6px; }
        ul { list-style: none; padding: 0; }
        li { background: #f5f5f5; margin: 6px 0; padding: 10px 14px; border-radius: 6px; display: flex; justify-content: space-between; align-items: center; gap: 10px; }
        .btn { padding: 7px 13px; border: none; border-radius: 4px; cursor: pointer; color: white; font-weight: bold; font-size: 0.88em; }
        .btn-archive { background: #f0ad4e; }
        .btn-unarchive { background: #5cb85c; }
        .btn-add { background: #0056b3; }
        .btn-users { background: #6c5ce7; }
        input[type=text] { padding: 9px; width: 60%; border: 1px solid #ccc; border-radius: 4px; font-size: 1em; }
        .form-group { display: flex; gap: 10px; margin-bottom: 20px; align-items: center; }
        a { color: #0056b3; text-decoration: none; font-weight: bold; }
        a:hover { text-decoration: underline; }
        .alert { padding: 10px 14px; margin-bottom: 14px; border-radius: 4px; font-size: 0.95em; }
        .alert-success { background: #d4edda; color: #155724; }
        .alert-error { background: #f8d7da; color: #721c24; }
        .role-badge { display: inline-block; background: #6c5ce7; color: white; border-radius: 12px; padding: 2px 10px; font-size: 0.8em; margin-left: 6px; }
        .owner-badge { background: #e17055; }
        .li-actions { display: flex; gap: 8px; align-items: center; flex-shrink: 0; }
        .cat-name { flex: 1; word-break: break-all; }
    </style>
</head>
<body>
    <div class="container">
        <div style="display: flex; justify-content: space-between; align-items: baseline;">
            <h1>Admin Dashboard</h1>
            <span>
                Logged in as <strong>{{ username }}</strong>
                {% if is_owner %}<span class="role-badge owner-badge">Owner</span>{% else %}<span class="role-badge">Manager</span>{% endif %}
                &nbsp;|&nbsp;<a href="{{ url_for('auditor.logout') }}">Logout</a>
            </span>
        </div>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
            <div class="alert alert-{{ 'success' if category == 'success' else 'error' }}">{{ message }}</div>
            {% endfor %}
          {% endif %}
        {% endwith %}

        {% if is_owner %}
        <div style="background:#fff8e1; border:1px solid #ffe082; padding:10px 14px; border-radius:6px; margin-bottom:20px; font-size:0.92em;">
            🔑 <strong>Owner Controls:</strong>
            <a href="{{ url_for('auditor.manage_roles') }}" style="margin-left:10px;">Manage Event Managers &rarr;</a>
        </div>
        {% endif %}

        <h3>Add New Event</h3>
        <form method="POST" class="form-group">
            <input type="hidden" name="action" value="add">
            <input type="text" name="category" id="categoryInput" placeholder="e.g. Category:Unreviewed images from Wiki Loves Earth 2027..." required autocomplete="off">
            <button type="submit" class="btn btn-add">Track Category</button>
        </form>

        <h3>Ongoing Events (Live)</h3>
        <ul>
            {% for cat in config.ongoing %}
            <li>
                <span class="cat-name">{{ cat }}</span>
                <div class="li-actions">
                    <a href="{{ url_for('auditor.manage_event_users', event_id=get_category_id(cat)) }}" class="btn btn-users">👥 Users</a>
                    <form method="POST" style="margin: 0;">
                        <input type="hidden" name="action" value="archive">
                        <input type="hidden" name="category" value="{{ cat }}">
                        <button type="submit" class="btn btn-archive">Archive</button>
                    </form>
                </div>
            </li>
            {% else %}
            <li style="justify-content: center; color: #777;">No ongoing events.</li>
            {% endfor %}
        </ul>

        <h3>Archived Events</h3>
        <ul>
            {% for cat in config.archived %}
            <li>
                <span class="cat-name" style="color: #777;">{{ cat }}</span>
                <div class="li-actions">
                    <a href="{{ url_for('auditor.manage_event_users', event_id=get_category_id(cat)) }}" class="btn btn-users">👥 Users</a>
                    <form method="POST" style="margin: 0;">
                        <input type="hidden" name="action" value="unarchive">
                        <input type="hidden" name="category" value="{{ cat }}">
                        <button type="submit" class="btn btn-unarchive">Restore</button>
                    </form>
                </div>
            </li>
            {% else %}
            <li style="justify-content: center; color: #777;">No archived events.</li>
            {% endfor %}
        </ul>
        
        <div style="margin-top: 30px;">
            <a href="{{ url_for('auditor.index') }}">&larr; Back to Home</a>
        </div>
    </div>
</body>
</html>
"""

MANAGE_USERS_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Manage Tracked Users – {{ category }}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: 'Segoe UI', Tahoma, sans-serif; margin: 40px; background: #f4f4f9; color: #333; }
        .container { max-width: 700px; margin: 0 auto; background: white; padding: 24px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h1 { color: #6c5ce7; border-bottom: 2px solid #6c5ce7; padding-bottom: 10px; margin-top: 0; font-size: 1.4em; }
        .sub { color: #666; font-size: 0.9em; margin-top: -10px; margin-bottom: 20px; }
        ul { list-style: none; padding: 0; }
        li { background: #f5f5f5; margin: 6px 0; padding: 10px 14px; border-radius: 6px; display: flex; justify-content: space-between; align-items: center; }
        .btn { padding: 7px 13px; border: none; border-radius: 4px; cursor: pointer; color: white; font-weight: bold; font-size: 0.88em; }
        .btn-add { background: #6c5ce7; }
        .btn-remove { background: #d63031; }
        .form-group { display: flex; gap: 10px; margin-bottom: 20px; position: relative; }
        .input-wrap { position: relative; flex: 1; }
        input[type=text] { padding: 9px; width: 100%; border: 1px solid #ccc; border-radius: 4px; font-size: 1em; box-sizing: border-box; }
        a { color: #6c5ce7; text-decoration: none; font-weight: bold; }
        a:hover { text-decoration: underline; }
        .alert { padding: 10px 14px; margin-bottom: 14px; border-radius: 4px; font-size: 0.95em; }
        .alert-success { background: #d4edda; color: #155724; }
        .alert-error { background: #f8d7da; color: #721c24; }
        #suggestions { position: absolute; top: 100%; left: 0; right: 0; background: white; border: 1px solid #ccc; border-top: none; border-radius: 0 0 6px 6px; z-index: 100; max-height: 200px; overflow-y: auto; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
        .suggestion-item { padding: 9px 14px; cursor: pointer; font-size: 0.95em; }
        .suggestion-item:hover { background: #f0eeff; color: #6c5ce7; }
        .info-box { background: #f0eeff; border: 1px solid #d4c9ff; border-radius: 6px; padding: 12px 16px; margin-bottom: 20px; font-size: 0.9em; color: #444; }
    </style>
</head>
<body>
    <div class="container">
        <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 4px;">
            <h1>👥 Tracked Users</h1>
            <span style="font-size:0.85em; color:#666;">Logged in as <strong>{{ username }}</strong></span>
        </div>
        <p class="sub">Event: <strong>{{ category }}</strong></p>

        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for cat, message in messages %}
            <div class="alert alert-{{ 'success' if cat == 'success' else 'error' }}">{{ message }}</div>
            {% endfor %}
          {% endif %}
        {% endwith %}

        <div class="info-box">
            ℹ️ Only users added here will appear in the event's leaderboard dashboard.
            If no users are added, <strong>all users</strong> are shown.
        </div>

        <h3 style="margin-top:0;">Add User to Track</h3>
        <form method="POST" class="form-group" autocomplete="off" onsubmit="return validateUser()">
            <input type="hidden" name="action" value="add_user">
            <div class="input-wrap">
                <input type="text" name="username" id="usernameInput" placeholder="Type a Wikimedia username…" required>
                <div id="suggestions"></div>
            </div>
            <button type="submit" class="btn btn-add">Add User</button>
        </form>

        <h3>Currently Tracked ({{ tracked_users|length }})</h3>
        {% if tracked_users %}
        <ul>
            {% for u in tracked_users %}
            <li>
                <span>{{ u }}</span>
                <form method="POST" style="margin:0;">
                    <input type="hidden" name="action" value="remove_user">
                    <input type="hidden" name="username" value="{{ u }}">
                    <button type="submit" class="btn btn-remove">Remove</button>
                </form>
            </li>
            {% endfor %}
        </ul>
        {% else %}
        <p style="color:#777; font-style:italic;">No users tracked yet. All contributors will be shown in the leaderboard.</p>
        {% endif %}

        <div style="margin-top: 28px; display:flex; gap:20px;">
            <a href="{{ url_for('auditor.admin') }}">&larr; Back to Admin</a>
            <a href="{{ url_for('auditor.event_dashboard', event_id=event_id) }}" target="_blank">View Dashboard &rarr;</a>
        </div>
    </div>

    <script>
        const input = document.getElementById('usernameInput');
        const suggestionsBox = document.getElementById('suggestions');
        let debounceTimer;

        input.addEventListener('input', function () {
            clearTimeout(debounceTimer);
            const query = this.value.trim();
            if (query.length < 2) {
                suggestionsBox.innerHTML = '';
                return;
            }
            debounceTimer = setTimeout(() => {
                fetch('/api/user-suggest?q=' + encodeURIComponent(query))
                    .then(r => r.json())
                    .then(users => {
                        suggestionsBox.innerHTML = '';
                        users.forEach(u => {
                            const div = document.createElement('div');
                            div.className = 'suggestion-item';
                            div.textContent = u;
                            div.addEventListener('click', () => {
                                input.value = u;
                                suggestionsBox.innerHTML = '';
                            });
                            suggestionsBox.appendChild(div);
                        });
                    });
            }, 250);
        });

        document.addEventListener('click', function (e) {
            if (!e.target.closest('.input-wrap')) suggestionsBox.innerHTML = '';
        });

        function validateUser() {
            if (!input.value.trim()) { alert('Please enter a username.'); return false; }
            return true;
        }
    </script>
</body>
</html>
"""

ROLES_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Manage Roles – Owner Panel</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: 'Segoe UI', Tahoma, sans-serif; margin: 40px; background: #f4f4f9; color: #333; }
        .container { max-width: 620px; margin: 0 auto; background: white; padding: 24px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h1 { color: #e17055; border-bottom: 2px solid #e17055; padding-bottom: 10px; margin-top: 0; }
        ul { list-style: none; padding: 0; }
        li { background: #f5f5f5; margin: 6px 0; padding: 10px 14px; border-radius: 6px; display: flex; justify-content: space-between; align-items: center; }
        .btn { padding: 7px 13px; border: none; border-radius: 4px; cursor: pointer; color: white; font-weight: bold; font-size: 0.88em; }
        .btn-grant { background: #00b894; }
        .btn-revoke { background: #d63031; }
        .form-group { display: flex; gap: 10px; margin-bottom: 20px; position: relative; }
        .input-wrap { position: relative; flex: 1; }
        input[type=text] { padding: 9px; width: 100%; border: 1px solid #ccc; border-radius: 4px; font-size: 1em; box-sizing: border-box; }
        a { color: #e17055; text-decoration: none; font-weight: bold; }
        a:hover { text-decoration: underline; }
        .alert { padding: 10px 14px; margin-bottom: 14px; border-radius: 4px; font-size: 0.95em; }
        .alert-success { background: #d4edda; color: #155724; }
        .alert-error { background: #f8d7da; color: #721c24; }
        #suggestions { position: absolute; top: 100%; left: 0; right: 0; background: white; border: 1px solid #ccc; border-top: none; border-radius: 0 0 6px 6px; z-index: 100; max-height: 200px; overflow-y: auto; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
        .suggestion-item { padding: 9px 14px; cursor: pointer; font-size: 0.95em; }
        .suggestion-item:hover { background: #fff5f5; color: #e17055; }
    </style>
</head>
<body>
    <div class="container">
        <div style="display:flex; justify-content:space-between; align-items:baseline;">
            <h1>🔑 Manage Roles</h1>
            <span style="font-size:0.85em; color:#666;">Owner: <strong>{{ username }}</strong></span>
        </div>

        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for cat, message in messages %}
            <div class="alert alert-{{ 'success' if cat == 'success' else 'error' }}">{{ message }}</div>
            {% endfor %}
          {% endif %}
        {% endwith %}

        <h3>Grant Event Manager Role</h3>
        <form method="POST" class="form-group" autocomplete="off">
            <input type="hidden" name="action" value="grant">
            <div class="input-wrap">
                <input type="text" name="manager_username" id="managerInput" placeholder="Wikimedia username…" required>
                <div id="suggestions"></div>
            </div>
            <button type="submit" class="btn btn-grant">Grant</button>
        </form>

        <h3>Current Event Managers</h3>
        <ul>
            {% for mgr in config.allowed_managers %}
            <li>
                <span>{{ mgr }}</span>
                <form method="POST" style="margin:0;">
                    <input type="hidden" name="action" value="revoke">
                    <input type="hidden" name="manager_username" value="{{ mgr }}">
                    <button type="submit" class="btn btn-revoke">Revoke</button>
                </form>
            </li>
            {% else %}
            <li style="justify-content:center; color:#777;">No managers assigned yet.</li>
            {% endfor %}
        </ul>

        <div style="margin-top: 28px;">
            <a href="{{ url_for('auditor.admin') }}">&larr; Back to Admin</a>
        </div>
    </div>

    <script>
        const input = document.getElementById('managerInput');
        const suggestionsBox = document.getElementById('suggestions');
        let debounceTimer;

        input.addEventListener('input', function () {
            clearTimeout(debounceTimer);
            const query = this.value.trim();
            if (query.length < 2) { suggestionsBox.innerHTML = ''; return; }
            debounceTimer = setTimeout(() => {
                fetch('/api/user-suggest?q=' + encodeURIComponent(query))
                    .then(r => r.json())
                    .then(users => {
                        suggestionsBox.innerHTML = '';
                        users.forEach(u => {
                            const div = document.createElement('div');
                            div.className = 'suggestion-item';
                            div.textContent = u;
                            div.addEventListener('click', () => {
                                input.value = u;
                                suggestionsBox.innerHTML = '';
                            });
                            suggestionsBox.appendChild(div);
                        });
                    });
            }, 250);
        });

        document.addEventListener('click', function (e) {
            if (!e.target.closest('.input-wrap')) suggestionsBox.innerHTML = '';
        });
    </script>
</body>
</html>
"""

app.register_blueprint(auditor_bp)

if __name__ == '__main__':
    catchup_missed_events()
    app.run(host='0.0.0.0', port=8000)

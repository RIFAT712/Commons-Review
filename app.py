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
USER_AGENT = "WLEAuditor/1.0 (ztools on Toolforge)"
HOME_DIR = os.environ.get("HOME", ".")
EVENTS_FILE = os.path.join(HOME_DIR, "events.json")
JSON_FILE = os.path.join(HOME_DIR, "removal_audit_log.json")
# ---------------------

lock = threading.Lock()


def get_events_config():
    if not os.path.exists(EVENTS_FILE):
        default_config = {
            "ongoing": ["Category:Unreviewed images from Wiki Loves Earth 2026 in Bangladesh"],
            "archived": []
        }
        with open(EVENTS_FILE, 'w', encoding='utf-8') as f:
            json.dump(default_config, f, indent=4)
        return default_config
    with open(EVENTS_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)


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
    with lock:
        lb = defaultdict(set)
        for ev in events:
            if category is None or ev.get("category") == category:
                lb[ev["user"]].add(ev["file_title"])
        counts = {u: len(fs) for u, fs in lb.items()}
        sorted_counts = sorted(
            counts.items(), key=lambda x: x[1], reverse=True)
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
    url = 'https://stream.wikimedia.org/v2/stream/recentchange'
    while True:
        try:
            with requests.get(url, stream=True, headers={'User-Agent': USER_AGENT, 'Accept': 'text/event-stream'}, timeout=120) as response:
                response.raise_for_status()
                for line in response.iter_lines():
                    if line:
                        decoded_line = line.decode('utf-8')
                        if decoded_line.startswith('data: '):
                            try:
                                data = json.loads(decoded_line[6:])
                                if data.get('wiki') == 'commonswiki' and data.get('type') == 'categorize':
                                    title = data.get('title')
                                    current_categories = get_events_config()[
                                        "ongoing"]
                                    if title in current_categories:
                                        comment = data.get('comment', '')
                                        if "removed" in comment.lower():
                                            user = data.get('user', 'Unknown')
                                            timestamp = data.get('meta', {}).get(
                                                'dt', time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
                                            file_name = "Unknown"
                                            match = re.search(
                                                r'\[\[(.*?)\]\]', comment)
                                            if match:
                                                file_name = match.group(1)

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
                            except json.JSONDecodeError:
                                pass
        except Exception as e:
            time.sleep(5)


stream_thread = threading.Thread(target=listen_to_stream, daemon=True)
stream_thread.start()

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

    return render_template_string(
        INDEX_TEMPLATE,
        leaderboard=leaderboard_data,
        ongoing=ongoing,
        selected_category=selected_category
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


@auditor_bp.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    config = get_events_config()
    if request.method == 'POST':
        action = request.form.get('action')
        category = request.form.get('category')

        if action == 'add' and category:
            if category not in config['ongoing'] and category not in config['archived']:
                config['ongoing'].append(category)
                save_events_config(config)
                flash(f"Added {category} to ongoing events.", "success")
        elif action == 'archive' and category:
            if category in config['ongoing']:
                config['ongoing'].remove(category)
                config['archived'].append(category)
                save_events_config(config)
                flash(f"Archived {category}.", "success")
        elif action == 'unarchive' and category:
            if category in config['archived']:
                config['archived'].remove(category)
                config['ongoing'].append(category)
                save_events_config(config)
                flash(f"Unarchived {category}.", "success")

        return redirect(url_for('auditor.admin'))

    return render_template_string(ADMIN_TEMPLATE, config=config, username=session['username'])


@auditor_bp.route('/api/update', methods=['POST'])
def update_now():
    added = catchup_missed_events()
    return jsonify({"status": "success", "new_events": added})


@auditor_bp.route('/api/log')
def get_log():
    with lock:
        return jsonify(events)


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
            <h2 style="margin: 0; color: #333; font-size: 1.4em;">{{ selected_category }}</h2>
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
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h1 { color: #d83434; border-bottom: 2px solid #d83434; padding-bottom: 10px; margin-top: 0; }
        ul { list-style: none; padding: 0; }
        li { background: #eee; margin: 5px 0; padding: 10px; border-radius: 4px; display: flex; justify-content: space-between; align-items: center; }
        .btn { padding: 8px 12px; border: none; border-radius: 4px; cursor: pointer; color: white; font-weight: bold; }
        .btn-archive { background: #f0ad4e; }
        .btn-unarchive { background: #5cb85c; }
        .btn-add { background: #0056b3; }
        input[type=text] { padding: 10px; width: 65%; border: 1px solid #ccc; border-radius: 4px; }
        .form-group { display: flex; gap: 10px; margin-bottom: 20px; }
        a { color: #0056b3; text-decoration: none; font-weight: bold; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <div style="display: flex; justify-content: space-between; align-items: baseline;">
            <h1>Admin Dashboard</h1>
            <span>Logged in as <strong>{{ username }}</strong> | <a href="{{ url_for('auditor.logout') }}">Logout</a></span>
        </div>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
            <div style="background: #d4edda; color: #155724; padding: 10px; margin-bottom: 15px; border-radius: 4px;">
              {{ message }}
            </div>
            {% endfor %}
          {% endif %}
        {% endwith %}

        <h3>Add New Event</h3>
        <form method="POST" class="form-group">
            <input type="hidden" name="action" value="add">
            <input type="text" name="category" placeholder="e.g. Category:Unreviewed images from Wiki Loves Earth 2027..." required>
            <button type="submit" class="btn btn-add">Track Category</button>
        </form>

        <h3>Ongoing Events (Live)</h3>
        <ul>
            {% for cat in config.ongoing %}
            <li>
                <span>{{ cat }}</span>
                <form method="POST" style="margin: 0;">
                    <input type="hidden" name="action" value="archive">
                    <input type="hidden" name="category" value="{{ cat }}">
                    <button type="submit" class="btn btn-archive">Archive</button>
                </form>
            </li>
            {% else %}
            <li style="justify-content: center; color: #777;">No ongoing events.</li>
            {% endfor %}
        </ul>

        <h3>Archived Events</h3>
        <ul>
            {% for cat in config.archived %}
            <li>
                <span style="color: #777;">{{ cat }}</span>
                <form method="POST" style="margin: 0;">
                    <input type="hidden" name="action" value="unarchive">
                    <input type="hidden" name="category" value="{{ cat }}">
                    <button type="submit" class="btn btn-unarchive">Restore</button>
                </form>
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

app.register_blueprint(auditor_bp)

if __name__ == '__main__':
    catchup_missed_events()
    app.run(host='0.0.0.0', port=8000)

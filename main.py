import requests
import json
import re
import os
import time
import threading
from collections import defaultdict
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer, ThreadingMixIn

# --- CONFIGURATION ---
API_URL = "https://commons.wikimedia.org/w/api.php"
USER_AGENT = "WLE2026BangladeshAuditor/1.0 (contact: yahya.commons@gmail.com; user: yahya)"
CATEGORY = "Category:Unreviewed images from Wiki Loves Earth 2026 in Bangladesh"
JSON_FILE = "removal_audit_log.json"
PORT = 8000
# ---------------------

lock = threading.Lock()


def get_existing_data():
    events = []
    seen_events = set()
    events_by_user = defaultdict(set)
    if os.path.exists(JSON_FILE):
        with open(JSON_FILE, mode='r', encoding='utf-8') as f:
            try:
                events = json.load(f)
            except json.JSONDecodeError:
                events = []
        for row in events:
            # Clean up the deleted property as requested
            if "deleted" in row:
                del row["deleted"]
            key = (row.get('timestamp'), row.get('file_title'))
            seen_events.add(key)
            events_by_user[row.get('user')].add(row.get('file_title'))
    return events, seen_events, events_by_user


events, seen_events, events_by_user = get_existing_data()


def save_events():
    with open(JSON_FILE, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=4, ensure_ascii=False)


def catchup_missed_events():
    print("Fetching missed events from API to catch up...")
    new_rows = []
    rccontinue = None
    with requests.Session() as session:
        while True:
            params = {
                "action": "query",
                "format": "json",
                "list": "recentchanges",
                "rctype": "categorize",
                "rctitle": CATEGORY,
                "rcprop": "user|comment|title|timestamp",
                "rclimit": "max"
            }
            if rccontinue:
                params["rccontinue"] = rccontinue

            try:
                response = session.get(API_URL, params=params, headers={
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
                            file_name = match.group(1) if match else "Unknown"

                            with lock:
                                if (timestamp, file_name) not in seen_events:
                                    events.append({
                                        "timestamp": timestamp,
                                        "user": user,
                                        "file_title": file_name,
                                        "full_comment": comment
                                    })
                                    seen_events.add((timestamp, file_name))
                                    events_by_user[user].add(file_name)
                                    new_rows.append(file_name)

                if "continue" in data and "rccontinue" in data["continue"]:
                    rccontinue = data["continue"]["rccontinue"]
                else:
                    break
            except Exception as e:
                print(f"Error during catch-up: {e}")
                break

    if new_rows:
        print(f"Caught up {len(new_rows)} missed events.")
        with lock:
            save_events()
    else:
        print("No missed events found. Up to date.")


def listen_to_stream():
    url = 'https://stream.wikimedia.org/v2/stream/recentchange'
    print(f"Connecting to Wikimedia EventStreams at {url}...")
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
                                    if data.get('title') == CATEGORY:
                                        comment = data.get('comment', '')
                                        if "removed" in comment.lower():
                                            user = data.get('user', 'Unknown')
                                            timestamp = data.get('meta', {}).get(
                                                'dt', time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
                                            match = re.search(
                                                r'\[\[(.*?)\]\]', comment)
                                            file_name = match.group(
                                                1) if match else "Unknown"

                                            with lock:
                                                key = (timestamp, file_name)
                                                if key not in seen_events:
                                                    events.append({
                                                        "timestamp": timestamp,
                                                        "user": user,
                                                        "file_title": file_name,
                                                        "full_comment": comment
                                                    })
                                                    seen_events.add(key)
                                                    events_by_user[user].add(
                                                        file_name)
                                                    save_events()
                                                    print(
                                                        f"[{timestamp}] Added live event: {user} removed {file_name}")
                            except json.JSONDecodeError:
                                pass
        except Exception as e:
            print(f"Stream error: {e}, reconnecting in 5 seconds...")
            time.sleep(5)


class ThreadedTCPServer(ThreadingMixIn, TCPServer):
    allow_reuse_address = True


class CustomHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Cache-Control', 'no-cache, must-revalidate')
        super().end_headers()

    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()

            with lock:
                leaderboard = {u: len(fs) for u, fs in events_by_user.items()}
                sorted_counts = sorted(
                    leaderboard.items(), key=lambda x: x[1], reverse=True)

            html = f"""<!DOCTYPE html>
<html>
<head>
    <title>WLE 2026 Global Removal Leaderboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background-color: #f4f4f9; color: #333; }}
        .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        h1 {{ color: #0056b3; border-bottom: 2px solid #0056b3; padding-bottom: 10px; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #0056b3; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        a {{ color: #0056b3; text-decoration: none; font-weight: bold; }}
        a:hover {{ text-decoration: underline; }}
        .meta {{ font-size: 0.9em; color: #666; margin-bottom: 20px; }}
        .status {{ display: inline-block; width: 10px; height: 10px; background: #28a745; border-radius: 50%; margin-right: 5px; }}
    </style>
    <script>
        // Auto-refresh every 30 seconds
        setTimeout(function(){{ window.location.reload(1); }}, 30000);
    </script>
</head>
<body>
    <div class="container">
        <h1>WLE 2026 Global Removal Leaderboard</h1>
        <div class="meta">
            <p><span class="status"></span><strong>Live System Active</strong></p>
            <p>Watching for removals from: <strong>{CATEGORY}</strong></p>
            <p><a href="/removal_audit_log.json" target="_blank">View Raw JSON Log</a> | Auto-updates every 30s</p>
        </div>
        <table>
            <tr>
                <th>Rank</th>
                <th>User</th>
                <th>Files Removed</th>
            </tr>
"""
            for rank, (user, count) in enumerate(sorted_counts, 1):
                html += f"""
            <tr>
                <td>{rank}</td>
                <td>{user}</td>
                <td>{count}</td>
            </tr>"""
            html += """
        </table>
    </div>
</body>
</html>"""
            self.wfile.write(html.encode('utf-8'))
        else:
            super().do_GET()


def start_server():
    server = ThreadedTCPServer(("", PORT), CustomHandler)
    print(f"Web server running on http://localhost:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    print("Starting WLE 2026 Auditor Server...")
    # 1. Catch up first
    catchup_missed_events()

    # 2. Start the event stream listener in a background thread
    t = threading.Thread(target=listen_to_stream, daemon=True)
    t.start()

    # 3. Start the web server
    start_server()

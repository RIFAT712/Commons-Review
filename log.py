import requests
import json
import re
import os
import time
from collections import defaultdict

# --- CONFIGURATION ---
API_URL = "https://commons.wikimedia.org/w/api.php"
USER_AGENT = "WLE2026BangladeshAuditor/1.0 (contact: yahya.commons@gmail.com; user: yahya)"
CATEGORY = "Category:Unreviewed images from Wiki Loves Earth 2026 in Bangladesh"
JSON_FILE = "removal_audit_log.json"
# ---------------------


def get_existing_data():
    """Reads existing JSON to prevent duplicate logging."""
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
            key = (row['timestamp'], row['file_title'])
            seen_events.add(key)
            events_by_user[row['user']].add(row['file_title'])

    return events, seen_events, events_by_user


def fetch_new_events(session, seen_events):
    """Fetches only new events from the API."""
    new_rows = []
    rccontinue = None

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

            if "error" in data:
                print(f"API Error: {data['error']['info']}")
                break

        except requests.exceptions.HTTPError as e:
            print(f"HTTP Error occurred: {e}")
            break
        except ValueError as e:
            print(f"Could not parse JSON. Response was likely HTML error page.")
            break

        if "query" in data and "recentchanges" in data["query"]:
            for rc in data["query"]["recentchanges"]:
                comment = rc.get("comment", "")
                if "removed" in comment.lower():
                    timestamp = rc.get("timestamp")
                    user = rc.get("user", "Unknown")
                    match = re.search(r'\[\[(.*?)\]\]', comment)
                    file_name = match.group(1) if match else "Unknown"

                    if (timestamp, file_name) not in seen_events:
                        new_rows.append({
                            "timestamp": timestamp,
                            "user": user,
                            "file_title": file_name,
                            "full_comment": comment,
                            "deleted": False
                        })
                        seen_events.add((timestamp, file_name))

        if "continue" in data and "rccontinue" in data["continue"]:
            rccontinue = data["continue"]["rccontinue"]
        else:
            break

    return new_rows


def check_deleted_files(session, all_events):
    """Checks if logged files have been deleted from Commons."""
    files_to_check = set()
    for event in all_events:
        if not event.get("deleted", False):
            files_to_check.add(event["file_title"])

    if not files_to_check:
        return 0

    print(f"Checking {len(files_to_check)} files for deletion status...")
    deleted_titles = set()
    files_to_check = list(files_to_check)

    # Query API in batches of 50
    for i in range(0, len(files_to_check), 50):
        batch = files_to_check[i:i+50]
        params = {
            "action": "query",
            "format": "json",
            "titles": "|".join(batch)
        }
        try:
            resp = session.get(API_URL, params=params, headers={
                               "User-Agent": USER_AGENT})
            resp.raise_for_status()
            data = resp.json()
            if "query" in data and "pages" in data["query"]:
                for page_id, page_info in data["query"]["pages"].items():
                    if "missing" in page_info:
                        deleted_titles.add(page_info.get("title", ""))
        except Exception as e:
            print(f"Error checking deletion status: {e}")

    marked_count = 0
    for event in all_events:
        if event["file_title"] in deleted_titles and not event.get("deleted", False):
            event["deleted"] = True
            marked_count += 1

    return marked_count


def main():
    # 1. Load existing
    events, seen_events, user_removals = get_existing_data()
    print(f"Loaded existing history. Scanning for new removals...")

    # 2. Fetch new
    with requests.Session() as session:
        new_events = fetch_new_events(session, seen_events)

        # 3. Update events list
        if new_events:
            events.extend(new_events)
            for event in new_events:
                user_removals[event["user"]].add(event["file_title"])
            print(f"Added {len(new_events)} new removal events.")
        else:
            print("No new removal events found.")

        # 4. Check deletion status
        marked_count = check_deleted_files(session, events)
        if marked_count > 0:
            print(f"Marked {marked_count} files as deleted.")

    # 5. Save JSON
    with open(JSON_FILE, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=4, ensure_ascii=False)

    # 6. Display Leaderboard
    print("\n=== WLE 2026 GLOBAL REMOVAL LEADERBOARD ===")
    leaderboard = {user: len(files) for user, files in user_removals.items()}
    sorted_counts = sorted(leaderboard.items(),
                           key=lambda x: x[1], reverse=True)

    for rank, (user, count) in enumerate(sorted_counts, 1):
        print(f"{rank}. {user}: {count} unique files removed")


if __name__ == "__main__":
    main()

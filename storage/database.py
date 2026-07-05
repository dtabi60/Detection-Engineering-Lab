import json
import sqlite3
from pathlib import Path

DB_FILE = Path("data/edr_events.db")
NORMALIZED_FILE = Path("data/normalized_sysmon_events.json")


def create_database():
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        event_id INTEGER,
        event_type TEXT,
        host TEXT,
        user TEXT,
        image TEXT,
        process_guid TEXT,
        process_id TEXT,
        command_line TEXT,
        current_directory TEXT,
        parent_image TEXT,
        parent_command_line TEXT,
        integrity_level TEXT,
        hashes TEXT,
        raw_message TEXT
    )
    """)

    connection.commit()
    connection.close()

    print(f"[+] Database ready: {DB_FILE}")


def insert_events():
    if not NORMALIZED_FILE.exists():
        print(f"[-] Missing file: {NORMALIZED_FILE}")
        print("Run this first: python normalizers\\sysmon_normalizer.py")
        return

    events = json.loads(NORMALIZED_FILE.read_text(encoding="utf-8"))

    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()

    for event in events:
        cursor.execute("""
        INSERT INTO events (
            timestamp,
            event_id,
            event_type,
            host,
            user,
            image,
            process_guid,
            process_id,
            command_line,
            current_directory,
            parent_image,
            parent_command_line,
            integrity_level,
            hashes,
            raw_message
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event.get("timestamp"),
            event.get("event_id"),
            event.get("event_type"),
            event.get("host"),
            event.get("user"),
            event.get("image"),
            event.get("process_guid"),
            event.get("process_id"),
            event.get("command_line"),
            event.get("current_directory"),
            event.get("parent_image"),
            event.get("parent_command_line"),
            event.get("integrity_level"),
            event.get("hashes"),
            event.get("raw_message")
        ))

    connection.commit()
    connection.close()

    print(f"[+] Inserted {len(events)} events into database")


def show_recent_events(limit=10):
    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()

    cursor.execute("""
    SELECT timestamp, event_type, user, image, command_line
    FROM events
    ORDER BY id DESC
    LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()
    connection.close()

    print("\n===== RECENT EVENTS =====")
    for row in rows:
        print(f"\nTime: {row[0]}")
        print(f"Type: {row[1]}")
        print(f"User: {row[2]}")
        print(f"Image: {row[3]}")
        print(f"Command Line: {row[4]}")


if __name__ == "__main__":
    create_database()
    insert_events()
    show_recent_events()
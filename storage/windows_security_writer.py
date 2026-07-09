import json
import sqlite3
from pathlib import Path


DB_PATH = "storage/entities.db"
INPUT_PATH = Path("data/windows_security_normalized.json")


def ensure_windows_security_table():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS windows_security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source TEXT,
            event_id INTEGER,
            event_type TEXT,
            severity TEXT,
            hostname TEXT,
            provider TEXT,
            message TEXT,
            raw_json TEXT
        )
    """)

    conn.commit()
    conn.close()


def load_windows_security_events():
    ensure_windows_security_table()

    with open(INPUT_PATH, "r", encoding="utf-8") as f:
        events = json.load(f)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    for event in events:
        cursor.execute(
            """
            INSERT INTO windows_security_events (
                timestamp,
                source,
                event_id,
                event_type,
                severity,
                hostname,
                provider,
                message,
                raw_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.get("timestamp"),
                event.get("source"),
                event.get("event_id"),
                event.get("event_type"),
                event.get("severity"),
                event.get("hostname"),
                event.get("provider"),
                event.get("message"),
                json.dumps(event.get("raw", {})),
            ),
        )

    conn.commit()
    conn.close()

    print(f"Loaded {len(events)} Windows Security events into SQLite.")


if __name__ == "__main__":
    load_windows_security_events()
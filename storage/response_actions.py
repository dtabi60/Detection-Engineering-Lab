import sqlite3
from datetime import datetime

DB_PATH = "storage/entities.db"


def init_response_actions():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS response_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id INTEGER,
        action_type TEXT,
        target TEXT,
        status TEXT,
        notes TEXT,
        timestamp TEXT
    )
    """)

    conn.commit()
    conn.close()


def log_response_action(alert_id, action_type, target, notes=""):
    init_response_actions()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO response_actions (
        alert_id,
        action_type,
        target,
        status,
        notes,
        timestamp
    )
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        alert_id,
        action_type,
        target,
        "Simulated Completed",
        notes,
        datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


def get_response_actions(alert_id):
    init_response_actions()

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
    SELECT action_type, target, status, notes, timestamp
    FROM response_actions
    WHERE alert_id = ?
    ORDER BY timestamp DESC
    """, (alert_id,))

    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return rows
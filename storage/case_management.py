import sqlite3
from datetime import datetime

DB_PATH = "storage/entities.db"


def ensure_case_columns():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    columns = {
        "case_owner": "TEXT",
        "case_status": "TEXT",
        "case_notes": "TEXT",
        "disposition": "TEXT",
        "priority": "TEXT",
        "last_updated": "TEXT"
    }

    cursor.execute("PRAGMA table_info(alerts)")
    existing_columns = [row[1] for row in cursor.fetchall()]

    for column_name, column_type in columns.items():
        if column_name not in existing_columns:
            cursor.execute(f"ALTER TABLE alerts ADD COLUMN {column_name} {column_type}")

    conn.commit()
    conn.close()


def update_case(alert_id, case_owner, case_status, case_notes, disposition, priority):
    ensure_case_columns()

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE alerts
        SET case_owner = ?,
            case_status = ?,
            case_notes = ?,
            disposition = ?,
            priority = ?,
            last_updated = ?
        WHERE id = ?
    """, (
        case_owner,
        case_status,
        case_notes,
        disposition,
        priority,
        now,
        alert_id
    ))

    conn.commit()
    conn.close()


def get_case_details(alert_id):
    ensure_case_columns()

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            case_owner,
            case_status,
            case_notes,
            disposition,
            priority,
            last_updated
        FROM alerts
        WHERE id = ?
    """, (alert_id,))

    row = cursor.fetchone()
    conn.close()

    if not row:
        return {}

    return dict(row)
import json
import sqlite3
from typing import Iterable

from api.models.telemetry import PowerShell4104Event


DB_PATH = "storage/entities.db"


def ensure_powershell_table():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS powershell_4104_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_id TEXT,
            hostname TEXT,
            actor_user TEXT,
            subject_domain TEXT,
            process_id TEXT,
            parent_process_id TEXT,
            process_name TEXT,
            command_line TEXT,
            script_block_text TEXT,
            script_block_id TEXT,
            runspace_id TEXT,
            raw_json TEXT
        )
    """)

    conn.commit()
    conn.close()


def insert_powershell_events(events: Iterable[PowerShell4104Event]) -> int:
    ensure_powershell_table()

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    count = 0

    for event in events:
        cur.execute(
            """
            INSERT INTO powershell_4104_events (
                timestamp,
                event_id,
                hostname,
                actor_user,
                subject_domain,
                process_id,
                parent_process_id,
                process_name,
                command_line,
                script_block_text,
                script_block_id,
                runspace_id,
                raw_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.timestamp.isoformat(),
                event.event_id,
                event.hostname,
                event.actor_user,
                event.subject_domain,
                event.process_id,
                event.parent_process_id,
                event.process_name,
                event.command_line,
                event.script_block_text,
                event.script_block_id,
                event.runspace_id,
                json.dumps(event.raw_payload),
            ),
        )
        count += 1

    conn.commit()
    conn.close()
    return count
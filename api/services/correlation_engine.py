import sqlite3
from typing import Dict, List

from api.models.telemetry import UniversalEvent
from api.services.detection_engine import evaluate_universal_events
from api.services.universal_events import (
    normalize_defender_row,
    normalize_powershell_row,
    normalize_sysmon_network_row,
    normalize_sysmon_process_row,
    normalize_windows_security_row,
)


DB_PATH = "storage/entities.db"


def fetch_rows(table: str) -> List[Dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:
        cur.execute(f"SELECT * FROM {table}")
        rows = [dict(row) for row in cur.fetchall()]
    except sqlite3.OperationalError:
        rows = []

    conn.close()
    return rows


def build_unified_timeline() -> Dict:
    events: List[UniversalEvent] = []

    for row in fetch_rows("windows_security_events"):
        events.append(normalize_windows_security_row(row))

    for row in fetch_rows("processes"):
        events.append(normalize_sysmon_process_row(row))

    for row in fetch_rows("network_connections"):
        events.append(normalize_sysmon_network_row(row))

    for row in fetch_rows("powershell_4104_events"):
        events.append(normalize_powershell_row(row))

    for row in fetch_rows("defender_events"):
        events.append(normalize_defender_row(row))

    events.sort(key=lambda event: event.timestamp)

    findings = evaluate_universal_events(events)

    return {
        "event_count": len(events),
        "detection_count": len(findings),
        "timeline": [event.model_dump(mode="json") for event in events],
        "detections": [finding.model_dump(mode="json") for finding in findings],
    }
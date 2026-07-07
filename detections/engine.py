from storage.entity_writer import write_alert_to_entities
import json
import sqlite3
from pathlib import Path

from scoring.risk import score_powershell, severity_from_score
from storage.entity_writer import write_alert_to_entities

DB_FILE = Path("data/edr_events.db")
ALERT_FILE = Path("data/alerts/detection_alerts.json")


def load_events():
    connection = sqlite3.connect(DB_FILE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute("""
    SELECT *
    FROM events
    ORDER BY id DESC
    """)

    events = [dict(row) for row in cursor.fetchall()]
    connection.close()
    return events


def detect_powershell(event):
    alerts = []

    image = (event.get("image") or "").lower()
    command_line = event.get("command_line") or ""

    if "powershell.exe" not in image:
        return alerts

    risk_score, reasons = score_powershell(command_line)
    severity = severity_from_score(risk_score)

    if risk_score > 0:
        alert = {
            "alert_name": "Suspicious PowerShell Execution",
            "severity": severity,
            "risk_score": risk_score,
            "timestamp": event.get("timestamp"),
            "user": event.get("user"),
            "host": event.get("host"),
            "hostname": event.get("host"),
            "image": event.get("image"),
            "process_name": event.get("image"),
            "process_id": event.get("process_id"),
            "parent_process_id": event.get("parent_process_id"),
            "command_line": event.get("command_line"),
            "parent_image": event.get("parent_image"),
            "mitre_tactic": "Execution",
            "mitre_technique": "T1059.001 - PowerShell",
            "description": "PowerShell executed with suspicious command-line behavior.",
            "reasons": reasons
        }

        alerts.append(alert)

        try:
            write_alert_to_entities(alert)
        except Exception as e:
            print(f"[entity_writer] Failed to write alert: {e}")

    return alerts


def run_detections():
    events = load_events()
    all_alerts = []

    for event in events:
        all_alerts.extend(detect_powershell(event))

    ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)
    ALERT_FILE.write_text(json.dumps(all_alerts, indent=4), encoding="utf-8")

    print(f"[+] Loaded {len(events)} events")
    print(f"[+] Generated {len(all_alerts)} alerts")
    print(f"[+] Saved alerts to {ALERT_FILE}")


if __name__ == "__main__":
    run_detections()
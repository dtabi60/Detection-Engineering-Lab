import json
import sqlite3
from pathlib import Path

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
    command_line = (event.get("command_line") or "").lower()

    if "powershell.exe" not in image:
        return alerts

    reasons = []
    risk_score = 0

    if "-encodedcommand" in command_line or "-enc" in command_line:
        reasons.append("Encoded PowerShell command detected")
        risk_score += 40

    if "-executionpolicy bypass" in command_line:
        reasons.append("ExecutionPolicy Bypass detected")
        risk_score += 25

    if "-windowstyle hidden" in command_line:
        reasons.append("Hidden PowerShell window detected")
        risk_score += 25

    if "-noprofile" in command_line:
        reasons.append("NoProfile flag detected")
        risk_score += 10

    if risk_score > 0:
        severity = "Low"
        if risk_score >= 70:
            severity = "High"
        elif risk_score >= 40:
            severity = "Medium"

        alerts.append({
            "alert_name": "Suspicious PowerShell Execution",
            "severity": severity,
            "risk_score": risk_score,
            "timestamp": event.get("timestamp"),
            "user": event.get("user"),
            "host": event.get("host"),
            "image": event.get("image"),
            "command_line": event.get("command_line"),
            "parent_image": event.get("parent_image"),
            "mitre_tactic": "Execution",
            "mitre_technique": "T1059.001 - PowerShell",
            "reasons": reasons
        })

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
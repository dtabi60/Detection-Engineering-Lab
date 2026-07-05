import json
import sqlite3
from pathlib import Path

DB_FILE = Path("data/edr_events.db")
ALERT_FILE = Path("data/alerts/powershell_alerts.json")


def detect_suspicious_powershell():
    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()

    cursor.execute("""
    SELECT id, timestamp, user, image, command_line, parent_image
    FROM events
    WHERE event_type = 'process_create'
      AND LOWER(image) LIKE '%powershell.exe%'
    """)

    rows = cursor.fetchall()
    connection.close()

    alerts = []

    for row in rows:
        event_id, timestamp, user, image, command_line, parent_image = row
        command_line_lower = (command_line or "").lower()

        reasons = []
        risk_score = 0

        if "-encodedcommand" in command_line_lower or "-enc" in command_line_lower:
            reasons.append("Encoded PowerShell command detected")
            risk_score += 40

        if "-executionpolicy bypass" in command_line_lower:
            reasons.append("ExecutionPolicy Bypass detected")
            risk_score += 25

        if "-windowstyle hidden" in command_line_lower:
            reasons.append("Hidden PowerShell window detected")
            risk_score += 25

        if "-noprofile" in command_line_lower:
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
                "timestamp": timestamp,
                "user": user,
                "image": image,
                "command_line": command_line,
                "parent_image": parent_image,
                "mitre_tactic": "Execution",
                "mitre_technique": "T1059.001 - PowerShell",
                "reasons": reasons
            })

    ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)
    ALERT_FILE.write_text(json.dumps(alerts, indent=4), encoding="utf-8")

    print(f"[+] Generated {len(alerts)} PowerShell alerts")
    print(f"[+] Saved to {ALERT_FILE}")

    return alerts


if __name__ == "__main__":
    detect_suspicious_powershell()
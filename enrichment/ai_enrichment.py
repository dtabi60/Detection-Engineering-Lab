import sqlite3

DB_PATH = "storage/entities.db"


def build_ai_summary(alert):
    alert_name = alert.get("alert_name") or "Unknown alert"
    severity = alert.get("severity") or "Unknown"
    mitre = alert.get("mitre_technique") or "Unknown"
    description = alert.get("description") or "No description available"
    hostname = alert.get("hostname") or "Unknown endpoint"

    summary = (
        f"{alert_name} was detected on {hostname}. "
        f"The alert severity is {severity} and maps to {mitre}. "
        f"{description}"
    )

    actions = (
        "Recommended analyst actions: review the parent process, inspect the full command line, "
        "validate whether the user activity was expected, check related file and network activity, "
        "and escalate or isolate the host if malicious behavior is confirmed."
    )

    if "PowerShell" in alert_name or "T1059.001" in mitre:
        verdict = "Suspicious PowerShell activity requiring analyst review."
        confidence = "Medium"
    else:
        verdict = "Alert requires review."
        confidence = "Low"

    return summary, verdict, actions, confidence


def ensure_ai_columns():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    columns = {
        "ai_summary": "TEXT",
        "analyst_verdict": "TEXT",
        "recommended_actions": "TEXT",
        "ai_confidence": "TEXT"
    }

    cursor.execute("PRAGMA table_info(alerts)")
    existing_columns = [row[1] for row in cursor.fetchall()]

    for column_name, column_type in columns.items():
        if column_name not in existing_columns:
            cursor.execute(f"ALTER TABLE alerts ADD COLUMN {column_name} {column_type}")

    conn.commit()
    conn.close()


def enrich_alerts_with_ai():
    ensure_ai_columns()

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
    SELECT 
        a.id,
        a.alert_name,
        a.severity,
        a.mitre_technique,
        a.description,
        a.timestamp,
        e.hostname
    FROM alerts a
    LEFT JOIN endpoints e ON a.endpoint_id = e.id
    WHERE a.ai_summary IS NULL
       OR a.ai_summary = ''
    """)

    alerts = [dict(row) for row in cursor.fetchall()]

    for alert in alerts:
        summary, verdict, actions, confidence = build_ai_summary(alert)

        cursor.execute("""
        UPDATE alerts
        SET ai_summary = ?,
            analyst_verdict = ?,
            recommended_actions = ?,
            ai_confidence = ?
        WHERE id = ?
        """, (
            summary,
            verdict,
            actions,
            confidence,
            alert["id"]
        ))

    conn.commit()
    conn.close()

    print(f"[+] AI-enriched {len(alerts)} alerts")


if __name__ == "__main__":
    enrich_alerts_with_ai()
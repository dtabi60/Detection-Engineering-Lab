import sqlite3
from pathlib import PureWindowsPath

DB_PATH = "storage/entities.db"


def clean_process_name(value):
    if not value:
        return "unknown_process"

    value = value.replace('"', "")

    try:
        return PureWindowsPath(value).name
    except Exception:
        return value


def get_storyline(endpoint_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 
            p.process_name,
            p.process_id,
            p.parent_process_id,
            p.user,
            p.command_line,
            p.timestamp
        FROM processes p
        WHERE p.endpoint_id = ?
        ORDER BY p.timestamp ASC
    """, (endpoint_id,))

    processes = [dict(row) for row in cursor.fetchall()]

    cursor.execute("""
        SELECT 
            alert_name,
            severity,
            mitre_technique,
            description,
            ai_summary,
            analyst_verdict,
            recommended_actions,
            ai_confidence,
            timestamp,
            status
        FROM alerts
        WHERE endpoint_id = ?
        ORDER BY timestamp ASC
    """, (endpoint_id,))

    alerts = [dict(row) for row in cursor.fetchall()]
    conn.close()

    lines = []

    lines.append("EDR STORYLINE")
    lines.append("=" * 70)
    lines.append("")

    if not processes and not alerts:
        return "No storyline data available for this endpoint."

    if processes:
        lines.append("1. Process Activity Observed")
        lines.append("-" * 70)

        seen = set()

        for process in processes:
            name = clean_process_name(process.get("process_name"))
            pid = process.get("process_id") or "unknown_pid"
            user = process.get("user") or "unknown_user"
            cmd = process.get("command_line") or ""
            timestamp = process.get("timestamp") or "unknown_time"

            key = (name, pid, cmd)
            if key in seen:
                continue

            seen.add(key)

            suspicious = (
                "powershell" in name.lower()
                or "encodedcommand" in cmd.lower()
                or "bypass" in cmd.lower()
                or "-nop" in cmd.lower()
            )

            icon = "🔴" if suspicious else "🟢"

            lines.append(f"{icon} {timestamp} - {name} executed as {user}")
            lines.append(f"   PID: {pid}")

            if cmd:
                lines.append(f"   Command Line: {cmd}")

            if suspicious:
                lines.append("   Why it matters: This process contains behavior commonly reviewed during PowerShell or script-based execution investigations.")

            lines.append("")

    if alerts:
        lines.append("2. Detection Alert Generated")
        lines.append("-" * 70)

        for alert in alerts:
            lines.append(f"🚨 {alert.get('timestamp')} - {alert.get('alert_name')}")
            lines.append(f"   Severity: {alert.get('severity')}")
            lines.append(f"   MITRE: {alert.get('mitre_technique')}")
            lines.append(f"   Status: {alert.get('status')}")
            lines.append(f"   Description: {alert.get('description')}")
            lines.append("")

            if alert.get("ai_summary"):
                lines.append("3. AI Analyst Summary")
                lines.append("-" * 70)
                lines.append(alert.get("ai_summary"))
                lines.append("")

            if alert.get("analyst_verdict"):
                lines.append("4. Analyst Verdict")
                lines.append("-" * 70)
                lines.append(alert.get("analyst_verdict"))
                lines.append(f"AI Confidence: {alert.get('ai_confidence')}")
                lines.append("")

            if alert.get("recommended_actions"):
                lines.append("5. Recommended Response Actions")
                lines.append("-" * 70)
                lines.append(alert.get("recommended_actions"))
                lines.append("")

    return "\n".join(lines)
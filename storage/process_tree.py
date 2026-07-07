import sqlite3
from pathlib import PureWindowsPath

DB_PATH = "storage/entities.db"


def get_processes(endpoint_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 
            process_name,
            process_id,
            parent_process_id,
            user,
            command_line,
            timestamp
        FROM processes
        WHERE endpoint_id = ?
        ORDER BY timestamp ASC
    """, (endpoint_id,))

    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def clean_process_name(value):
    if not value:
        return "unknown_process"

    value = value.replace('"', "")

    try:
        return PureWindowsPath(value).name
    except Exception:
        return value


def render_process_tree(endpoint_id):
    processes = get_processes(endpoint_id)

    if not processes:
        return "No process data available for this endpoint."

    seen = set()
    lines = []

    for process in processes:
        raw_name = process.get("process_name") or "unknown_process"
        name = clean_process_name(raw_name)
        pid = process.get("process_id") or "unknown_pid"
        ppid = process.get("parent_process_id") or "unknown_parent"
        user = process.get("user") or "unknown_user"
        cmd = process.get("command_line") or ""

        unique_key = (name, pid, ppid, cmd)

        if unique_key in seen:
            continue

        seen.add(unique_key)

        suspicious = (
            "powershell" in name.lower()
            or "encodedcommand" in cmd.lower()
            or "bypass" in cmd.lower()
            or "-nop" in cmd.lower()
        )

        icon = "🔴" if suspicious else "🟢"

        lines.append(f"{icon} {name} | PID={pid} | Parent={ppid} | User={user}")

        if cmd:
            lines.append(f"    CMD: {cmd}")

        lines.append("")

    return "\n".join(lines)
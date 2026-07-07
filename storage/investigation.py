import sqlite3

DB_PATH = "storage/entities.db"


def get_all_alerts():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            a.id,
            e.hostname,
            a.alert_name,
            a.severity,
            a.mitre_technique,
            a.timestamp,
            a.status
        FROM alerts a
        LEFT JOIN endpoints e ON a.endpoint_id = e.id
        ORDER BY a.timestamp DESC
    """)

    alerts = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return alerts


def get_alert_investigation(alert_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            a.id,
            a.endpoint_id,
            e.hostname,
            e.ip_address,
            e.os,
            a.alert_name,
            a.severity,
            a.mitre_technique,
            a.description,
            a.ai_summary,
            a.analyst_verdict,
            a.recommended_actions,
            a.ai_confidence,
            a.timestamp,
            a.status
        FROM alerts a
        LEFT JOIN endpoints e ON a.endpoint_id = e.id
        WHERE a.id = ?
    """, (alert_id,))

    alert = cursor.fetchone()

    if not alert:
        conn.close()
        return None

    alert = dict(alert)
    endpoint_id = alert["endpoint_id"]

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
        ORDER BY timestamp DESC
        LIMIT 10
    """, (endpoint_id,))

    processes = [dict(row) for row in cursor.fetchall()]

    cursor.execute("""
        SELECT
            process_id,
            destination_ip,
            destination_port,
            protocol,
            timestamp
        FROM network_connections
        WHERE endpoint_id = ?
        ORDER BY timestamp DESC
        LIMIT 10
    """, (endpoint_id,))

    network = [dict(row) for row in cursor.fetchall()]

    cursor.execute("""
        SELECT
            process_id,
            file_path,
            file_hash,
            action,
            timestamp
        FROM file_events
        WHERE endpoint_id = ?
        ORDER BY timestamp DESC
        LIMIT 10
    """, (endpoint_id,))

    files = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return {
        "alert": alert,
        "processes": processes,
        "network": network,
        "files": files
    }
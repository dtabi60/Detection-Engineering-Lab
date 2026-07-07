import sqlite3
from pathlib import Path
from datetime import datetime

DB_PATH = Path("storage/entities.db")


def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(DB_PATH)


def init_entity_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS endpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hostname TEXT UNIQUE,
        ip_address TEXT,
        os TEXT,
        first_seen TEXT,
        last_seen TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS processes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        endpoint_id INTEGER,
        process_name TEXT,
        process_id TEXT,
        parent_process_id TEXT,
        command_line TEXT,
        user TEXT,
        timestamp TEXT,
        FOREIGN KEY(endpoint_id) REFERENCES endpoints(id)
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS network_connections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        endpoint_id INTEGER,
        process_id TEXT,
        destination_ip TEXT,
        destination_port TEXT,
        protocol TEXT,
        timestamp TEXT,
        FOREIGN KEY(endpoint_id) REFERENCES endpoints(id)
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS file_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        endpoint_id INTEGER,
        process_id TEXT,
        file_path TEXT,
        file_hash TEXT,
        action TEXT,
        timestamp TEXT,
        FOREIGN KEY(endpoint_id) REFERENCES endpoints(id)
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        endpoint_id INTEGER,
        alert_name TEXT,
        severity TEXT,
        mitre_technique TEXT,
        description TEXT,
        timestamp TEXT,
        status TEXT DEFAULT 'Open',
        FOREIGN KEY(endpoint_id) REFERENCES endpoints(id)
    )
    """)

    conn.commit()
    conn.close()


def upsert_endpoint(hostname, ip_address=None, os=None):
    now = datetime.utcnow().isoformat()

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO endpoints (hostname, ip_address, os, first_seen, last_seen)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(hostname) DO UPDATE SET
        ip_address=excluded.ip_address,
        os=excluded.os,
        last_seen=excluded.last_seen
    """, (hostname, ip_address, os, now, now))

    conn.commit()

    cursor.execute("SELECT id FROM endpoints WHERE hostname = ?", (hostname,))
    endpoint_id = cursor.fetchone()[0]

    conn.close()
    return endpoint_id


def add_process(endpoint_id, process_name, process_id, parent_process_id=None,
                command_line=None, user=None, timestamp=None):
    timestamp = timestamp or datetime.utcnow().isoformat()

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO processes (
        endpoint_id, process_name, process_id, parent_process_id,
        command_line, user, timestamp
    )
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        endpoint_id, process_name, process_id, parent_process_id,
        command_line, user, timestamp
    ))

    conn.commit()
    conn.close()


def add_network_connection(endpoint_id, process_id, destination_ip,
                           destination_port=None, protocol=None, timestamp=None):
    timestamp = timestamp or datetime.utcnow().isoformat()

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO network_connections (
        endpoint_id, process_id, destination_ip,
        destination_port, protocol, timestamp
    )
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        endpoint_id, process_id, destination_ip,
        destination_port, protocol, timestamp
    ))

    conn.commit()
    conn.close()


def add_file_event(endpoint_id, process_id, file_path,
                   file_hash=None, action=None, timestamp=None):
    timestamp = timestamp or datetime.utcnow().isoformat()

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO file_events (
        endpoint_id, process_id, file_path,
        file_hash, action, timestamp
    )
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        endpoint_id, process_id, file_path,
        file_hash, action, timestamp
    ))

    conn.commit()
    conn.close()


def add_alert(endpoint_id, alert_name, severity, mitre_technique,
              description, timestamp=None):
    timestamp = timestamp or datetime.utcnow().isoformat()

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO alerts (
        endpoint_id, alert_name, severity,
        mitre_technique, description, timestamp
    )
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        endpoint_id, alert_name, severity,
        mitre_technique, description, timestamp
    ))

    conn.commit()
    conn.close()


def get_endpoint_summary(hostname):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id, hostname, ip_address, os FROM endpoints WHERE hostname = ?", (hostname,))
    endpoint = cursor.fetchone()

    if not endpoint:
        conn.close()
        return None

    endpoint_id = endpoint[0]

    cursor.execute("SELECT COUNT(*) FROM processes WHERE endpoint_id = ?", (endpoint_id,))
    process_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM network_connections WHERE endpoint_id = ?", (endpoint_id,))
    network_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM file_events WHERE endpoint_id = ?", (endpoint_id,))
    file_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE endpoint_id = ?", (endpoint_id,))
    alert_count = cursor.fetchone()[0]

    conn.close()

    return {
        "endpoint_id": endpoint_id,
        "hostname": endpoint[1],
        "ip_address": endpoint[2],
        "os": endpoint[3],
        "process_count": process_count,
        "network_count": network_count,
        "file_count": file_count,
        "alert_count": alert_count
    }
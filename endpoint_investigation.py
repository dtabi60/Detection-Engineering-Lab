import sqlite3

DB_PATH = "storage/entities.db"


def print_section(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def main():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    print_section("AVAILABLE ENDPOINTS")

    cursor.execute("""
    SELECT id, hostname, ip_address, os, first_seen, last_seen
    FROM endpoints
    ORDER BY last_seen DESC
    """)

    endpoints = cursor.fetchall()

    if not endpoints:
        print("No endpoints found.")
        conn.close()
        return

    for endpoint in endpoints:
        print(f"{endpoint[0]} | {endpoint[1]} | {endpoint[2]} | {endpoint[3]}")

    endpoint_id = input("\nEnter endpoint ID to investigate: ").strip()

    print_section("ENDPOINT DETAILS")

    cursor.execute("""
    SELECT id, hostname, ip_address, os, first_seen, last_seen
    FROM endpoints
    WHERE id = ?
    """, (endpoint_id,))

    endpoint = cursor.fetchone()

    if not endpoint:
        print("Endpoint not found.")
        conn.close()
        return

    print(f"ID: {endpoint[0]}")
    print(f"Hostname: {endpoint[1]}")
    print(f"IP Address: {endpoint[2]}")
    print(f"OS: {endpoint[3]}")
    print(f"First Seen: {endpoint[4]}")
    print(f"Last Seen: {endpoint[5]}")

    print_section("ALERTS")

    cursor.execute("""
    SELECT alert_name, severity, mitre_technique, description, timestamp, status
    FROM alerts
    WHERE endpoint_id = ?
    ORDER BY timestamp DESC
    """, (endpoint_id,))

    for row in cursor.fetchall():
        print(f"[{row[1]}] {row[0]}")
        print(f"MITRE: {row[2]}")
        print(f"Description: {row[3]}")
        print(f"Timestamp: {row[4]}")
        print(f"Status: {row[5]}")
        print("-" * 70)

    print_section("PROCESSES")

    cursor.execute("""
    SELECT process_name, process_id, parent_process_id, command_line, user, timestamp
    FROM processes
    WHERE endpoint_id = ?
    ORDER BY timestamp DESC
    """, (endpoint_id,))

    for row in cursor.fetchall():
        print(f"Process: {row[0]}")
        print(f"PID: {row[1]}")
        print(f"Parent PID: {row[2]}")
        print(f"User: {row[4]}")
        print(f"Command Line: {row[3]}")
        print(f"Timestamp: {row[5]}")
        print("-" * 70)

    print_section("NETWORK CONNECTIONS")

    cursor.execute("""
    SELECT process_id, destination_ip, destination_port, protocol, timestamp
    FROM network_connections
    WHERE endpoint_id = ?
    ORDER BY timestamp DESC
    """, (endpoint_id,))

    rows = cursor.fetchall()

    if not rows:
        print("No network connections found.")

    for row in rows:
        print(f"PID {row[0]} -> {row[1]}:{row[2]} {row[3]} at {row[4]}")

    print_section("FILE EVENTS")

    cursor.execute("""
    SELECT process_id, file_path, file_hash, action, timestamp
    FROM file_events
    WHERE endpoint_id = ?
    ORDER BY timestamp DESC
    """, (endpoint_id,))

    rows = cursor.fetchall()

    if not rows:
        print("No file events found.")

    for row in rows:
        print(f"PID {row[0]} | {row[3]} | {row[1]}")
        print(f"Hash: {row[2]}")
        print(f"Timestamp: {row[4]}")
        print("-" * 70)

    conn.close()


if __name__ == "__main__":
    main()
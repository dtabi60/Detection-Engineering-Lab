import sqlite3

conn = sqlite3.connect("storage/entities.db")
cursor = conn.cursor()

tables = [
    "alerts",
    "processes",
    "network_connections",
    "file_events",
    "endpoints"
]

for table in tables:
    cursor.execute(f"DELETE FROM {table}")

conn.commit()
conn.close()

print("[+] Entity database reset complete.")
import sqlite3

conn = sqlite3.connect("storage/entities.db")
cursor = conn.cursor()

tables = [
    "endpoints",
    "processes",
    "network_connections",
    "file_events",
    "alerts"
]

print("=" * 50)
print("ENTITY DATABASE")
print("=" * 50)

for table in tables:

    cursor.execute(f"SELECT COUNT(*) FROM {table}")
    count = cursor.fetchone()[0]

    print(f"{table:<25} {count}")

print("=" * 50)

cursor.execute("""
SELECT hostname,
       first_seen,
       last_seen
FROM endpoints
""")

rows = cursor.fetchall()

print("\nEndpoints\n")

for row in rows:
    print(row)

conn.close()
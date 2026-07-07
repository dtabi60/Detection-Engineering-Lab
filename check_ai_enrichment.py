import sqlite3

conn = sqlite3.connect("storage/entities.db")
cursor = conn.cursor()

cursor.execute("""
SELECT 
    id,
    alert_name,
    severity,
    ai_confidence,
    analyst_verdict,
    ai_summary,
    recommended_actions
FROM alerts
ORDER BY id DESC
""")

rows = cursor.fetchall()

for row in rows:
    print("=" * 80)
    print(f"Alert ID: {row[0]}")
    print(f"Alert: {row[1]}")
    print(f"Severity: {row[2]}")
    print(f"AI Confidence: {row[3]}")
    print(f"Verdict: {row[4]}")
    print(f"Summary: {row[5]}")
    print(f"Actions: {row[6]}")

conn.close()
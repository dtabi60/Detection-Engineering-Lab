import json
import subprocess
from pathlib import Path

alert_path = Path("data/edr_alerts/suspicious_powershell.json")

with open(alert_path, "r") as f:
    alert = json.load(f)

observable = alert.get("observable")
observable_type = alert.get("observable_type")

print("===== EDR ALERT =====")
print(f"Alert: {alert['alert_name']}")
print(f"Host: {alert['host']}")
print(f"User: {alert['user']}")
print(f"Command Line: {alert['command_line']}")
print(f"Observable: {observable}")
print()

print("===== ENRICHMENT RESULT =====")

result = subprocess.run(
    ["python", "-m", "enrichment.engine", observable],
    capture_output=True,
    text=True
)

print(result.stdout)
import json
import subprocess
from pathlib import Path

OUTPUT_FILE = Path("data/live_sysmon_events.json")


def collect_sysmon_events(max_events=50):
   command = [
    "powershell",
    "-Command",
    f"""
    Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents {max_events} |
    Where-Object {{ $_.Id -in 1,3,7,11,13,22 }} |
    Select-Object TimeCreated, Id, ProviderName, Message |
    ConvertTo-Json -Depth 4
    """
]

    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode != 0:
        print("Failed to collect Sysmon events")
        print(result.stderr)
        return []

    if not result.stdout.strip():
        print("No Sysmon events found")
        return []

    events = json.loads(result.stdout)

    if isinstance(events, dict):
        events = [events]

    OUTPUT_FILE.parent.mkdir(exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(events, indent=2, default=str))

    print(f"Collected {len(events)} Sysmon events")
    print(f"Saved to {OUTPUT_FILE}")

    return events


if __name__ == "__main__":
    collect_sysmon_events()
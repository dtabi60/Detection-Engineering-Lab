import json
import subprocess
from pathlib import Path

# Output location
OUTPUT_FILE = Path("data/live_sysmon_events.json")


def collect_sysmon_events(max_events=50):
    """
    Collects recent Sysmon events and saves them as JSON.
    """

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

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("[-] Failed to collect Sysmon events")
        print(result.stderr)
        return []

    if not result.stdout.strip():
        print("[!] No Sysmon events found.")
        return []

    try:
        events = json.loads(result.stdout)
    except json.JSONDecodeError:
        print("[-] Failed to parse Sysmon JSON output.")
        return []

    # PowerShell returns a dictionary when there is only one event
    if isinstance(events, dict):
        events = [events]

    # Create data directory if needed
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Save events
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=4, default=str)

    print(f"[+] Collected {len(events)} Sysmon events")
    print(f"[+] Saved to {OUTPUT_FILE}")

    return events


if __name__ == "__main__":
    collect_sysmon_events()
import json
import subprocess
from pathlib import Path

OUTPUT_FILE = Path("data/raw_powershell_4104.json")


def collect_powershell_events(max_events=50):
    command = [
        "powershell",
        "-Command",
        f"""
        Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents {max_events} |
        Where-Object {{ $_.Id -eq 4104 }} |
        Select-Object TimeCreated, Id, ProviderName, Message |
        ConvertTo-Json -Depth 4
        """
    ]

    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode != 0:
        print("[-] Failed to collect PowerShell 4104 events")
        print(result.stderr)
        return []

    if not result.stdout.strip():
        print("[!] No PowerShell 4104 events found")
        return []

    events = json.loads(result.stdout)

    if isinstance(events, dict):
        events = [events]

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(events, indent=4), encoding="utf-8")

    print(f"[+] Collected {len(events)} PowerShell 4104 events")
    print(f"[+] Saved to {OUTPUT_FILE}")
    return events


if __name__ == "__main__":
    collect_powershell_events()
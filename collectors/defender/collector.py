import json
import subprocess
from pathlib import Path


OUTPUT_PATH = Path("data/raw_defender_events.json")

DEFENDER_EVENT_IDS = [
    1116,  # Malware detected
    1117,  # Remediation started
    1118,  # Remediation failed
    1119,  # Remediation succeeded
    1121,  # Behavior detected
    5007,  # Defender configuration changed
]


def collect_defender_events(max_events: int = 100):
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    event_ids = ",".join(str(event_id) for event_id in DEFENDER_EVENT_IDS)

    powershell_command = f"""
    Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-Windows Defender/Operational'; Id={event_ids}}} -MaxEvents {max_events} |
    Select-Object TimeCreated, Id, ProviderName, MachineName, Message |
    ConvertTo-Json -Depth 4
    """

    result = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            powershell_command,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr)

    raw_output = result.stdout.strip()

    if not raw_output:
        events = []
    else:
        events = json.loads(raw_output)
        if isinstance(events, dict):
            events = [events]

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=4)

    return events


if __name__ == "__main__":
    events = collect_defender_events()
    print(f"Collected {len(events)} Defender events")
    print(f"Saved to {OUTPUT_PATH}")
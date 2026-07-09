import json
import subprocess
from pathlib import Path


OUTPUT_PATH = Path("data/raw_windows_security_events.json")


EVENT_IDS = [
    4624,  # successful logon
    4625,  # failed logon
    4672,  # special privileges
    4688,  # process creation if enabled
    4720,  # user created
    4728,  # user added to privileged group
    4732,  # user added to local group
]


def collect_windows_security_events(max_events: int = 100):
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    event_filter = ",".join(str(event_id) for event_id in EVENT_IDS)

    powershell_command = f"""
    Get-WinEvent -FilterHashtable @{{LogName='Security'; Id={event_filter}}} -MaxEvents {max_events} |
    Select-Object TimeCreated, Id, ProviderName, MachineName, Message |
    ConvertTo-Json -Depth 4
    """

    result = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", powershell_command],
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
    events = collect_windows_security_events()
    print(f"Collected {len(events)} Windows Security events")
    print(f"Saved to {OUTPUT_PATH}")
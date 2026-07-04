import json
from pathlib import Path

INPUT_FILE = Path("data/normalized_sysmon_events.json")
OUTPUT_FILE = Path("data/alerts.json")

SUSPICIOUS_FLAGS = [
    "-ExecutionPolicy Bypass",
    "-NoProfile",
    "-EncodedCommand",
    "-WindowStyle Hidden",
    "-nop",
    "-enc",
    "-w hidden",
]


def detect_suspicious_powershell():
    if not INPUT_FILE.exists():
        print("Run collectors\\sysmon.py and parsers\\sysmon_parser.py first.")
        return []

    events = json.loads(INPUT_FILE.read_text())
    alerts = []

    for event in events:
        image = event.get("image", "").lower()
        command_line = event.get("command_line", "")

        if "powershell.exe" in image:
            matched_flags = [
                flag for flag in SUSPICIOUS_FLAGS
                if flag.lower() in command_line.lower()
            ]

            if matched_flags:
                alerts.append({
                    "alert_name": "Suspicious PowerShell Execution",
                    "severity": "High",
                    "risk_score": 85,
                    "timestamp": event.get("timestamp"),
                    "host": "Local Windows Host",
                    "user": event.get("user"),
                    "process": event.get("image"),
                    "parent_process": event.get("parent_image"),
                    "command_line": command_line,
                    "matched_flags": matched_flags,
                    "mitre": {
                        "technique_id": "T1059.001",
                        "technique_name": "PowerShell"
                    },
                    "raw_event": event
                })

    OUTPUT_FILE.write_text(json.dumps(alerts, indent=4, default=str))

    print(f"Generated {len(alerts)} alerts.")
    print(f"Saved to {OUTPUT_FILE}")

    return alerts


if __name__ == "__main__":
    detect_suspicious_powershell()
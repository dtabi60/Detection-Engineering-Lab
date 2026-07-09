import json
from pathlib import Path


RAW_EVENTS = Path("data/raw_defender_events.json")
OUTPUT_EVENTS = Path("data/defender_normalized.json")


EVENT_TYPE_MAP = {
    1116: ("malware_detected", "high"),
    1117: ("remediation_started", "medium"),
    1118: ("remediation_failed", "high"),
    1119: ("remediation_succeeded", "low"),
    1121: ("behavior_detected", "high"),
    5007: ("defender_configuration_changed", "medium"),
}


def normalize_event(event: dict) -> dict:
    event_id = int(event.get("Id", 0))

    event_type, severity = EVENT_TYPE_MAP.get(
        event_id,
        ("unknown_defender_event", "low"),
    )

    return {
        "timestamp": event.get("TimeCreated"),
        "source": "windows_defender",
        "event_id": event_id,
        "event_type": event_type,
        "severity": severity,
        "hostname": event.get("MachineName"),
        "provider": event.get("ProviderName"),
        "message": event.get("Message"),
        "raw": event,
    }


def normalize_events():
    if not RAW_EVENTS.exists():
        raise FileNotFoundError(f"Missing input file: {RAW_EVENTS}")

    with open(RAW_EVENTS, "r", encoding="utf-8") as f:
        raw_events = json.load(f)

    normalized = [normalize_event(event) for event in raw_events]

    with open(OUTPUT_EVENTS, "w", encoding="utf-8") as f:
        json.dump(normalized, f, indent=4)

    print(f"Normalized {len(normalized)} Defender events")
    print(f"Saved to {OUTPUT_EVENTS}")


if __name__ == "__main__":
    normalize_events()
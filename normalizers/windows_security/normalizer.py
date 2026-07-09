import json
from pathlib import Path


RAW_EVENTS = Path("data/raw_windows_security_events.json")
OUTPUT_EVENTS = Path("data/windows_security_normalized.json")


EVENT_TYPE_MAP = {
    4624: ("successful_logon", "low"),
    4625: ("failed_logon", "medium"),
    4672: ("special_privileges_assigned", "high"),
    4688: ("process_creation", "medium"),
    4720: ("user_account_created", "medium"),
    4728: ("user_added_to_privileged_group", "high"),
    4732: ("user_added_to_local_group", "medium"),
}


def normalize_event(event: dict) -> dict:
    event_id = int(event.get("Id", 0))

    event_type, severity = EVENT_TYPE_MAP.get(
        event_id,
        ("unknown", "low"),
    )

    return {
        "timestamp": event.get("TimeCreated"),
        "source": "windows_security",
        "event_id": event_id,
        "event_type": event_type,
        "severity": severity,
        "hostname": event.get("MachineName"),
        "provider": event.get("ProviderName"),
        "message": event.get("Message"),
        "raw": event,
    }


def normalize_events():
    with open(RAW_EVENTS, "r", encoding="utf-8") as f:
        raw_events = json.load(f)

    normalized = [
        normalize_event(event)
        for event in raw_events
    ]

    with open(OUTPUT_EVENTS, "w", encoding="utf-8") as f:
        json.dump(normalized, f, indent=4)

    print(f"Normalized {len(normalized)} events")
    print(f"Saved to {OUTPUT_EVENTS}")


if __name__ == "__main__":
    normalize_events()
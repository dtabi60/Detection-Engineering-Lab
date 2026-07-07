import json
import re
from datetime import datetime, timezone
from pathlib import Path

RAW_FILE = Path("data/live_sysmon_events.json")
OUTPUT_FILE = Path("data/normalized_sysmon_events.json")


def clean_timestamp(value):
    if not value:
        return None

    value = str(value)

    # Handles PowerShell JSON format: /Date(1783226741146)/
    match = re.search(r"/Date\((\d+)\)/", value)
    if match:
        milliseconds = int(match.group(1))
        seconds = milliseconds / 1000
        return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Handles normal timestamp strings
    return value


def extract_field(message, field_name):
    pattern = rf"{field_name}:\s*(.*)"
    match = re.search(pattern, message)
    if match:
        return match.group(1).strip()
    return None


def normalize_event(raw_event):
    message = raw_event.get("Message", "")
    event_id = raw_event.get("Id")

    event_type_map = {
        1: "process_create",
        3: "network_connection",
        7: "image_loaded",
        11: "file_created",
        13: "registry_value_set",
        22: "dns_query"
    }

    normalized = {
        "timestamp": clean_timestamp(raw_event.get("TimeCreated")),
        "event_id": event_id,
        "event_type": event_type_map.get(event_id, "unknown"),
        "host": extract_field(message, "Computer") or "local_endpoint",
        "user": extract_field(message, "User"),
        "image": extract_field(message, "Image"),
        "process_guid": extract_field(message, "ProcessGuid"),
        "process_id": extract_field(message, "ProcessId"),
        "command_line": extract_field(message, "CommandLine"),
        "current_directory": extract_field(message, "CurrentDirectory"),
        "parent_image": extract_field(message, "ParentImage"),
        "parent_command_line": extract_field(message, "ParentCommandLine"),
        "integrity_level": extract_field(message, "IntegrityLevel"),
        "hashes": extract_field(message, "Hashes"),
        "raw_message": message
    }

    return normalized


def normalize_sysmon_events():
    if not RAW_FILE.exists():
        print(f"[-] Raw file not found: {RAW_FILE}")
        print("Run this first: python collectors\\sysmon.py")
        return []

    raw_events = json.loads(RAW_FILE.read_text(encoding="utf-8"))

    if isinstance(raw_events, dict):
        raw_events = [raw_events]

    normalized_events = [normalize_event(event) for event in raw_events]

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(
        json.dumps(normalized_events, indent=4, default=str),
        encoding="utf-8"
    )

    print(f"[+] Normalized {len(normalized_events)} Sysmon events")
    print(f"[+] Saved to {OUTPUT_FILE}")

    return normalized_events


if __name__ == "__main__":
    normalize_sysmon_events()
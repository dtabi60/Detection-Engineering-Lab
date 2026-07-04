import json
import re
from pathlib import Path

INPUT_FILE = Path("data/live_sysmon_events.json")
OUTPUT_FILE = Path("data/normalized_sysmon_events.json")


def extract_field(message: str, field_name: str) -> str:
    """
    Extract a field from a Sysmon message.

    Example:
    Image: Windows PowerShell executable path
    """
    pattern = rf"{field_name}:\s*(.*)"
    match = re.search(pattern, message)

    if match:
        return match.group(1).strip()

    return "Unknown"


def parse_event(event):

    message = event.get("Message", "")

    normalized = {

        # Human-readable timestamp from Sysmon
        "timestamp": extract_field(message, "UtcTime"),

        # Native Windows metadata
        "event_id": event.get("Id"),
        "provider": event.get("ProviderName"),

        # Core process information
        "process_guid": extract_field(message, "ProcessGuid"),
        "process_id": extract_field(message, "ProcessId"),
        "image": extract_field(message, "Image"),
        "command_line": extract_field(message, "CommandLine"),
        "current_directory": extract_field(message, "CurrentDirectory"),
        "user": extract_field(message, "User"),
        "integrity_level": extract_field(message, "IntegrityLevel"),
        "hashes": extract_field(message, "Hashes"),

        # Parent process
        "parent_process_guid": extract_field(message, "ParentProcessGuid"),
        "parent_process_id": extract_field(message, "ParentProcessId"),
        "parent_image": extract_field(message, "ParentImage"),
        "parent_command_line": extract_field(message, "ParentCommandLine"),
        "parent_user": extract_field(message, "ParentUser"),

        # Executable metadata
        "company": extract_field(message, "Company"),
        "description": extract_field(message, "Description"),
        "product": extract_field(message, "Product"),
        "original_file_name": extract_field(message, "OriginalFileName"),

        # Keep the raw message for future parsing
        "raw_message": message
    }

    return normalized


def main():

    if not INPUT_FILE.exists():
        print("Run collectors\\sysmon.py first.")
        return

    events = json.loads(INPUT_FILE.read_text())

    if isinstance(events, dict):
        events = [events]

    normalized = []

    for event in events:
        normalized.append(parse_event(event))

    OUTPUT_FILE.write_text(
        json.dumps(normalized, indent=4, default=str)
    )

    print(f"Parsed {len(normalized)} events.")
    print(f"Saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
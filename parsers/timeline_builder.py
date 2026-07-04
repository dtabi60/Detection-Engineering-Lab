import json
from pathlib import Path

INPUT_FILE = Path("data/normalized_sysmon_events.json")
OUTPUT_FILE = Path("data/investigation_timeline.json")


def build_timeline():
    if not INPUT_FILE.exists():
        print("Run the collector and parser first.")
        return []

    events = json.loads(INPUT_FILE.read_text())

    timeline = []

    for event in events:
        event_id = event.get("event_id")
        timestamp = event.get("timestamp")

        if event_id == 1:
            title = "Process Created"
            detail = event.get("command_line")

        elif event_id == 3:
            title = "Network Connection"
            detail = f"{event.get('source_ip', 'Unknown')} → {event.get('destination_ip', 'Unknown')}"

        elif event_id == 11:
            title = "File Created"
            detail = event.get("target_filename", "Unknown")

        elif event_id == 22:
            title = "DNS Query"
            detail = event.get("query_name", "Unknown")

        elif event_id == 13:
            title = "Registry Modified"
            detail = event.get("target_object", "Unknown")

        else:
            title = f"Sysmon Event {event_id}"
            detail = event.get("command_line", "No detail available")

        timeline.append({
            "timestamp": timestamp,
            "event_id": event_id,
            "title": title,
            "detail": detail,
            "user": event.get("user", "Unknown"),
            "process": event.get("image", "Unknown"),
            "parent_process": event.get("parent_image", "Unknown"),
            "raw_event": event
        })

    timeline = sorted(timeline, key=lambda x: str(x.get("timestamp")))

    OUTPUT_FILE.write_text(json.dumps(timeline, indent=4, default=str))

    print(f"Built timeline with {len(timeline)} events.")
    print(f"Saved to {OUTPUT_FILE}")

    return timeline


if __name__ == "__main__":
    build_timeline()
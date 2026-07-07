import re
from datetime import datetime, timezone


def normalize_timestamp(value):
    """
    Converts many timestamp formats into one clean format:
    YYYY-MM-DD HH:MM:SS

    Supports:
    - /Date(1783260455973)/
    - Date(1783260455973)/
    - Unix seconds
    - Unix milliseconds
    - ISO timestamps
    - None / empty values
    """

    if value is None or value == "":
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    value = str(value).strip()

    # Microsoft JSON date format: /Date(1783260455973)/
    match = re.search(r"Date\((\d+)\)", value)
    if match:
        milliseconds = int(match.group(1))
        seconds = milliseconds / 1000
        return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    # Unix timestamp as number
    if value.isdigit():
        number = int(value)

        # milliseconds
        if number > 9999999999:
            number = number / 1000

        return datetime.fromtimestamp(number, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    # ISO timestamp
    try:
        cleaned = value.replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        pass

    # fallback
    return value
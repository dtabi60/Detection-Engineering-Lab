from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

from fastapi import APIRouter, Query

from storage.investigation import get_all_alerts


router = APIRouter(
    prefix="/api/v1/timeline",
    tags=["timeline"]
)


SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4
}


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def floor_to_bucket(dt: datetime, minutes: int = 5) -> datetime:
    discard = timedelta(
        minutes=dt.minute % minutes,
        seconds=dt.second,
        microseconds=dt.microsecond
    )
    return dt - discard


def get_highest_severity(current: str, new: str) -> str:
    current_rank = SEVERITY_RANK.get(str(current).lower(), 0)
    new_rank = SEVERITY_RANK.get(str(new).lower(), 0)
    return new if new_rank > current_rank else current


@router.get("/")
def get_timeline(
    start_time: Optional[str] = Query(default=None),
    end_time: Optional[str] = Query(default=None),
    host_id: Optional[str] = Query(default=None),
    bucket_minutes: int = Query(default=5, ge=1, le=60)
):
    alerts = get_all_alerts()

    filtered_events: List[Dict[str, Any]] = []

    for alert in alerts:
        timestamp = alert.get("timestamp") or alert.get("event_time") or alert.get("created_at")

        if not timestamp:
            continue

        try:
            event_dt = parse_time(str(timestamp))
        except ValueError:
            continue

        if start_time and event_dt < parse_time(start_time):
            continue

        if end_time and event_dt > parse_time(end_time):
            continue

        if host_id and str(alert.get("host_id", "")).lower() != host_id.lower():
            continue

        alert["_parsed_time"] = event_dt
        filtered_events.append(alert)

    buckets = {}

    for event in filtered_events:
        bucket_start_dt = floor_to_bucket(event["_parsed_time"], bucket_minutes)
        bucket_end_dt = bucket_start_dt + timedelta(minutes=bucket_minutes)
        bucket_key = bucket_start_dt.isoformat()

        severity = str(event.get("severity", "low"))

        if bucket_key not in buckets:
            buckets[bucket_key] = {
                "bucket_start": bucket_start_dt.isoformat(),
                "bucket_end": bucket_end_dt.isoformat(),
                "event_count": 0,
                "highest_severity": severity,
                "events": []
            }

        buckets[bucket_key]["event_count"] += 1
        buckets[bucket_key]["highest_severity"] = get_highest_severity(
            buckets[bucket_key]["highest_severity"],
            severity
        )

        event.pop("_parsed_time", None)

        buckets[bucket_key]["events"].append({
            "alert_id": event.get("alert_id"),
            "host_id": event.get("host_id"),
            "severity": event.get("severity"),
            "title": event.get("title") or event.get("name"),
            "timestamp": timestamp
        })

    return {
        "filters": {
            "start_time": start_time,
            "end_time": end_time,
            "host_id": host_id,
            "bucket_minutes": bucket_minutes
        },
        "bucket_count": len(buckets),
        "timeline": list(sorted(buckets.values(), key=lambda x: x["bucket_start"]))
    }
import ipaddress
import re
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Query

from api.schemas import EntityPivotResponse, EntityTimelineEvent, EntityType
from storage.investigation import get_all_alerts


router = APIRouter(
    prefix="/api/v1/entities",
    tags=["entity-pivot"],
)


SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")


@router.get("/pivot/{entity_value}", response_model=EntityPivotResponse)
def pivot_entity(
    entity_value: str,
    start_time: Optional[str] = Query(default=None),
    end_time: Optional[str] = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
):
    entity_type = identify_entity_type(entity_value)
    alerts = get_all_alerts()

    timeline: List[EntityTimelineEvent] = []

    for alert in alerts:
        timestamp = str(alert.get("timestamp", ""))

        if start_time and timestamp < start_time:
            continue

        if end_time and timestamp > end_time:
            continue

        if not alert_contains_entity(alert, entity_value):
            continue

        timeline.append(
            EntityTimelineEvent(
                timestamp=alert.get("timestamp"),
                event_type=alert.get("event_type", "alert"),
                source="alerts",
                entity_type=entity_type,
                entity_value=entity_value,
                alert_id=str(alert.get("alert_id") or alert.get("id") or ""),
                host_id=alert.get("host_id") or alert.get("hostname"),
                process_guid=alert.get("process_guid"),
                severity=alert.get("severity"),
                summary=alert.get("title") or alert.get("alert_name") or alert.get("name"),
                raw=alert,
            )
        )

    timeline.sort(key=lambda x: x.timestamp or "", reverse=True)

    return EntityPivotResponse(
        entity_value=entity_value,
        entity_type=entity_type,
        count=len(timeline[:limit]),
        timeline=timeline[:limit],
    )


def identify_entity_type(value: str) -> EntityType:
    normalized = value.strip()

    try:
        ipaddress.ip_address(normalized)
        return EntityType.ip
    except ValueError:
        pass

    if SHA256_RE.match(normalized) or SHA1_RE.match(normalized) or MD5_RE.match(normalized):
        return EntityType.hash

    if normalized.lower().startswith("proc-") or "{" in normalized:
        return EntityType.process_guid

    if "\\" in normalized or "@" in normalized:
        return EntityType.user

    if "." in normalized or normalized.upper().startswith(("WIN", "DESKTOP", "LAPTOP")):
        return EntityType.host

    if normalized.lower().endswith(".exe"):
        return EntityType.process_name

    return EntityType.unknown


def alert_contains_entity(alert: Dict[str, Any], entity_value: str) -> bool:
    needle = entity_value.lower()

    searchable_values = [
        alert.get("host_id"),
        alert.get("hostname"),
        alert.get("host_ip"),
        alert.get("source_ip"),
        alert.get("src_ip"),
        alert.get("destination_ip"),
        alert.get("dest_ip"),
        alert.get("remote_ip"),
        alert.get("user"),
        alert.get("username"),
        alert.get("process_guid"),
        alert.get("process_name"),
        alert.get("process"),
        alert.get("image"),
        alert.get("file_hash"),
        alert.get("sha256"),
        alert.get("sha1"),
        alert.get("md5"),
        alert.get("command_line"),
    ]

    return any(
        needle in str(value).lower()
        for value in searchable_values
        if value is not None
    )
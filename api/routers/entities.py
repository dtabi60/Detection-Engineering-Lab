from typing import Optional, Dict, Any, List

from fastapi import APIRouter, Query

from api.schemas import EntityType
from storage.investigation import get_all_alerts, get_alert_investigation
from storage.storyline import get_storyline
from storage.process_tree import render_process_tree


router = APIRouter(
    prefix="/api/v1/entities",
    tags=["entities"]
)


def entity_matches(value: Any, entity_id: str) -> bool:
    if value is None:
        return False

    if isinstance(value, dict):
        return any(entity_matches(v, entity_id) for v in value.values())

    if isinstance(value, list):
        return any(entity_matches(v, entity_id) for v in value)

    return str(value).lower() == entity_id.lower()


@router.get("/{entity_id}")
def pivot_entity(
    entity_id: str,
    entity_type: EntityType = Query(...),
    start_time: Optional[str] = Query(default=None),
    end_time: Optional[str] = Query(default=None)
):
    alerts = get_all_alerts()
    matches: List[Dict[str, Any]] = []

    for alert in alerts:
        timestamp = str(
            alert.get("timestamp")
            or alert.get("event_time")
            or alert.get("created_at")
            or ""
        )

        if start_time and timestamp and timestamp < start_time:
            continue

        if end_time and timestamp and timestamp > end_time:
            continue

        alert_id = alert.get("alert_id")
        storyline_id = alert.get("storyline_id")

        alert_matched = entity_matches(alert, entity_id)

        investigation = None
        storyline = None
        process_tree = None

        if alert_id:
            investigation = get_alert_investigation(str(alert_id))

        if storyline_id:
            storyline = get_storyline(str(storyline_id))
            process_tree = render_process_tree(str(storyline_id))

        if (
            alert_matched
            or entity_matches(investigation, entity_id)
            or entity_matches(storyline, entity_id)
            or entity_matches(process_tree, entity_id)
        ):
            matches.append({
                "entity_id": entity_id,
                "entity_type": entity_type.value,
                "alert_id": alert_id,
                "storyline_id": storyline_id,
                "host_id": alert.get("host_id"),
                "timestamp": timestamp,
                "severity": alert.get("severity"),
                "match_sources": {
                    "alert": alert_matched,
                    "investigation": entity_matches(investigation, entity_id),
                    "storyline": entity_matches(storyline, entity_id),
                    "process_tree": entity_matches(process_tree, entity_id)
                },
                "alert_summary": {
                    "title": alert.get("title") or alert.get("name"),
                    "description": alert.get("description"),
                    "severity": alert.get("severity")
                }
            })

    return {
        "entity_id": entity_id,
        "entity_type": entity_type.value,
        "filters": {
            "start_time": start_time,
            "end_time": end_time
        },
        "match_count": len(matches),
        "matches": matches
    }
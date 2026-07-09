from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException

from api.schemas import UnifiedInvestigationResponse
from storage.investigation import get_all_alerts, get_alert_investigation
from storage.process_tree import render_process_tree
from storage.response_actions import get_response_actions
from storage.storyline import get_storyline


router = APIRouter(
    prefix="/api/v1/unified-investigation",
    tags=["unified-investigation"],
)


@router.get("/{alert_id}", response_model=UnifiedInvestigationResponse)
def get_unified_investigation(alert_id: str):
    alert = find_alert(alert_id)

    if not alert:
        raise HTTPException(
            status_code=404,
            detail=f"Alert {alert_id} not found.",
        )

    storyline_id = alert.get("storyline_id")
    process_guid = alert.get("process_guid") or storyline_id

    investigation = safe_call(get_alert_investigation, alert_id, default={})
    process_tree = safe_call(render_process_tree, process_guid, default={})
    storyline = safe_call(get_storyline, storyline_id, default={})
    response_actions = safe_call(get_response_actions, alert_id, default=[])

    processes = extract_processes(investigation, process_tree, storyline)
    network_connections = extract_network_connections(investigation, storyline)
    file_events = extract_file_events(investigation, storyline)

    return UnifiedInvestigationResponse(
        alert_id=str(alert_id),
        alert=alert,
        processes=processes,
        network_connections=network_connections,
        file_events=file_events,
        response_actions=response_actions or [],
    )


def find_alert(alert_id: str) -> Dict[str, Any] | None:
    alerts = get_all_alerts()

    for alert in alerts:
        current_id = str(alert.get("alert_id") or alert.get("id") or "")
        if current_id == str(alert_id):
            return alert

    return None


def safe_call(func, *args, default):
    try:
        if not args or any(arg is None for arg in args):
            return default
        return func(*args)
    except Exception:
        return default


def extract_processes(
    investigation: Dict[str, Any],
    process_tree: Dict[str, Any],
    storyline: Dict[str, Any],
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    for source in [investigation, process_tree, storyline]:
        collect_matching_dicts(
            source,
            results,
            keys=["process_name", "process_guid", "process_id", "command_line"],
        )

    return dedupe_dicts(results)


def extract_network_connections(
    investigation: Dict[str, Any],
    storyline: Dict[str, Any],
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    for source in [investigation, storyline]:
        collect_matching_dicts(
            source,
            results,
            keys=["destination_ip", "dest_ip", "remote_ip", "destination_port"],
        )

    return dedupe_dicts(results)


def extract_file_events(
    investigation: Dict[str, Any],
    storyline: Dict[str, Any],
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    for source in [investigation, storyline]:
        collect_matching_dicts(
            source,
            results,
            keys=["file_path", "file_hash", "sha256", "sha1", "md5"],
        )

    return dedupe_dicts(results)


def collect_matching_dicts(
    obj: Any,
    results: List[Dict[str, Any]],
    keys: List[str],
):
    if isinstance(obj, dict):
        if any(key in obj for key in keys):
            results.append(obj)

        for value in obj.values():
            collect_matching_dicts(value, results, keys)

    elif isinstance(obj, list):
        for item in obj:
            collect_matching_dicts(item, results, keys)


def dedupe_dicts(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    deduped = []

    for item in items:
        marker = str(sorted(item.items()))
        if marker not in seen:
            seen.add(marker)
            deduped.append(item)

    return deduped
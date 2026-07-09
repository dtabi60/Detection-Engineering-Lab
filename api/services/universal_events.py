from datetime import datetime
from typing import Any, Dict

from api.models.telemetry import (
    NormalizedAction,
    PowerShell4104Event,
    ProcessContext,
    TelemetrySource,
    UniversalEvent,
)


def normalize_powershell_4104(event: PowerShell4104Event) -> UniversalEvent:
    return UniversalEvent(
        timestamp=event.timestamp,
        event_id="4104",
        source=TelemetrySource.powershell,
        actor_user=event.actor_user,
        subject_domain=event.subject_domain,
        process_context=ProcessContext(
            process_id=event.process_id,
            parent_process_id=event.parent_process_id,
            process_name=event.process_name,
            command_line=event.command_line,
        ),
        normalized_action=NormalizedAction.script_execution,
        summary="PowerShell Script Block Logging event captured.",
        raw_payload={
            **event.raw_payload,
            "script_block_text": event.script_block_text,
            "script_block_id": event.script_block_id,
            "runspace_id": event.runspace_id,
        },
    )


def normalize_windows_security_row(row: Dict[str, Any]) -> UniversalEvent:
    event_id = str(row.get("event_id"))

    action = NormalizedAction.authentication
    if event_id == "4672":
        action = NormalizedAction.privilege_change

    return UniversalEvent(
        timestamp=parse_time(row.get("timestamp")),
        event_id=event_id,
        source=TelemetrySource.win_security,
        actor_user=None,
        subject_domain=None,
        normalized_action=action,
        summary=row.get("event_type") or "Windows Security event.",
        raw_payload=row,
    )


def normalize_sysmon_process_row(row: Dict[str, Any]) -> UniversalEvent:
    return UniversalEvent(
        timestamp=parse_time(row.get("timestamp")),
        event_id="1",
        source=TelemetrySource.sysmon,
        actor_user=row.get("user"),
        process_context=ProcessContext(
            process_id=str(row.get("process_id") or ""),
            parent_process_id=str(row.get("parent_process_id") or ""),
            process_name=row.get("process_name"),
            command_line=row.get("command_line"),
        ),
        normalized_action=NormalizedAction.process_creation,
        summary=f"Process created: {row.get('process_name')}",
        raw_payload=row,
    )


def normalize_sysmon_network_row(row: Dict[str, Any]) -> UniversalEvent:
    return UniversalEvent(
        timestamp=parse_time(row.get("timestamp")),
        event_id="3",
        source=TelemetrySource.sysmon,
        process_context=ProcessContext(
            process_id=str(row.get("process_id") or ""),
        ),
        normalized_action=NormalizedAction.network_connection,
        summary=f"Network connection to {row.get('destination_ip')}:{row.get('destination_port')}",
        raw_payload=row,
    )


def normalize_powershell_row(row: Dict[str, Any]) -> UniversalEvent:
    return UniversalEvent(
        timestamp=parse_time(row.get("timestamp")),
        event_id="4104",
        source=TelemetrySource.powershell,
        actor_user=row.get("actor_user"),
        subject_domain=row.get("subject_domain"),
        process_context=ProcessContext(
            process_id=row.get("process_id"),
            parent_process_id=row.get("parent_process_id"),
            process_name=row.get("process_name"),
            command_line=row.get("command_line"),
        ),
        normalized_action=NormalizedAction.script_execution,
        summary="PowerShell script block executed.",
        raw_payload=row,
    )


def parse_time(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value

    if not value:
        return datetime.utcnow()

    text = str(value).replace("Z", "+00:00")

    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return datetime.utcnow()
    
def normalize_defender_row(row: Dict[str, Any]) -> UniversalEvent:
    event_type = str(row.get("event_type") or "").lower()

    action = NormalizedAction.unknown

    if "malware" in event_type or "behavior" in event_type:
        action = NormalizedAction.script_execution
    elif "remediation" in event_type:
        action = NormalizedAction.file_write

    return UniversalEvent(
        timestamp=parse_time(row.get("timestamp")),
        event_id=str(row.get("event_id")),
        source=TelemetrySource.defender,
        actor_user=None,
        subject_domain=None,
        process_context=ProcessContext(),
        normalized_action=action,
        summary=row.get("event_type") or "Microsoft Defender event.",
        raw_payload=row,
    )
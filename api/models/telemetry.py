from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class TelemetrySource(str, Enum):
    sysmon = "Sysmon"
    win_security = "WinSecurity"
    powershell = "PowerShell"


class NormalizedAction(str, Enum):
    process_creation = "PROCESS_CREATION"
    authentication = "AUTHENTICATION"
    script_execution = "SCRIPT_EXECUTION"
    network_connection = "NETWORK_CONNECTION"
    file_write = "FILE_WRITE"
    privilege_change = "PRIVILEGE_CHANGE"
    unknown = "UNKNOWN"


class ProcessContext(BaseModel):
    process_id: Optional[str] = None
    parent_process_id: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None


class PowerShell4104Event(BaseModel):
    timestamp: datetime
    event_id: str = "4104"
    hostname: str
    actor_user: str
    subject_domain: Optional[str] = None
    process_id: Optional[str] = None
    parent_process_id: Optional[str] = None
    process_name: str = "powershell.exe"
    command_line: Optional[str] = None
    script_block_text: str
    script_block_id: Optional[str] = None
    runspace_id: Optional[str] = None
    raw_payload: Dict[str, Any] = Field(default_factory=dict)


class UniversalEvent(BaseModel):
    timestamp: datetime
    event_id: str
    source: TelemetrySource
    actor_user: Optional[str] = None
    subject_domain: Optional[str] = None
    process_context: ProcessContext = Field(default_factory=ProcessContext)
    normalized_action: NormalizedAction
    summary: str
    raw_payload: Dict[str, Any] = Field(default_factory=dict)


class DetectionFinding(BaseModel):
    rule_id: str
    rule_name: str
    severity: str
    timestamp: datetime
    source: TelemetrySource
    event_id: str
    actor_user: Optional[str] = None
    process_name: Optional[str] = None
    summary: str
    evidence: str
    mitre_technique: Optional[str] = None


class PowerShellIngestResponse(BaseModel):
    ingested_count: int
    detections_count: int
    detections: List[DetectionFinding]
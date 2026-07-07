from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ResponseActionType(str, Enum):
    isolate_host = "Isolate Host"
    kill_process = "Kill Process"
    quarantine_file = "Quarantine File"
    disconnect_network = "Disconnect Network"
    collect_forensic_package = "Collect Forensic Package"


class EntityType(str, Enum):
    user = "user"
    process = "process"
    ip = "ip"
    hostname = "hostname"
    file_hash = "file_hash"


class ResponseActionRequest(BaseModel):
    host_id: str = Field(..., min_length=1)
    alert_id: str = Field(..., min_length=1)
    action_type: ResponseActionType
    target_identifier: str = Field(..., min_length=1)


class ResponseActionResponse(BaseModel):
    message: str
    tracking_id: str
    status: str
    action: Dict[str, Any]


class TimelineEvent(BaseModel):
    alert_id: Optional[str] = None
    host_id: Optional[str] = None
    severity: Optional[str] = None
    title: Optional[str] = None
    timestamp: str


class TimelineBucket(BaseModel):
    bucket_start: str
    bucket_end: str
    event_count: int
    highest_severity: str
    events: List[TimelineEvent]


class TimelineResponse(BaseModel):
    filters: Dict[str, Any]
    bucket_count: int
    timeline: List[TimelineBucket]


class EntityPivotResponse(BaseModel):
    entity_id: str
    entity_type: EntityType
    match_count: int
    matches: List[Dict[str, Any]]
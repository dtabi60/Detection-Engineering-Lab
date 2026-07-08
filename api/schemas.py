from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ============================================================
# Response Actions
# ============================================================

class ResponseActionType(str, Enum):
    isolate_host = "Isolate Host"
    kill_process = "Kill Process"
    quarantine_file = "Quarantine File"
    disconnect_network = "Disconnect Network"
    collect_forensic_package = "Collect Forensic Package"


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


# ============================================================
# Timeline
# ============================================================

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


# ============================================================
# Entity Types
# ============================================================

class EntityType(str, Enum):
    host = "host"
    hostname = "hostname"
    ip = "ip"
    user = "user"
    hash = "hash"
    file_hash = "file_hash"
    process = "process"
    process_guid = "process_guid"
    process_name = "process_name"
    unknown = "unknown"


# ============================================================
# Network Graph
# ============================================================

class NetworkGraphNodeType(str, Enum):
    source_ip = "source_ip"
    destination_ip = "destination_ip"
    process = "process"


class NetworkGraphNode(BaseModel):
    id: str
    label: str
    type: NetworkGraphNodeType
    metadata: Dict[str, Any] = Field(default_factory=dict)


class NetworkGraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str
    weight: int = 1
    metadata: Dict[str, Any] = Field(default_factory=dict)


class NetworkGraphResponse(BaseModel):
    node_count: int
    edge_count: int
    nodes: List[NetworkGraphNode]
    edges: List[NetworkGraphEdge]


# ============================================================
# Entity Pivot
# ============================================================

class EntityTimelineEvent(BaseModel):
    timestamp: Optional[str] = None
    event_type: str
    source: str
    entity_type: EntityType
    entity_value: str

    alert_id: Optional[str] = None
    host_id: Optional[str] = None
    process_guid: Optional[str] = None
    severity: Optional[str] = None
    summary: Optional[str] = None

    raw: Dict[str, Any] = Field(default_factory=dict)


class EntityPivotResponse(BaseModel):
    entity_value: str
    entity_type: EntityType
    count: int
    timeline: List[EntityTimelineEvent]


# ============================================================
# MITRE ATT&CK
# ============================================================

class MITREEnrichment(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    badge: str


# ============================================================
# AI Summary
# ============================================================

class AlertSummaryRequest(BaseModel):
    alert: Dict[str, Any]


class AlertSummaryResponse(BaseModel):
    analyst_summary: str
    confidence: str = "medium"


# ============================================================
# Unified Investigation
# ============================================================

class UnifiedInvestigationResponse(BaseModel):
    alert_id: str
    alert: Dict[str, Any]

    processes: List[Dict[str, Any]]
    network_connections: List[Dict[str, Any]]
    file_events: List[Dict[str, Any]]
    response_actions: List[Dict[str, Any]]
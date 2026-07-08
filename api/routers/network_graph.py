from collections import defaultdict
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Query

from api.schemas import (
    NetworkGraphEdge,
    NetworkGraphNode,
    NetworkGraphNodeType,
    NetworkGraphResponse,
)

from storage.investigation import get_all_alerts


router = APIRouter(
    prefix="/api/v1/network-graph",
    tags=["network-graph"],
)


@router.get("/", response_model=NetworkGraphResponse)
def get_network_graph(
    host_id: Optional[str] = Query(default=None),
    start_time: Optional[str] = Query(default=None),
    end_time: Optional[str] = Query(default=None),
):
    alerts = get_all_alerts()

    nodes: Dict[str, NetworkGraphNode] = {}
    edge_weights = defaultdict(int)
    edge_metadata: Dict[str, Dict[str, Any]] = {}

    for alert in alerts:
        timestamp = str(alert.get("timestamp", ""))

        if host_id and str(alert.get("host_id", "")).lower() != host_id.lower():
            continue

        if start_time and timestamp < start_time:
            continue

        if end_time and timestamp > end_time:
            continue

        src_ip = alert.get("source_ip") or alert.get("src_ip") or alert.get("host_ip")
        dst_ip = alert.get("destination_ip") or alert.get("dest_ip") or alert.get("remote_ip")
        process = alert.get("process_name") or alert.get("process") or alert.get("image")

        if not src_ip or not dst_ip:
            continue

        src_id = f"ip:{src_ip}"
        dst_id = f"ip:{dst_ip}"

        nodes[src_id] = NetworkGraphNode(
            id=src_id,
            label=str(src_ip),
            type=NetworkGraphNodeType.source_ip,
            metadata={"host_id": alert.get("host_id")},
        )

        nodes[dst_id] = NetworkGraphNode(
            id=dst_id,
            label=str(dst_ip),
            type=NetworkGraphNodeType.destination_ip,
            metadata={"port": alert.get("destination_port")},
        )

        if process:
            process_id = f"process:{process}"

            nodes[process_id] = NetworkGraphNode(
                id=process_id,
                label=str(process),
                type=NetworkGraphNodeType.process,
                metadata={
                    "process_guid": alert.get("process_guid"),
                    "command_line": alert.get("command_line"),
                },
            )

            edge_id_1 = f"{src_id}->{process_id}"
            edge_weights[edge_id_1] += 1
            edge_metadata[edge_id_1] = {"relationship": "executed_network_activity"}

            edge_id_2 = f"{process_id}->{dst_id}"
            edge_weights[edge_id_2] += 1
            edge_metadata[edge_id_2] = {
                "relationship": "connected_to",
                "destination_port": alert.get("destination_port"),
                "protocol": alert.get("protocol"),
            }

        else:
            edge_id = f"{src_id}->{dst_id}"
            edge_weights[edge_id] += 1
            edge_metadata[edge_id] = {"relationship": "network_connection"}

    edges: List[NetworkGraphEdge] = []

    for edge_id, weight in edge_weights.items():
        source, target = edge_id.split("->", 1)

        edges.append(
            NetworkGraphEdge(
                id=edge_id,
                source=source,
                target=target,
                label=edge_metadata.get(edge_id, {}).get("relationship", "related"),
                weight=weight,
                metadata=edge_metadata.get(edge_id, {}),
            )
        )

    return NetworkGraphResponse(
        node_count=len(nodes),
        edge_count=len(edges),
        nodes=list(nodes.values()),
        edges=edges,
    )
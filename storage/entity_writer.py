from storage.entities import (
    init_entity_db,
    upsert_endpoint,
    add_process,
    add_network_connection,
    add_file_event,
    add_alert
)

from utils.time_utils import normalize_timestamp


def write_alert_to_entities(alert):
    """
    Takes one alert dictionary and writes it into the entity database.
    """

    init_entity_db()

    hostname = alert.get("hostname") or alert.get("host") or "UNKNOWN-HOST"
    ip_address = alert.get("ip_address")
    os = alert.get("os")

    timestamp = normalize_timestamp(alert.get("timestamp"))

    endpoint_id = upsert_endpoint(
        hostname=hostname,
        ip_address=ip_address,
        os=os
    )

    process_name = alert.get("process_name")
    process_id = alert.get("process_id")
    parent_process_id = alert.get("parent_process_id")
    command_line = alert.get("command_line")
    user = alert.get("user")

    if process_name:
        add_process(
            endpoint_id=endpoint_id,
            process_name=process_name,
            process_id=process_id,
            parent_process_id=parent_process_id,
            command_line=command_line,
            user=user,
            timestamp=timestamp
        )

    destination_ip = alert.get("destination_ip")

    if destination_ip:
        add_network_connection(
            endpoint_id=endpoint_id,
            process_id=process_id,
            destination_ip=destination_ip,
            destination_port=alert.get("destination_port"),
            protocol=alert.get("protocol"),
            timestamp=timestamp
        )

    file_path = alert.get("file_path")

    if file_path:
        add_file_event(
            endpoint_id=endpoint_id,
            process_id=process_id,
            file_path=file_path,
            file_hash=alert.get("file_hash"),
            action=alert.get("file_action"),
            timestamp=timestamp
        )

    add_alert(
        endpoint_id=endpoint_id,
        alert_name=alert.get("rule_name") or alert.get("alert_name") or "Unknown Alert",
        severity=alert.get("severity") or "Medium",
        mitre_technique=alert.get("mitre_technique") or alert.get("mitre") or "Unknown",
        description=alert.get("description") or "No description provided.",
        timestamp=timestamp
    )

    return endpoint_id
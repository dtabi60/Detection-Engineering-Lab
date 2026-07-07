from storage.entities import (
    init_entity_db,
    upsert_endpoint,
    add_process,
    add_network_connection,
    add_file_event,
    add_alert,
    get_endpoint_summary
)

init_entity_db()

endpoint_id = upsert_endpoint(
    hostname="DESKTOP-LAB01",
    ip_address="192.168.1.50",
    os="Windows 11"
)

add_process(
    endpoint_id=endpoint_id,
    process_name="powershell.exe",
    process_id="4567",
    parent_process_id="1234",
    command_line="powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand test",
    user="Admin"
)

add_network_connection(
    endpoint_id=endpoint_id,
    process_id="4567",
    destination_ip="8.8.8.8",
    destination_port="53",
    protocol="UDP"
)

add_file_event(
    endpoint_id=endpoint_id,
    process_id="4567",
    file_path="C:\\Users\\Admin\\Downloads\\test.ps1",
    file_hash="abc123",
    action="created"
)

add_alert(
    endpoint_id=endpoint_id,
    alert_name="Suspicious Encoded PowerShell",
    severity="High",
    mitre_technique="T1059.001",
    description="PowerShell executed with encoded command."
)

summary = get_endpoint_summary("DESKTOP-LAB01")
print(summary)
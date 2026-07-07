from storage.entity_writer import write_alert_to_entities
from storage.entities import get_endpoint_summary

sample_alert = {
    "hostname": "DESKTOP-LAB01",
    "ip_address": "192.168.1.50",
    "os": "Windows 11",
    "process_name": "powershell.exe",
    "process_id": "4567",
    "parent_process_id": "1234",
    "command_line": "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand test",
    "user": "Admin",
    "destination_ip": "8.8.8.8",
    "destination_port": "53",
    "protocol": "UDP",
    "file_path": "C:\\Users\\Admin\\Downloads\\test.ps1",
    "file_hash": "abc123",
    "file_action": "created",
    "rule_name": "Suspicious Encoded PowerShell",
    "severity": "High",
    "mitre_technique": "T1059.001",
    "description": "PowerShell executed with encoded command.",
    "timestamp": "2026-07-05T21:00:00"
}

endpoint_id = write_alert_to_entities(sample_alert)

print("Wrote alert to endpoint ID:", endpoint_id)
print(get_endpoint_summary("DESKTOP-LAB01"))
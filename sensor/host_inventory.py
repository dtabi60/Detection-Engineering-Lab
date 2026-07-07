import json
import platform
import socket
import subprocess
from pathlib import Path

OUTPUT_FILE = Path("data/host_inventory.json")


def run_powershell(command):
    result = subprocess.run(
        ["powershell", "-Command", command],
        capture_output=True,
        text=True
    )
    return result.stdout.strip()


def collect_host_inventory():
    inventory = {
        "hostname": socket.gethostname(),
        "os": platform.platform(),
        "ip_addresses": run_powershell(
            "Get-NetIPAddress -AddressFamily IPv4 | "
            "Select-Object IPAddress,InterfaceAlias | ConvertTo-Json"
        ),
        "local_users": run_powershell(
            "Get-LocalUser | Select-Object Name,Enabled,LastLogon | ConvertTo-Json"
        ),
        "listening_ports": run_powershell(
            "Get-NetTCPConnection -State Listen | "
            "Select-Object LocalAddress,LocalPort,OwningProcess | ConvertTo-Json"
        )
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(inventory, indent=4), encoding="utf-8")

    print(f"[+] Host inventory saved to {OUTPUT_FILE}")
    return inventory


if __name__ == "__main__":
    collect_host_inventory()
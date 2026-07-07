import subprocess


def run_step(name, command):
    print(f"\n===== {name} =====")
    result = subprocess.run(command, shell=True, text=True)

    if result.returncode != 0:
        print(f"[-] {name} failed")
        return False

    print(f"[+] {name} completed")
    return True


def run_sensor():
    steps = [
        ("Collect Sysmon Events", "python collectors\\sysmon.py"),
        ("Collect PowerShell 4104 Events", "python sensor\\powershell_collector.py"),
        ("Collect Host Inventory", "python sensor\\host_inventory.py"),
        ("Normalize Sysmon Events", "python normalizers\\sysmon_normalizer.py"),
        ("Store Events in SQLite", "python storage\\database.py"),
        ("Run Detection Engine", "python detections\\engine.py"),
    ]

    for name, command in steps:
        run_step(name, command)


if __name__ == "__main__":
    run_sensor()
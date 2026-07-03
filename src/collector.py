"""
collector.py

Collects log files for the detection engine.
"""

from pathlib import Path


class LogCollector:
    def __init__(self, log_directory):
        self.log_directory = Path(log_directory)

    def list_logs(self):
        return list(self.log_directory.glob("*"))


if __name__ == "__main__":
    collector = LogCollector("sample_logs")

    logs = collector.list_logs()

    print(f"Found {len(logs)} log files.")

    for log in logs:
        print(log.name)
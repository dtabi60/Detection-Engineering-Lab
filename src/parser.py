"""
parser.py

Reads the contents of a log file and returns the text.
"""

from pathlib import Path


class LogParser:

    def read_log(self, file_path):
        file_path = Path(file_path)

        with open(file_path, "r") as log_file:
            return log_file.read()


if __name__ == "__main__":

    parser = LogParser()

    content = parser.read_log("sample_logs/powershell_test.txt")

    print("===== Log Contents =====")
    print(content)
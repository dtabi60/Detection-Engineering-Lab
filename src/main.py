from collector import LogCollector
from parser import LogParser
from detector import Detector


def main():
    collector = LogCollector("sample_logs")
    parser = LogParser()
    detector = Detector()

    log_files = collector.list_logs()

    print("===== Detection Engine Started =====")
    print(f"Found {len(log_files)} log files.")

    for log_file in log_files:
        if log_file.name == ".gitkeep":
            continue

        print(f"\nAnalyzing: {log_file.name}")

        log_text = parser.read_log(log_file)
        findings = detector.detect(log_text)

        if findings:
            for finding in findings:
                print(f"Suspicious flag detected: {finding}")
        else:
            print("No suspicious behavior found.")


if __name__ == "__main__":
    main()
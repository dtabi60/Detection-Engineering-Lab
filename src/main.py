from collector import LogCollector
from parser import LogParser
from detector import Detector
from risk import RiskScorer
from alert import AlertBuilder


def main():
    collector = LogCollector("sample_logs")
    parser = LogParser()
    detector = Detector("detections")
    risk_scorer = RiskScorer()
    alert_builder = AlertBuilder()

    log_files = collector.list_logs()

    print("\n===== Detection Engine Started =====")
    print(f"Found {len(log_files)} log files.\n")

    for log_file in log_files:
        if log_file.name == ".gitkeep":
            continue

        print(f"Analyzing: {log_file.name}")

        log_text = parser.read_log(log_file)
        findings = detector.detect(log_text)
        risk_score = risk_scorer.score(findings)

        alert = alert_builder.build_alert(
            log_file.name,
            findings,
            risk_score
        )

        print(f"Severity : {alert['severity']}")
        print(f"Risk     : {alert['risk_score']}")

        if findings:
            print("Findings:")
            for finding in findings:
                print(f"  - {finding['rule_title']} matched {finding['value']}")
                print(f"    MITRE: {finding['mitre'].get('technique_id')}")
        else:
            print("No suspicious behavior found.")

        print("-" * 40)


if __name__ == "__main__":
    main()
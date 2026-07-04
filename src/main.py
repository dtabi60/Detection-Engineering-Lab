import json
from pathlib import Path

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
    alerts = []

    for log_file in log_files:
        if log_file.name == ".gitkeep":
            continue

        log_text = parser.read_log(log_file)
        findings = detector.detect(log_text)
        risk_score = risk_scorer.score(findings)

        if findings:
            alert = alert_builder.build_alert(log_file.name, findings, risk_score)
            alerts.append(alert)

    Path("data").mkdir(exist_ok=True)
    Path("data/alerts.json").write_text(json.dumps(alerts, indent=4))

    print(f"Generated {len(alerts)} alerts.")
    print("Saved alerts to data/alerts.json")


if __name__ == "__main__":
    main()
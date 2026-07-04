"""
detector.py

Loads YAML detection rules and checks logs for suspicious patterns.
"""

import yaml
from pathlib import Path


class Detector:
    def __init__(self, rules_directory="detections"):
        self.rules_directory = Path(rules_directory)
        self.rules = self.load_rules()

    def load_rules(self):
        rules = []

        for rule_file in self.rules_directory.glob("*.yaml"):
            with open(rule_file, "r") as file:
                rule = yaml.safe_load(file)
                rules.append(rule)

        return rules

    def detect(self, log_text):
        findings = []

        for rule in self.rules:
            for pattern in rule.get("patterns", []):
                value = pattern.get("value")

                if value and value.lower() in log_text.lower():
                    findings.append({
                        "rule_title": rule.get("title"),
                        "value": value,
                        "score": pattern.get("score", 0),
                        "mitre": rule.get("mitre", {})
                    })

        return findings


if __name__ == "__main__":
    detector = Detector()

    sample_log = "powershell.exe -NoProfile -ExecutionPolicy Bypass"

    results = detector.detect(sample_log)

    for result in results:
        print(result)
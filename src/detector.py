"""
detector.py

Looks for suspicious PowerShell execution.
"""


class Detector:

    def detect_powershell(self, log_text):

        findings = []

        if "-ExecutionPolicy Bypass" in log_text:
            findings.append("ExecutionPolicy Bypass detected")

        if "-NoProfile" in log_text:
            findings.append("NoProfile detected")

        if "EncodedCommand" in log_text:
            findings.append("EncodedCommand detected")

        return findings


if __name__ == "__main__":

    sample = "Image=powershell.exe CommandLine=powershell.exe -NoProfile -ExecutionPolicy Bypass"

    detector = Detector()

    alerts = detector.detect_powershell(sample)

    print("Detections:")

    for alert in alerts:
        print("-", alert)
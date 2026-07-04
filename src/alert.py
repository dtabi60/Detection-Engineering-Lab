"""
alert.py

Builds security alerts from detection results.
"""


class AlertBuilder:
    """
    Creates alerts and assigns a severity level
    based on the calculated risk score.
    """

    def get_severity(self, risk_score):
        """
        Determine the alert severity based on the risk score.
        """

        if risk_score >= 70:
            return "High"

        elif risk_score >= 40:
            return "Medium"

        elif risk_score > 0:
            return "Low"

        return "Informational"

    def build_alert(self, log_file, findings, risk_score):
        """
        Build an alert dictionary.
        """

        severity = self.get_severity(risk_score)

        return {
            "log_file": log_file,
            "findings": findings,
            "risk_score": risk_score,
            "severity": severity,
        }


if __name__ == "__main__":

    builder = AlertBuilder()

    alert = builder.build_alert(
        "powershell_test.txt",
        [
            "-ExecutionPolicy Bypass",
            "-NoProfile"
        ],
        40
    )

    print("===== Alert =====")

    print(f"Log File   : {alert['log_file']}")
    print(f"Severity   : {alert['severity']}")
    print(f"Risk Score : {alert['risk_score']}")
    print("Findings:")

    for finding in alert["findings"]:
        print(f" - {finding}")
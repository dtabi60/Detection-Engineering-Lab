"""
risk.py

Calculates risk score from detection findings.
"""


class RiskScorer:
    def score(self, findings):
        total_score = 0

        for finding in findings:
            total_score += finding.get("score", 0)

        return total_score
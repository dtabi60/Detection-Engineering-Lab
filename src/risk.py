class RiskScorer:
    def __init__(self):
        self.weights = {
            "-EncodedCommand": 40,
            "-enc": 40,
            "-ExecutionPolicy Bypass": 30,
            "-WindowStyle Hidden": 25,
            "-NoProfile": 10,
            "-nop": 10,
        }

    def score(self, findings):
        total_score = 0

        for finding in findings:
            total_score += self.weights.get(finding, 0)

        return total_score
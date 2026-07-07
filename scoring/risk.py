def score_powershell(command_line):
    command_line = (command_line or "").lower()

    score = 0
    reasons = []

    if "-encodedcommand" in command_line or " -enc " in command_line:
        score += 40
        reasons.append("Encoded PowerShell command")

    if "-executionpolicy bypass" in command_line:
        score += 25
        reasons.append("ExecutionPolicy Bypass")

    if "-windowstyle hidden" in command_line:
        score += 25
        reasons.append("Hidden PowerShell window")

    if "-noprofile" in command_line:
        score += 10
        reasons.append("NoProfile flag")

    return score, reasons


def severity_from_score(score):
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    if score > 0:
        return "Low"
    return "Informational"
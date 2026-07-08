from typing import Any, Dict


def generate_ai_alert_summary(alert: Dict[str, Any]) -> Dict[str, str]:
    """
    Lightweight AI-style analyst summary.

    This version does not call a paid LLM yet.
    It creates a clean SOC analyst narrative from the alert fields.
    Later, we can replace this function with OpenAI/Ollama.
    """

    title = (
        alert.get("title")
        or alert.get("name")
        or alert.get("alert_name")
        or "Unknown Alert"
    )

    severity = alert.get("severity", "Unknown")
    host = alert.get("host_id") or alert.get("hostname") or "Unknown Host"
    user = alert.get("user") or alert.get("username") or "Unknown User"
    process = (
        alert.get("process_name")
        or alert.get("process")
        or alert.get("image")
        or "Unknown Process"
    )
    command_line = alert.get("command_line") or "No command line available."
    mitre = alert.get("mitre_technique") or "No MITRE technique mapped."

    summary = (
        f"{severity} severity alert '{title}' was observed on host {host}. "
        f"The activity appears associated with user {user} and process {process}. "
        f"Command line evidence: {command_line}. "
        f"Mapped MITRE context: {mitre}."
    )

    recommendation = build_recommendation(severity, process, command_line)

    return {
        "analyst_summary": summary,
        "recommended_action": recommendation,
        "confidence": "medium",
    }


def build_recommendation(severity: str, process: str, command_line: str) -> str:
    text = f"{severity} {process} {command_line}".lower()

    if "mimikatz" in text or "lsass" in text:
        return (
            "Treat as potential credential access. Isolate the host, collect memory, "
            "review identity activity, and reset exposed credentials if confirmed."
        )

    if "powershell" in text or "encodedcommand" in text:
        return (
            "Review script block logs, parent process, network connections, and user context. "
            "Contain the host if execution is unauthorized."
        )

    if "certutil" in text or "rundll32" in text or "regsvr32" in text:
        return (
            "Investigate possible LOLBin abuse. Review file writes, network activity, "
            "and process ancestry before containment."
        )

    return (
        "Review the alert context, process tree, storyline, and related endpoint telemetry "
        "before assigning final analyst verdict."
    )
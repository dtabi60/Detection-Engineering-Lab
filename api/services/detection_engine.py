import re
from typing import List

from api.models.telemetry import DetectionFinding, UniversalEvent


RULES = [
    {
        "rule_id": "EDR-001",
        "rule_name": "Obfuscated PowerShell Execution",
        "severity": "High",
        "regex": r"(?i)(-enc|-encodedcommand|\bfrombase64string\b|[A-Za-z0-9+/]{80,}={0,2})",
        "mitre": "T1059.001",
    },
    {
        "rule_id": "EDR-002",
        "rule_name": "PowerShell Network Download Cradle",
        "severity": "High",
        "regex": r"(?i)(new-object\s+system\.net\.webclient|downloadstring|invoke-webrequest|\biwr\b|start-bitstransfer)",
        "mitre": "T1105",
    },
    {
        "rule_id": "EDR-003",
        "rule_name": "Execution Policy Bypass",
        "severity": "Medium",
        "regex": r"(?i)(-executionpolicy\s+bypass|-ep\s+bypass|-nop|-noprofile)",
        "mitre": "T1059.001",
    },
]


def evaluate_universal_events(events: List[UniversalEvent]) -> List[DetectionFinding]:
    findings: List[DetectionFinding] = []

    for event in events:
        searchable = " ".join(
            [
                event.summary or "",
                event.process_context.command_line or "",
                str(event.raw_payload.get("script_block_text", "")),
                str(event.raw_payload),
            ]
        )

        for rule in RULES:
            if re.search(rule["regex"], searchable):
                findings.append(
                    DetectionFinding(
                        rule_id=rule["rule_id"],
                        rule_name=rule["rule_name"],
                        severity=rule["severity"],
                        timestamp=event.timestamp,
                        source=event.source,
                        event_id=event.event_id,
                        actor_user=event.actor_user,
                        process_name=event.process_context.process_name,
                        summary=event.summary,
                        evidence=searchable[:500],
                        mitre_technique=rule["mitre"],
                    )
                )

    return findings
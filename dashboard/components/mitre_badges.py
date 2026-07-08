import streamlit as st


MITRE_LOOKUP = {
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1059.001": ("PowerShell", "Execution"),
    "T1003": ("OS Credential Dumping", "Credential Access"),
    "T1003.001": ("LSASS Memory", "Credential Access"),
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1047": ("Windows Management Instrumentation", "Execution"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
}


def render_mitre_badges(alert: dict):
    st.subheader("🎯 MITRE ATT&CK Mapping")

    technique = (
        alert.get("mitre_technique")
        or alert.get("technique_id")
        or alert.get("attack_technique")
    )

    if not technique:
        st.info("No MITRE technique mapped for this alert.")
        return

    technique = str(technique).strip()
    name, tactic = MITRE_LOOKUP.get(
        technique,
        ("Unknown Technique", "Unknown Tactic"),
    )

    col1, col2, col3 = st.columns(3)

    col1.metric("Technique ID", technique)
    col2.metric("Technique", name)
    col3.metric("Tactic", tactic)

    st.caption(f"ATT&CK Badge: `{technique} | {name} | {tactic}`")
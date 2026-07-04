import json
from pathlib import Path

import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="Detection Engineering Lab",
    page_icon="🛡️",
    layout="wide",
)

ALERTS_FILE = Path("data/alerts.json")

st.title("🛡️ Detection Engineering Lab")
st.caption("Interactive SOC investigation console")

if not ALERTS_FILE.exists():
    st.warning("No alerts found. Run `python src\\main.py` first.")
    st.stop()

alerts = json.loads(ALERTS_FILE.read_text())

if not alerts:
    st.info("No alerts generated.")
    st.stop()


def get_first_finding(alert):
    return alert["findings"][0] if alert.get("findings") else {}


def extract_metadata(alert):
    finding = get_first_finding(alert)
    raw = alert.get("raw_event", {})
    mitre = finding.get("mitre", {})

    return {
        "severity": alert.get("severity", "Unknown"),
        "risk_score": alert.get("risk_score", 0),
        "log_file": alert.get("log_file", "Unknown"),
        "rule": finding.get("rule_title", "Unknown"),
        "matched_value": finding.get("value", "N/A"),
        "mitre_id": mitre.get("technique_id", "N/A"),
        "mitre_name": mitre.get("technique_name", "N/A"),

        "timestamp": raw.get("timestamp", alert.get("timestamp", "Unknown")),
        "hostname": raw.get("hostname", raw.get("host", "Unknown")),
        "user": raw.get("user", raw.get("username", "Unknown")),
        "src_ip": raw.get("src_ip", raw.get("source_ip", "Unknown")),
        "dst_ip": raw.get("dst_ip", raw.get("destination_ip", "Unknown")),
        "process": raw.get("process_name", raw.get("process", "Unknown")),
        "parent_process": raw.get("parent_process", "Unknown"),
        "command_line": raw.get("command_line", "Unknown"),
        "file_hash": raw.get("sha256", raw.get("hash", "Unknown")),
        "file_path": raw.get("file_path", "Unknown"),
    }


rows = []

for index, alert in enumerate(alerts):
    meta = extract_metadata(alert)

    rows.append({
        "ID": index,
        "Severity": meta["severity"],
        "Risk Score": meta["risk_score"],
        "Rule": meta["rule"],
        "MITRE": meta["mitre_id"],
        "Host": meta["hostname"],
        "User": meta["user"],
        "Process": meta["process"],
        "Time": meta["timestamp"],
    })

df = pd.DataFrame(rows)

st.subheader("Alert Queue")

selected_id = st.selectbox(
    "Select an alert to investigate",
    df["ID"],
    format_func=lambda x: f"{df.loc[df['ID'] == x, 'Severity'].values[0]} | {df.loc[df['ID'] == x, 'Rule'].values[0]}"
)

st.dataframe(df, use_container_width=True, hide_index=True)

selected_alert = alerts[selected_id]
meta = extract_metadata(selected_alert)

st.divider()

st.subheader("Investigation View")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Severity", meta["severity"])
col2.metric("Risk Score", meta["risk_score"])
col3.metric("MITRE", meta["mitre_id"])
col4.metric("Source Log", meta["log_file"])

tabs = st.tabs([
    "Summary",
    "Timeline",
    "Host",
    "User",
    "Process",
    "Network",
    "MITRE",
    "Analyst Notes",
    "Raw JSON"
])

with tabs[0]:
    st.markdown("### Alert Summary")

    c1, c2 = st.columns(2)

    with c1:
        st.write("**Rule:**", meta["rule"])
        st.write("**Time:**", meta["timestamp"])
        st.write("**Matched Value:**", meta["matched_value"])
        st.write("**File Path:**", meta["file_path"])

    with c2:
        st.write("**Host:**", meta["hostname"])
        st.write("**User:**", meta["user"])
        st.write("**Process:**", meta["process"])
        st.write("**Parent Process:**", meta["parent_process"])

    st.markdown("### Command Line")
    st.code(meta["command_line"], language="powershell")

with tabs[1]:
    st.markdown("### Investigation Timeline")

    timeline_events = [
        ("Alert generated", meta["timestamp"]),
        (f"Rule matched: {meta['rule']}", meta["timestamp"]),
        (f"Process observed: {meta['process']}", meta["timestamp"]),
        (f"User involved: {meta['user']}", meta["timestamp"]),
        (f"Host involved: {meta['hostname']}", meta["timestamp"]),
    ]

    for event, time in timeline_events:
        st.markdown(f"""
        #### {event}
        `{time}`
        """)

with tabs[2]:
    st.markdown("### Host Profile")

    st.info("This is your SentinelOne-style host pivot.")

    st.write("**Hostname:**", meta["hostname"])
    st.write("**Related User:**", meta["user"])
    st.write("**Open Alerts on Host:**")

    related = df[df["Host"] == meta["hostname"]]
    st.dataframe(related, use_container_width=True, hide_index=True)

with tabs[3]:
    st.markdown("### User Profile")

    st.info("This is your user pivot.")

    st.write("**Username:**", meta["user"])
    st.write("**Current Host:**", meta["hostname"])
    st.write("**Related Alerts for User:**")

    related = df[df["User"] == meta["user"]]
    st.dataframe(related, use_container_width=True, hide_index=True)

with tabs[4]:
    st.markdown("### Process Details")

    st.write("**Process:**", meta["process"])
    st.write("**Parent Process:**", meta["parent_process"])
    st.write("**File Path:**", meta["file_path"])
    st.write("**Hash:**", meta["file_hash"])

    st.markdown("### Command Line")
    st.code(meta["command_line"], language="powershell")

with tabs[5]:
    st.markdown("### Network Details")

    st.write("**Source IP:**", meta["src_ip"])
    st.write("**Destination IP:**", meta["dst_ip"])

    network_rows = []

    if meta["src_ip"] != "Unknown":
        network_rows.append({"Type": "Source IP", "Value": meta["src_ip"]})

    if meta["dst_ip"] != "Unknown":
        network_rows.append({"Type": "Destination IP", "Value": meta["dst_ip"]})

    if network_rows:
        st.dataframe(pd.DataFrame(network_rows), use_container_width=True, hide_index=True)
    else:
        st.warning("No network metadata found for this alert.")

with tabs[6]:
    st.markdown("### MITRE ATT&CK Mapping")

    st.write("**Technique ID:**", meta["mitre_id"])
    st.write("**Technique Name:**", meta["mitre_name"])

    st.markdown("### Why this matters")
    st.write(
        "This section explains what attacker behavior the detection maps to "
        "and helps an analyst understand the alert quickly."
    )

with tabs[7]:
    st.markdown("### Analyst Notes")

    verdict = st.selectbox(
        "Verdict",
        ["Open", "Needs Review", "True Positive", "False Positive", "Benign Authorized Activity"]
    )

    notes = st.text_area(
        "Investigation Notes",
        placeholder="Example: User executed PowerShell with suspicious flags. Need to validate parent process, user intent, and related host activity."
    )

    if st.button("Save Investigation Note"):
        st.success("Note saved locally in this session.")

    st.write("**Selected Verdict:**", verdict)
    st.write("**Notes:**", notes)

with tabs[8]:
    st.markdown("### Raw Alert JSON")
    st.json(selected_alert)
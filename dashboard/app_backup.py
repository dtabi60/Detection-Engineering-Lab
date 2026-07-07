import json
import sqlite3
from pathlib import Path

import pandas as pd
import streamlit as st

ALERT_FILE = Path("data/alerts/detection_alerts.json")
HOST_FILE = Path("data/host_inventory.json")
DB_FILE = Path("data/edr_events.db")

st.set_page_config(page_title="Detection Engineering Lab", layout="wide")


def parse_json_field(value):
    if not value:
        return []
    if isinstance(value, list):
        return value
    try:
        return json.loads(value)
    except Exception:
        return []


def load_process_events():
    if not DB_FILE.exists():
        return pd.DataFrame()

    conn = sqlite3.connect(DB_FILE)

    query = """
    SELECT
        timestamp,
        user,
        host,
        image,
        command_line,
        parent_image,
        parent_command_line,
        process_guid,
        process_id,
        integrity_level,
        hashes
    FROM events
    WHERE event_type = 'process_create'
    ORDER BY id DESC
    LIMIT 500
    """

    df = pd.read_sql_query(query, conn)
    conn.close()
    return df


st.sidebar.title("Detection Lab")
st.sidebar.caption("Threat Hunting Platform")

page = st.sidebar.radio(
    "Navigation",
    ["Overview", "Alerts", "Hosts", "Processes", "Settings"]
)

dark_mode = st.sidebar.toggle("Dark Mode")

if dark_mode:
    st.markdown("""
    <style>
    .stApp { background-color: #0f1720; color: #e5e7eb; }
    section[data-testid="stSidebar"] { background-color: #111827; }
    div[data-testid="stMetric"] {
        background-color: #1f2937;
        padding: 20px;
        border-radius: 14px;
        border: 1px solid #374151;
    }
    </style>
    """, unsafe_allow_html=True)
else:
    st.markdown("""
    <style>
    .stApp { background-color: #f8fafc; }
    section[data-testid="stSidebar"] { background-color: #ffffff; }
    div[data-testid="stMetric"] {
        background-color: #ffffff;
        padding: 20px;
        border-radius: 14px;
        border: 1px solid #e5e7eb;
        box-shadow: 0px 2px 10px rgba(0,0,0,0.04);
    }
    </style>
    """, unsafe_allow_html=True)

st.title("Detection Engineering Lab")
st.caption("Endpoint Detection & Threat Hunting Dashboard")

if ALERT_FILE.exists():
    alerts = json.loads(ALERT_FILE.read_text(encoding="utf-8"))
else:
    alerts = []

df = pd.DataFrame(alerts)

if page == "Overview":
    st.subheader("Overview")

    total = len(df)
    high = int((df["severity"] == "High").sum()) if not df.empty else 0
    medium = int((df["severity"] == "Medium").sum()) if not df.empty else 0
    low = int((df["severity"] == "Low").sum()) if not df.empty else 0

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Unresolved Alerts", total)
    c2.metric("High Severity", high)
    c3.metric("Medium Severity", medium)
    c4.metric("Low Severity", low)

    st.divider()
    st.subheader("Unresolved Detections")

    if df.empty:
        st.success("No alerts generated.")
    else:
        display_cols = ["alert_name", "severity", "risk_score", "user", "host", "mitre_technique"]
        display_cols = [c for c in display_cols if c in df.columns]
        st.dataframe(df[display_cols], use_container_width=True, hide_index=True)

elif page == "Alerts":
    st.subheader("Alert Investigation")

    if df.empty:
        st.warning("No alerts found. Run the pipeline first.")
        st.code("python sensor\\endpoint_sensor.py")
        st.stop()

    alert_choices = [
        f"{i} | {a.get('alert_name')} | {a.get('severity')} | Risk {a.get('risk_score')}"
        for i, a in enumerate(alerts)
    ]

    selected = st.selectbox("Select Alert", alert_choices)
    selected_id = int(selected.split("|")[0].strip())
    alert = alerts[selected_id]

    left, right = st.columns([2, 1])

    with left:
        st.write("### Process Evidence")
        st.write("**Image**")
        st.code(alert.get("image") or "N/A")
        st.write("**Parent Process**")
        st.code(alert.get("parent_image") or "N/A")
        st.write("**Command Line**")
        st.code(alert.get("command_line") or "N/A")

    with right:
        st.metric("Risk Score", alert.get("risk_score"))
        st.write(f"**Severity:** {alert.get('severity')}")
        st.write(f"**User:** {alert.get('user')}")
        st.write(f"**Host:** {alert.get('host')}")
        st.write(f"**MITRE:** {alert.get('mitre_technique')}")

    st.write("### Detection Reasons")
    for reason in alert.get("reasons", []):
        st.write(f"- {reason}")

    st.write("### Analyst Notes")
    st.selectbox(
        "Verdict",
        ["New", "Investigating", "True Positive", "False Positive", "Benign", "Needs More Evidence"]
    )
    st.text_area("Notes")

elif page == "Hosts":
    st.subheader("Host Pivot")

    if not HOST_FILE.exists():
        st.warning("No host inventory found.")
        st.code("python sensor\\host_inventory.py")
        st.stop()

    host = json.loads(HOST_FILE.read_text(encoding="utf-8"))

    hostname = host.get("hostname", "Unknown")
    os_name = host.get("os", "Unknown")

    st.write(f"## {hostname}")

    c1, c2, c3 = st.columns(3)
    c1.metric("Hostname", hostname)
    c2.metric("Operating System", os_name)
    c3.metric("Inventory Status", "Collected")

    st.divider()

    ip_addresses = parse_json_field(host.get("ip_addresses"))
    local_users = parse_json_field(host.get("local_users"))
    listening_ports = parse_json_field(host.get("listening_ports"))

    st.write("### IP Addresses")
    if ip_addresses:
        st.dataframe(pd.DataFrame(ip_addresses), use_container_width=True, hide_index=True)

    st.write("### Local Users")
    if local_users:
        st.dataframe(pd.DataFrame(local_users), use_container_width=True, hide_index=True)

    st.write("### Listening Ports")
    if listening_ports:
        ports_df = pd.DataFrame(listening_ports)
        if "LocalPort" in ports_df.columns:
            ports_df = ports_df.sort_values("LocalPort")
        st.dataframe(ports_df, use_container_width=True, hide_index=True)

    st.divider()
    st.write("### Related Alerts")

    if not df.empty and "host" in df.columns:
        related = df[df["host"] == hostname]
        if related.empty:
            st.info("No alerts linked to this host.")
        else:
            st.dataframe(related, use_container_width=True, hide_index=True)

elif page == "Processes":
    st.subheader("Process Pivot")

    process_df = load_process_events()

    if process_df.empty:
        st.warning("No process events found. Run the endpoint sensor first.")
        st.code("python sensor\\endpoint_sensor.py")
        st.stop()

    st.write("### Recent Process Events")

    search = st.text_input("Search process, parent, user, or command line")

    filtered = process_df.copy()

    if search:
        search_lower = search.lower()
        filtered = filtered[
            filtered.apply(
                lambda row: search_lower in str(row.to_dict()).lower(),
                axis=1
            )
        ]

    display_cols = [
        "timestamp",
        "user",
        "image",
        "parent_image",
        "command_line",
        "process_id"
    ]

    st.dataframe(
        filtered[display_cols],
        use_container_width=True,
        hide_index=True
    )

    st.divider()
    st.write("### Investigate Process")

    process_choices = [
        f"{i} | {row.get('image')} | PID {row.get('process_id')}"
        for i, row in filtered.reset_index(drop=True).iterrows()
    ]

    if not process_choices:
        st.info("No processes match your search.")
        st.stop()

    selected_process = st.selectbox("Select Process", process_choices)
    selected_index = int(selected_process.split("|")[0].strip())
    proc = filtered.reset_index(drop=True).iloc[selected_index].to_dict()

    left, right = st.columns([2, 1])

    with left:
        st.write("### Process Details")

        st.write("**Image**")
        st.code(proc.get("image") or "N/A")

        st.write("**Command Line**")
        st.code(proc.get("command_line") or "N/A")

        st.write("**Parent Image**")
        st.code(proc.get("parent_image") or "N/A")

        st.write("**Parent Command Line**")
        st.code(proc.get("parent_command_line") or "N/A")

    with right:
        st.write("### Metadata")
        st.write(f"**Time:** {proc.get('timestamp')}")
        st.write(f"**User:** {proc.get('user')}")
        st.write(f"**Host:** {proc.get('host')}")
        st.write(f"**Process ID:** {proc.get('process_id')}")
        st.write(f"**Integrity:** {proc.get('integrity_level')}")
        st.write(f"**Process GUID:** {proc.get('process_guid')}")

    st.write("### Hashes")
    st.code(proc.get("hashes") or "No hash data")

    st.write("### Simple Process Lineage")

    st.code(f"""
Parent:
{proc.get("parent_image") or "N/A"}

    └── Child:
        {proc.get("image") or "N/A"}
""")

elif page == "Settings":
    st.subheader("Settings")
    st.write("Dark mode is controlled from the sidebar.")
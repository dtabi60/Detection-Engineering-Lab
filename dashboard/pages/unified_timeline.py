import pandas as pd
import streamlit as st

from dashboard.api_client import get_unified_timeline


def render_unified_timeline_page():
    initialize_unified_timeline_state()

    st.header("🧬 Unified Event Timeline")
    st.caption("Clickable correlated Sysmon + Windows Security + PowerShell telemetry")

    try:
        response = get_unified_timeline()
    except Exception as e:
        st.error(f"Failed to load unified timeline: {e}")
        return

    timeline = response.get("timeline", [])
    detections = response.get("detections", [])

    c1, c2, c3 = st.columns(3)
    c1.metric("Unified Events", response.get("event_count", len(timeline)))
    c2.metric("Detections", response.get("detection_count", len(detections)))
    c3.metric("Selected Event", st.session_state.get("selected_event_id") or "None")

    st.divider()

    left, right = st.columns([2, 1])

    with left:
        render_detection_cards(detections)
        st.divider()
        render_clickable_timeline(timeline)

    with right:
        render_investigation_drawer()


def initialize_unified_timeline_state():
    if "selected_event" not in st.session_state:
        st.session_state.selected_event = None

    if "selected_event_id" not in st.session_state:
        st.session_state.selected_event_id = None


def render_detection_cards(detections):
    st.subheader("🚨 Behavioral Detections")

    if not detections:
        st.info("No behavioral detections found.")
        return

    for detection in detections:
        severity = str(detection.get("severity", "Unknown"))

        with st.container(border=True):
            st.write(f"### {severity_icon(severity)} {detection.get('rule_name', 'Detection')}")
            st.write(f"**Rule ID:** `{detection.get('rule_id', 'Unknown')}`")
            st.write(f"**MITRE:** `{detection.get('mitre_technique', 'Unknown')}`")
            st.write(f"**User:** `{detection.get('actor_user', 'Unknown')}`")
            st.write(f"**Process:** `{detection.get('process_name', 'Unknown')}`")
            st.caption(detection.get("summary", ""))


def render_clickable_timeline(timeline):
    st.subheader("Chronological Timeline")

    if not timeline:
        st.info("No timeline events found.")
        return

    for index, event in enumerate(timeline):
        event_key = build_event_key(event, index)
        selected = st.session_state.selected_event_id == event_key

        border_label = "✅ Selected" if selected else "Open Details"

        with st.container(border=True):
            c1, c2, c3 = st.columns([1, 3, 1])

            with c1:
                st.write(event_icon(event))
                st.caption(event.get("timestamp", "Unknown time"))

            with c2:
                st.write(f"**{event.get('source', 'Unknown')} | {event.get('event_id', 'Unknown')}**")
                st.write(event.get("summary", "No summary available."))
                st.caption(f"Action: {event.get('normalized_action', 'UNKNOWN')}")

            with c3:
                if st.button(border_label, key=f"select_event_{event_key}"):
                    st.session_state.selected_event = event
                    st.session_state.selected_event_id = event_key
                    st.rerun()


def render_investigation_drawer():
    st.subheader("🕵️ Investigation Drawer")

    event = st.session_state.get("selected_event")

    if not event:
        st.info("Click an event in the timeline to inspect it.")
        return

    st.write(f"**Source:** `{event.get('source', 'Unknown')}`")
    st.write(f"**Event ID:** `{event.get('event_id', 'Unknown')}`")
    st.write(f"**Action:** `{event.get('normalized_action', 'UNKNOWN')}`")
    st.write(f"**Timestamp:** `{event.get('timestamp', 'Unknown')}`")

    actor = event.get("actor_user")
    if actor:
        st.write(f"**Actor User:** `{actor}`")

    process_context = event.get("process_context") or {}

    if process_context:
        st.divider()
        st.write("### Process Context")

        for key, value in process_context.items():
            if value:
                st.write(f"**{key.replace('_', ' ').title()}:**")
                if key in ["command_line", "process_name"]:
                    st.code(str(value))
                else:
                    st.write(f"`{value}`")

    raw = event.get("raw_payload") or {}

    if raw:
        st.divider()
        st.write("### Raw Payload")

        script_block = raw.get("script_block_text")
        if script_block:
            st.write("**PowerShell Script Block:**")
            st.code(script_block, language="powershell")

        with st.expander("Full Raw JSON"):
            st.json(raw)


def build_event_key(event, index):
    return (
        f"{index}_"
        f"{event.get('timestamp', '')}_"
        f"{event.get('source', '')}_"
        f"{event.get('event_id', '')}"
    )


def severity_icon(severity):
    severity = severity.lower()

    if severity == "critical":
        return "🚨"
    if severity == "high":
        return "🔴"
    if severity == "medium":
        return "🟠"
    if severity == "low":
        return "🟡"

    return "🔵"


def event_icon(event):
    source = str(event.get("source", "")).lower()
    action = str(event.get("normalized_action", "")).lower()

    if "powershell" in source:
        return "🔵 PowerShell"
    if "winsecurity" in source:
        return "🪟 Security"
    if "network" in action:
        return "🌐 Network"
    if "process" in action:
        return "⚙️ Process"

    return "📄 Event"
import streamlit as st

from dashboard.components.process_tree import render_process_tree
from dashboard.components.storyline_viewer import render_storyline_viewer
from dashboard.api_client import (
    get_alerts,
    get_alert_details,
    get_storyline,
    get_process_tree,
    get_response_actions,
    create_response_action,
    create_ai_summary,
)


def render_alert_workspace_page():
    st.header("Alert Investigation Workspace")
    st.caption("API-driven analyst workspace powered by FastAPI")

    try:
        alert_response = get_alerts()
        alerts = alert_response.get("alerts", [])
    except Exception as e:
        st.error(f"Failed to load alerts from FastAPI: {e}")
        alerts = []

    if not alerts:
        st.warning("No alerts found from API.")
        st.stop()

    alert_options = {
        f"{alert.get('alert_id') or alert.get('id')} | "
        f"{alert.get('host_id') or alert.get('hostname', 'Unknown Host')} | "
        f"{alert.get('severity', 'Unknown')} | "
        f"{alert.get('title') or alert.get('name') or alert.get('alert_name', 'Untitled Alert')}": alert
        for alert in alerts
    }

    selected_label = st.selectbox(
        "Select alert to investigate",
        list(alert_options.keys()),
    )

    selected_alert = alert_options[selected_label]

    alert_id = selected_alert.get("alert_id") or selected_alert.get("id")
    storyline_id = selected_alert.get("storyline_id")
    process_guid = selected_alert.get("process_guid") or storyline_id
    host_id = (
        selected_alert.get("host_id")
        or selected_alert.get("hostname")
        or selected_alert.get("endpoint_id")
        or "unknown-host"
    )

    if not alert_id:
        st.error("Cannot investigate this alert because alert_id is missing.")
        st.stop()

    with st.spinner("Loading investigation context from FastAPI..."):
        try:
            alert_details = get_alert_details(str(alert_id))
        except Exception as e:
            alert_details = None
            st.warning(f"Alert details unavailable: {e}")

        try:
            storyline = get_storyline(str(storyline_id)) if storyline_id else None
        except Exception as e:
            storyline = None
            st.warning(f"Storyline unavailable: {e}")

        try:
            process_tree = get_process_tree(str(process_guid)) if process_guid else None
        except Exception as e:
            process_tree = None
            st.warning(f"Process tree unavailable: {e}")

        try:
            response_actions = get_response_actions(str(alert_id))
        except Exception as e:
            response_actions = None
            st.warning(f"Response actions unavailable: {e}")

    st.divider()

    st.subheader("Selected Alert")

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Alert ID", str(alert_id))
    c2.metric("Severity", selected_alert.get("severity", "Unknown"))
    c3.metric("Host", str(host_id))
    c4.metric("Storyline", str(storyline_id or "Unknown"))

    st.write(
        "**Alert Name:** "
        f"{selected_alert.get('title') or selected_alert.get('name') or selected_alert.get('alert_name', 'Untitled Alert')}"
    )

    st.divider()

    tab1, tab2, tab3, tab4, tab5 = st.tabs(
        [
            "Alert Details",
            "Storyline",
            "Process Tree",
            "Response Actions Hub",
            "Raw Alert",
        ]
    )

    with tab1:
        st.subheader("Alert Details")

        st.subheader("🤖 AI Investigation Summary")

        try:
            ai_summary = create_ai_summary(selected_alert)

            st.info(ai_summary.get("analyst_summary", "No summary returned."))
            st.caption(f"Confidence: {ai_summary.get('confidence', 'unknown')}")
        except Exception as e:
            st.warning(f"AI summary unavailable: {e}")

        st.divider()

        st.subheader("Raw Alert Details")

        if alert_details:
            st.json(alert_details)
        else:
            st.info("No alert details available.")
    with tab2:
        render_storyline_viewer(storyline)

        
    with tab3:
        render_process_tree(process_tree)

    with tab4:
        st.subheader("Response Actions Hub")

        if not host_id:
            host_id = "unknown-host"

        if not process_guid:
            process_guid = host_id

        col1, col2, col3, col4, col5 = st.columns(5)

        with col1:
            isolate_clicked = st.button("Isolate Host")

        with col2:
            kill_clicked = st.button("Kill Process")

        with col3:
            quarantine_clicked = st.button("Quarantine File")

        with col4:
            disconnect_clicked = st.button("Disconnect Network")

        with col5:
            forensic_clicked = st.button("Collect Forensics")

        def run_response_action(action_type: str, target_identifier: str):
            try:
                result = create_response_action(
                    host_id=str(host_id),
                    alert_id=str(alert_id),
                    action_type=action_type,
                    target_identifier=str(target_identifier or host_id),
                )
                st.success(f"{action_type} action logged successfully.")
                st.json(result)
            except Exception as e:
                st.error(f"Failed to log {action_type}: {e}")

        if isolate_clicked:
            run_response_action("Isolate Host", host_id)

        if kill_clicked:
            run_response_action("Kill Process", process_guid)

        if quarantine_clicked:
            run_response_action(
                "Quarantine File",
                selected_alert.get("file_path") or "unknown_file",
            )

        if disconnect_clicked:
            run_response_action("Disconnect Network", host_id)

        if forensic_clicked:
            run_response_action("Collect Forensic Package", host_id)

        st.divider()

        st.subheader("Response Action Audit History")

        if response_actions:
            st.json(response_actions)
        else:
            st.info("No response actions have been recorded yet.")

    with tab5:
        st.subheader("Raw Alert Payload")
        st.json(selected_alert)
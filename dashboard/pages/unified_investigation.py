import streamlit as st

from dashboard.api_client import get_unified_investigation


def render_unified_investigation_page():
    st.header("🕵️ Unified Investigation")
    st.caption("Single-pane investigation powered by FastAPI")

    alert_id = st.text_input(
        "Alert ID",
        placeholder="Enter Alert ID (example: 1)",
    )

    if not alert_id:
        st.info("Enter an Alert ID to begin.")
        return

    try:
        investigation = get_unified_investigation(alert_id)
    except Exception as e:
        st.error(f"Failed to load investigation: {e}")
        return

    alert = investigation.get("alert", {})
    processes = investigation.get("processes", [])
    network = investigation.get("network_connections", [])
    files = investigation.get("file_events", [])
    actions = investigation.get("response_actions", [])

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Processes", len(processes))
    c2.metric("Network", len(network))
    c3.metric("Files", len(files))
    c4.metric("Response Actions", len(actions))

    st.divider()

    tab1, tab2, tab3, tab4, tab5 = st.tabs(
        [
            "Alert",
            "Processes",
            "Network",
            "Files",
            "Response Actions",
        ]
    )

    with tab1:
        st.json(alert)

    with tab2:
        if processes:
            st.dataframe(processes, use_container_width=True)
        else:
            st.info("No process activity.")

    with tab3:
        if network:
            st.dataframe(network, use_container_width=True)
        else:
            st.info("No network activity.")

    with tab4:
        if files:
            st.dataframe(files, use_container_width=True)
        else:
            st.info("No file activity.")

    with tab5:
        if actions:
            st.dataframe(actions, use_container_width=True)
        else:
            st.info("No response actions.")
import sqlite3

import plotly.express as px
import pandas as pd
import streamlit as st
from dashboard.pages.timeline import render_timeline_page
from dashboard.api_client import (

    get_alerts,
    get_alert_details,
    get_storyline,
    get_process_tree,
    get_response_actions,
    create_response_action,
    
)


DB_PATH = "storage/entities.db"


st.set_page_config(
    page_title="Detection Engineering Lab",
    page_icon="🛡️",
    layout="wide",
)


def query_db(query, params=()):
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query(query, conn, params=params)
    conn.close()
    return df


def get_metric_count(table):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(f"SELECT COUNT(*) FROM {table}")
    count = cursor.fetchone()[0]
    conn.close()
    return count


st.title("🛡️ Detection Engineering Lab")
st.caption("Version 2.2 - API Driven Investigation Workspace")


page = st.sidebar.radio(
    "Navigation",
    [
        "Dashboard",
        "Endpoints",
        "Alerts",
        "Investigation",
        "Alert Workspace",
        "Timeline",
    ],
)


if page == "Dashboard":
    st.header("Security Overview")

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Endpoints", get_metric_count("endpoints"))
    c2.metric("Processes", get_metric_count("processes"))
    c3.metric("Network Events", get_metric_count("network_connections"))
    c4.metric("Alerts", get_metric_count("alerts"))

    st.subheader("Recent Alerts")

    alerts_df = query_db("""
        SELECT 
            a.id,
            e.hostname,
            a.alert_name,
            a.severity,
            a.mitre_technique,
            a.ai_confidence,
            a.timestamp,
            a.status
        FROM alerts a
        LEFT JOIN endpoints e ON a.endpoint_id = e.id
        ORDER BY a.timestamp DESC
        LIMIT 10
    """)

    st.dataframe(alerts_df, use_container_width=True)


elif page == "Endpoints":
    st.header("Endpoints")

    endpoints_df = query_db("""
        SELECT 
            id,
            hostname,
            ip_address,
            os,
            first_seen,
            last_seen
        FROM endpoints
        ORDER BY last_seen DESC
    """)

    st.dataframe(endpoints_df, use_container_width=True)
    st.info("Use the endpoint ID on the Investigation page to open a host investigation.")


elif page == "Alerts":
    st.header("Alerts")

    alerts_df = query_db("""
        SELECT 
            a.id,
            e.hostname,
            a.alert_name,
            a.severity,
            a.mitre_technique,
            a.description,
            a.ai_summary,
            a.analyst_verdict,
            a.recommended_actions,
            a.ai_confidence,
            a.timestamp,
            a.status
        FROM alerts a
        LEFT JOIN endpoints e ON a.endpoint_id = e.id
        ORDER BY a.timestamp DESC
    """)

    severity_filter = st.selectbox(
        "Filter by severity",
        ["All", "High", "Medium", "Low"],
    )

    if severity_filter != "All":
        alerts_df = alerts_df[alerts_df["severity"] == severity_filter]

    st.dataframe(alerts_df, use_container_width=True)


elif page == "Investigation":
    st.header("Endpoint Investigation")

    endpoints_df = query_db("""
        SELECT id, hostname
        FROM endpoints
        ORDER BY last_seen DESC
    """)

    if endpoints_df.empty:
        st.warning("No endpoints found.")
    else:
        endpoint_options = {
            f"{row['id']} - {row['hostname']}": row["id"]
            for _, row in endpoints_df.iterrows()
        }

        selected = st.selectbox(
            "Select endpoint",
            list(endpoint_options.keys()),
        )

        endpoint_id = endpoint_options[selected]

        endpoint_df = query_db("""
            SELECT 
                id,
                hostname,
                ip_address,
                os,
                first_seen,
                last_seen
            FROM endpoints
            WHERE id = ?
        """, (endpoint_id,))

        endpoint = endpoint_df.iloc[0]

        st.subheader(f"Host: {endpoint['hostname']}")

        c1, c2, c3 = st.columns(3)

        c1.metric("Endpoint ID", endpoint["id"])
        c2.metric("IP Address", endpoint["ip_address"] or "Unknown")
        c3.metric("OS", endpoint["os"] or "Unknown")

        st.write(f"**First Seen:** {endpoint['first_seen']}")
        st.write(f"**Last Seen:** {endpoint['last_seen']}")

        tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(
            [
                "Alerts + AI",
                "Processes",
                "Process Tree",
                "Storyline",
                "Network",
                "Files",
            ]
        )

        with tab1:
            st.subheader("Alerts with AI Enrichment")

            alerts_df = query_db("""
                SELECT 
                    alert_name,
                    severity,
                    mitre_technique,
                    description,
                    ai_summary,
                    analyst_verdict,
                    recommended_actions,
                    ai_confidence,
                    timestamp,
                    status
                FROM alerts
                WHERE endpoint_id = ?
                ORDER BY timestamp DESC
            """, (endpoint_id,))

            if alerts_df.empty:
                st.info("No alerts found for this endpoint.")
            else:
                for _, alert in alerts_df.iterrows():
                    with st.expander(f"{alert['severity']} | {alert['alert_name']}"):
                        st.write(f"**MITRE:** {alert['mitre_technique']}")
                        st.write(f"**Status:** {alert['status']}")
                        st.write(f"**Timestamp:** {alert['timestamp']}")
                        st.write(f"**Description:** {alert['description']}")

                        st.divider()

                        st.write("### AI Summary")
                        st.write(alert["ai_summary"] or "No AI summary available.")

                        st.write("### Analyst Verdict")
                        st.write(alert["analyst_verdict"] or "No verdict available.")

                        st.write("### Recommended Actions")
                        st.write(alert["recommended_actions"] or "No recommended actions available.")

                        st.write("### AI Confidence")
                        st.write(alert["ai_confidence"] or "Unknown")

        with tab2:
            st.subheader("Processes")

            processes_df = query_db("""
                SELECT 
                    process_name,
                    process_id,
                    parent_process_id,
                    user,
                    command_line,
                    timestamp
                FROM processes
                WHERE endpoint_id = ?
                ORDER BY timestamp DESC
            """, (endpoint_id,))

            st.dataframe(processes_df, use_container_width=True)

        with tab3:
            st.subheader("Process Tree")
            st.info("API-driven process tree is available in Alert Workspace.")

        with tab4:
            st.subheader("Attack Storyline")
            st.info("API-driven storyline is available in Alert Workspace.")

        with tab5:
            st.subheader("Network Connections")

            network_df = query_db("""
                SELECT 
                    process_id,
                    destination_ip,
                    destination_port,
                    protocol,
                    timestamp
                FROM network_connections
                WHERE endpoint_id = ?
                ORDER BY timestamp DESC
            """, (endpoint_id,))

            st.dataframe(network_df, use_container_width=True)

        with tab6:
            st.subheader("File Events")

            files_df = query_db("""
                SELECT 
                    process_id,
                    file_path,
                    file_hash,
                    action,
                    timestamp
                FROM file_events
                WHERE endpoint_id = ?
                ORDER BY timestamp DESC
            """, (endpoint_id,))

            st.dataframe(files_df, use_container_width=True)


elif page == "Alert Workspace":
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

        if alert_details:
            st.json(alert_details)
        else:
            st.info("No alert details available.")

    with tab2:
        st.subheader("Storyline Timeline")

        if storyline:
            st.json(storyline)
        else:
            st.info("No storyline available for this alert.")

    with tab3:
        st.subheader("Process Tree")

        if process_tree:
            st.json(process_tree)
        else:
            st.info("No process tree available for this alert.")

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


elif page == "Timeline":
    render_timeline_page()
    
    
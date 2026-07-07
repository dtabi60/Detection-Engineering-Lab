import sqlite3

import pandas as pd
import streamlit as st

from dashboard.pages.timeline import render_timeline_page
from dashboard.pages.alert_workspace import render_alert_workspace_page


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
    render_alert_workspace_page()


elif page == "Timeline":
    render_timeline_page()
    
    
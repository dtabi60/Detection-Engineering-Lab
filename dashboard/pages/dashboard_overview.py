import streamlit as st


def render_dashboard_page(query_db, get_metric_count):
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
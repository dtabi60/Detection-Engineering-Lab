import sqlite3

import pandas as pd
import streamlit as st


DB_PATH = "storage/entities.db"


def render_defender_page():
    st.header("🛡️ Microsoft Defender Events")
    st.caption("Defender detections, remediation events, and configuration changes")

    conn = sqlite3.connect(DB_PATH)

    df = pd.read_sql_query(
        """
        SELECT
            id,
            timestamp,
            event_id,
            event_type,
            severity,
            hostname,
            provider,
            message
        FROM defender_events
        ORDER BY id DESC
        """,
        conn,
    )

    conn.close()

    st.metric("Defender Events", len(df))

    severity = st.selectbox("Severity", ["All", "high", "medium", "low"])

    if severity != "All":
        df = df[df["severity"].fillna("").str.lower() == severity]

    st.dataframe(df, use_container_width=True, hide_index=True)
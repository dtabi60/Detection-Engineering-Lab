import sqlite3

import pandas as pd
import streamlit as st


DB_PATH = "storage/entities.db"


def render_windows_security_page():
    st.header("🪟 Windows Security Events")
    st.caption("Real Windows Security logs collected from your machine")

    try:
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
            FROM windows_security_events
            ORDER BY id DESC
            """,
            conn,
        )

        conn.close()

    except Exception as e:
        st.error(f"Failed to load Windows Security events: {e}")
        return

    st.write(f"Rows loaded from database: **{len(df)}**")

    if df.empty:
        st.warning("No Windows Security events found.")
        return

    severity = st.selectbox(
        "Severity",
        ["All", "high", "medium", "low"],
    )

    if severity != "All":
        df = df[df["severity"].fillna("").str.lower() == severity.lower()]

    st.metric("Displayed Events", len(df))

    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
    )
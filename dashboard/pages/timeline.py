import pandas as pd
import plotly.express as px
import streamlit as st

from dashboard.api_client import get_timeline


def render_timeline_page():
    st.header("📈 Interactive Timeline")
    st.caption("API-driven event timeline powered by FastAPI + Plotly")

    col1, col2, col3 = st.columns(3)

    with col1:
        start_time = st.text_input(
            "Start Time",
            placeholder="2026-07-06T00:00:00Z",
        )

    with col2:
        end_time = st.text_input(
            "End Time",
            placeholder="2026-07-06T23:59:59Z",
        )

    with col3:
        timeline_host_id = st.text_input(
            "Host ID",
            placeholder="Optional host filter",
        )

    bucket_minutes = st.slider(
        "Bucket Size (minutes)",
        min_value=1,
        max_value=60,
        value=5,
        step=1,
    )

    try:
        response = get_timeline(
            start_time=start_time or None,
            end_time=end_time or None,
            host_id=timeline_host_id or None,
            bucket_minutes=bucket_minutes,
        )

        timeline = response.get("timeline", [])

        st.metric("Timeline Buckets", response.get("bucket_count", 0))

        if not timeline:
            st.info("No timeline data available.")
            return

        timeline_df = pd.DataFrame(timeline)

        st.subheader("Event Histogram")

        fig = px.bar(
            timeline_df,
            x="bucket_start",
            y="event_count",
            color="highest_severity",
            hover_data=[
                "bucket_end",
                "event_count",
                "highest_severity",
            ],
            title="Security Events Over Time",
        )

        fig.update_layout(
            xaxis_title="Time",
            yaxis_title="Number of Events",
            legend_title="Highest Severity",
            height=500,
        )

        st.plotly_chart(fig, use_container_width=True)

        st.divider()

        st.subheader("Timeline Buckets")
        st.dataframe(timeline_df, use_container_width=True)

        st.divider()

        st.subheader("Timeline Details")

        for bucket in timeline:
            with st.expander(
                f"{bucket.get('bucket_start')} | "
                f"{bucket.get('event_count')} Events | "
                f"Severity: {bucket.get('highest_severity')}"
            ):
                events = bucket.get("events", [])

                if events:
                    st.dataframe(
                        pd.DataFrame(events),
                        use_container_width=True,
                    )
                else:
                    st.info("No events recorded.")

    except Exception as e:
        st.error(f"Timeline API error: {e}")
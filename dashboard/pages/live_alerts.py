import streamlit as st
from streamlit_autorefresh import st_autorefresh

from dashboard.api_client import get_alerts


def render_live_alerts_page():
    st.header("🔴 Live Alerts")
    st.caption("Auto-refreshing alert feed powered by FastAPI")

    refresh_count = st_autorefresh(
        interval=10000,
        key="live_alerts_refresh",
    )

    st.sidebar.success("Live Alerts refresh every 10 seconds")
    st.caption(f"Refresh count: {refresh_count}")

    try:
        response = get_alerts()
        alerts = response.get("alerts", [])
    except Exception as e:
        st.error(f"Failed to load live alerts: {e}")
        return

    if not alerts:
        st.info("No alerts available.")
        return

    st.metric("Total Alerts", len(alerts))

    severity_filter = st.selectbox(
        "Severity Filter",
        ["All", "Critical", "High", "Medium", "Low", "Informational"],
    )

    if severity_filter != "All":
        alerts = [
            alert for alert in alerts
            if str(alert.get("severity", "")).lower() == severity_filter.lower()
        ]

    sorted_alerts = sorted(
        alerts,
        key=lambda alert: str(alert.get("timestamp", "")),
        reverse=True,
    )

    for alert in sorted_alerts:
        severity = str(alert.get("severity", "Unknown"))
        alert_id = alert.get("alert_id") or alert.get("id") or "Unknown"
        title = (
            alert.get("title")
            or alert.get("name")
            or alert.get("alert_name")
            or "Untitled Alert"
        )
        host = alert.get("host_id") or alert.get("hostname") or "Unknown Host"
        timestamp = alert.get("timestamp", "Unknown Time")

        with st.container(border=True):
            st.write(f"### {severity_icon(severity)} {title}")
            st.write(f"**Alert ID:** `{alert_id}`")
            st.write(f"**Host:** `{host}`")
            st.write(f"**Severity:** `{severity}`")
            st.write(f"**Timestamp:** `{timestamp}`")

            with st.expander("Raw Alert"):
                st.json(alert)


def severity_icon(severity: str) -> str:
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
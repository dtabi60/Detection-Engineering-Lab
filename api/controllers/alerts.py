from typing import Any, Dict, Optional

from fastapi import HTTPException

from storage.investigation import get_all_alerts, get_alert_investigation


class AlertController:
    """
    Handles alert business logic.

    Flow:
    Router -> AlertController -> storage.investigation
    """

    def list_alerts(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        severity: Optional[str] = None,
        host_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        try:
            alerts = get_all_alerts()
        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to retrieve alerts: {exc}",
            )

        if start_time:
            alerts = [a for a in alerts if str(a.get("timestamp", "")) >= start_time]

        if end_time:
            alerts = [a for a in alerts if str(a.get("timestamp", "")) <= end_time]

        if severity:
            alerts = [
                a for a in alerts
                if str(a.get("severity", "")).lower() == severity.lower()
            ]

        if host_id:
            alerts = [
                a for a in alerts
                if str(a.get("host_id", "")).lower() == host_id.lower()
            ]

        return {
            "count": len(alerts),
            "filters": {
                "start_time": start_time,
                "end_time": end_time,
                "severity": severity,
                "host_id": host_id,
            },
            "alerts": alerts,
        }

    def get_alert(self, alert_id: str) -> Dict[str, Any]:
        try:
            investigation = get_alert_investigation(alert_id)
        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to retrieve alert investigation: {exc}",
            )

        if not investigation:
            raise HTTPException(
                status_code=404,
                detail=f"Alert {alert_id} not found",
            )

        return {
            "alert_id": alert_id,
            "investigation": investigation,
        }
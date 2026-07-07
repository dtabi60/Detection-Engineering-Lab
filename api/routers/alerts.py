from typing import Optional

from fastapi import APIRouter, Depends, Query

from api.controllers.alerts import AlertController


router = APIRouter(
    prefix="/api/v1/alerts",
    tags=["alerts"],
)


def get_alert_controller() -> AlertController:
    return AlertController()


@router.get("/")
def list_alerts(
    start_time: Optional[str] = Query(default=None),
    end_time: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    host_id: Optional[str] = Query(default=None),
    controller: AlertController = Depends(get_alert_controller),
):
    return controller.list_alerts(
        start_time=start_time,
        end_time=end_time,
        severity=severity,
        host_id=host_id,
    )


@router.get("/{alert_id}")
def get_alert(
    alert_id: str,
    controller: AlertController = Depends(get_alert_controller),
):
    return controller.get_alert(alert_id)
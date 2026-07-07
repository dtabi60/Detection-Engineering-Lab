from datetime import datetime, timezone
from typing import Any, Dict
from uuid import uuid4

from fastapi import HTTPException

from api.schemas import ResponseActionRequest
from storage.response_actions import log_response_action, get_response_actions


class ResponseActionController:
    """
    Handles response action business logic.

    Flow:
    Router -> Controller -> Storage Layer
    """

    def create_action(self, request: ResponseActionRequest) -> Dict[str, Any]:
        tracking_id = str(uuid4())

        action_record = {
            "tracking_id": tracking_id,
            "host_id": request.host_id,
            "alert_id": request.alert_id,
            "action_type": request.action_type.value,
            "target_identifier": request.target_identifier,
            "status": "queued",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        try:
            log_response_action(action_record)
        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to log response action: {exc}",
            )

        return {
            "message": "Response action logged successfully",
            "tracking_id": tracking_id,
            "status": "queued",
            "action": action_record,
        }

    def get_actions_for_alert(self, alert_id: str) -> Dict[str, Any]:
        try:
            actions = get_response_actions(alert_id)
        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to retrieve response actions: {exc}",
            )

        return {
            "alert_id": alert_id,
            "count": len(actions) if actions else 0,
            "actions": actions or [],
        }
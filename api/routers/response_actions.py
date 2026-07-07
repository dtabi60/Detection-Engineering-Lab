from fastapi import APIRouter, Depends

from api.schemas import ResponseActionRequest, ResponseActionResponse
from api.controllers.response_actions import ResponseActionController


router = APIRouter(
    prefix="/api/v1/response-actions",
    tags=["response-actions"],
)


def get_response_action_controller() -> ResponseActionController:
    return ResponseActionController()


@router.post("/", response_model=ResponseActionResponse, status_code=201)
def create_response_action(
    request: ResponseActionRequest,
    controller: ResponseActionController = Depends(get_response_action_controller),
):
    return controller.create_action(request)


@router.get("/{alert_id}")
def read_response_actions(
    alert_id: str,
    controller: ResponseActionController = Depends(get_response_action_controller),
):
    return controller.get_actions_for_alert(alert_id)
from fastapi import APIRouter

from api.schemas import AlertSummaryRequest, AlertSummaryResponse
from api.services.ai_summary import generate_ai_alert_summary


router = APIRouter(
    prefix="/api/v1/ai-summary",
    tags=["ai-summary"],
)


@router.post("/", response_model=AlertSummaryResponse)
def create_ai_alert_summary(payload: AlertSummaryRequest):
    result = generate_ai_alert_summary(payload.alert)

    return AlertSummaryResponse(
        analyst_summary=result["analyst_summary"],
        confidence=result["confidence"],
    )
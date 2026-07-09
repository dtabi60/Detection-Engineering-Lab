from fastapi import APIRouter

from api.services.correlation_engine import build_unified_timeline


router = APIRouter(
    prefix="/api/v1/unified-timeline",
    tags=["unified-timeline"],
)


@router.get("/")
def get_unified_timeline():
    return build_unified_timeline()
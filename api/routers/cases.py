from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from storage.case_management import ensure_case_columns, get_case_details, update_case


router = APIRouter(
    prefix="/api/v1/cases",
    tags=["cases"]
)


class CaseUpdateRequest(BaseModel):
    status: Optional[str] = None
    assignee: Optional[str] = None
    notes: Optional[str] = None
    priority: Optional[str] = None


@router.get("/{case_id}")
def read_case(case_id: str):
    ensure_case_columns()

    case = get_case_details(case_id)

    if not case:
        raise HTTPException(
            status_code=404,
            detail=f"Case {case_id} not found"
        )

    return {
        "case_id": case_id,
        "case": case
    }


@router.patch("/{case_id}")
def patch_case(case_id: str, request: CaseUpdateRequest):
    ensure_case_columns()

    updates = request.model_dump(exclude_none=True)

    if not updates:
        raise HTTPException(
            status_code=400,
            detail="No updates provided"
        )

    updated_case = update_case(case_id, updates)

    if not updated_case:
        raise HTTPException(
            status_code=404,
            detail=f"Case {case_id} not found"
        )

    return {
        "message": "Case updated successfully",
        "case_id": case_id,
        "updates": updates,
        "case": updated_case
    }
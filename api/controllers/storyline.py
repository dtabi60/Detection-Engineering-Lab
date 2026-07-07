from typing import Any, Dict

from fastapi import HTTPException

from storage.storyline import get_storyline


class StorylineController:
    """
    Handles storyline retrieval.

    Flow:
    Router -> StorylineController -> storage.storyline
    """

    def get_storyline_by_id(self, storyline_id: str) -> Dict[str, Any]:
        try:
            storyline = get_storyline(storyline_id)
        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to retrieve storyline: {exc}",
            )

        if not storyline:
            raise HTTPException(
                status_code=404,
                detail=f"Storyline {storyline_id} not found",
            )

        return {
            "storyline_id": storyline_id,
            "storyline": storyline,
        }
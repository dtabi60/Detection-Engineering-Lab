from fastapi import APIRouter, Depends

from api.controllers.storyline import StorylineController


router = APIRouter(
    prefix="/api/v1/storylines",
    tags=["storylines"],
)


def get_storyline_controller() -> StorylineController:
    return StorylineController()


@router.get("/{storyline_id}")
def read_storyline(
    storyline_id: str,
    controller: StorylineController = Depends(get_storyline_controller),
):
    return controller.get_storyline_by_id(storyline_id)

from fastapi import APIRouter, Depends

from api.controllers.process_tree import ProcessTreeController


router = APIRouter(
    prefix="/api/v1/process-tree",
    tags=["process-tree"],
)


def get_process_tree_controller() -> ProcessTreeController:
    return ProcessTreeController()


@router.get("/{process_guid}")
def read_process_tree(
    process_guid: str,
    controller: ProcessTreeController = Depends(get_process_tree_controller),
):
    return controller.get_process_tree(process_guid)
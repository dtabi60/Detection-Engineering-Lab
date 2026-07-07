from typing import Any, Dict

from fastapi import HTTPException

from storage.process_tree import render_process_tree


class ProcessTreeController:
    """
    Handles process tree rendering.

    Flow:
    Router -> ProcessTreeController -> storage.process_tree
    """

    def get_process_tree(self, process_guid: str) -> Dict[str, Any]:
        try:
            tree = render_process_tree(process_guid)
        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to render process tree: {exc}",
            )

        if not tree:
            raise HTTPException(
                status_code=404,
                detail=f"Process tree for {process_guid} not found",
            )

        return {
            "process_guid": process_guid,
            "process_tree": tree,
        }
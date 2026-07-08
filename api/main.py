from fastapi import FastAPI

from api.routers.alerts import router as alerts_router
from api.routers.storyline import router as storyline_router
from api.routers.process_tree import router as process_tree_router
from api.routers.cases import router as cases_router
from api.routers.response_actions import router as response_actions_router
from api.routers.timeline import router as timeline_router
from api.routers.entities import router as entities_router
from api.routers.network_graph import router as network_graph_router
from api.routers.entity_pivot import router as entity_pivot_router



app = FastAPI(
    title="Detection Engineering Lab API",
    version="1.0.0",
    description=(
        "FastAPI backend for alerts, investigations, process trees, "
        "storylines, case management, response actions, timeline analysis, "
        "and entity pivoting."
    ),
)


# ============================
# API Routers
# ============================

app.include_router(alerts_router)
app.include_router(storyline_router)
app.include_router(process_tree_router)
app.include_router(cases_router)
app.include_router(response_actions_router)
app.include_router(timeline_router)
app.include_router(entities_router)

app.include_router(network_graph_router)
app.include_router(entity_pivot_router)


# ============================
# Root Endpoint
# ============================

@app.get("/", tags=["System"])
def root():
    return {
        "application": "Detection Engineering Lab",
        "version": "1.0.0",
        "status": "running",
        "message": "FastAPI backend is operational."
    }


# ============================
# Health Check
# ============================

@app.get("/health", tags=["System"])
def health_check():
    return {
        "status": "healthy",
        "service": "Detection Engineering Lab API"
    }


# ============================
# API Information
# ============================

@app.get("/api/v1", tags=["System"])
def api_info():
    return {
        "name": "Detection Engineering Lab API",
        "version": "1.0.0",
        "modules": [
            "Alerts",
            "Storylines",
            "Process Trees",
            "Cases",
            "Response Actions",
            "Timeline",
            "Entities"
        ]
    }
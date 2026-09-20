from fastapi import APIRouter
from backend.app.core.config import settings

router = APIRouter()

@router.get("/health")
def health_check():
    """Health check endpoint confirming API status and system environment."""
    return {
        "status": "healthy",
        "project": settings.PROJECT_NAME,
        "environment": settings.ENV,
        "demo_mode_default": settings.DEMO_MODE,
        "scoring_version": settings.DEFAULT_SCORING_VERSION
    }

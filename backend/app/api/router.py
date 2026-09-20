from fastapi import APIRouter
from backend.app.api.endpoints import health, analyze, repository

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router, tags=["Health"])
api_router.include_router(analyze.router, tags=["Risk Analysis"])
api_router.include_router(repository.router, tags=["Repositories"])

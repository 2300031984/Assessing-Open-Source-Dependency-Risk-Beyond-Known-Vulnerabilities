import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.database.session import init_db
from backend.app.api.router import api_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Application startup
    logger.info(f"Starting {settings.PROJECT_NAME} backend...")
    logger.info("Initializing database schemas...")
    init_db()
    logger.info("Database initialized successfully.")
    yield
    # Application shutdown
    logger.info("Shutting down backend service.")

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="CP1 Review-2 Prototype API for assessing open-source dependency risk beyond known vulnerabilities.",
    version="0.1.0",
    lifespan=lifespan
)

# Enable CORS with explicit origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(api_router)

@app.get("/", tags=["System"])
def root():
    """Root entrypoint providing service status and documentation link."""
    return {
        "project": settings.PROJECT_NAME,
        "status": "operational",
        "docs_url": "/docs",
        "health_check": "/api/v1/health",
        "version": "0.1.0"
    }

if __name__ == "__main__":
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)


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

# Enable CORS for local Streamlit / Frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)

if __name__ == "__main__":
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)

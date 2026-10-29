import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from project root if present
BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
dotenv_path = BASE_DIR / ".env"
if dotenv_path.exists():
    load_dotenv(dotenv_path)

class Settings:
    PROJECT_NAME: str = os.getenv("PROJECT_NAME", "CYBER-100: Assessing Open Source Dependency Risk Beyond Known Vulnerabilities")
    ENV: str = os.getenv("ENV", "development")
    DEBUG: bool = os.getenv("DEBUG", "True").lower() == "true"
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./risk_assessment.db")
    GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")
    DEMO_MODE: bool = os.getenv("DEMO_MODE", "False").lower() == "true"
    DEFAULT_SCORING_VERSION: str = os.getenv("DEFAULT_SCORING_VERSION", "v0.1")
    DEFAULT_FEATURE_VERSION: str = os.getenv("DEFAULT_FEATURE_VERSION", "v0.1")
    API_TIMEOUT_SECONDS: int = int(os.getenv("API_TIMEOUT_SECONDS", "10"))
    ALLOWED_ORIGINS: list[str] = [
        origin.strip()
        for origin in os.getenv(
            "ALLOWED_ORIGINS",
            "http://localhost:8501,http://127.0.0.1:8501,http://localhost:3000,http://localhost:8000,http://localhost:8001"
        ).split(",")
        if origin.strip()
    ]

settings = Settings()


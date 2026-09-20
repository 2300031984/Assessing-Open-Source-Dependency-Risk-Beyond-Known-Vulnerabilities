from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.app.api.deps import get_database
from backend.app.schemas.analysis import AnalyzeRequest, AnalysisResponse
from backend.app.services.analysis_service import AnalysisService

router = APIRouter()

@router.post("/analyze", response_model=AnalysisResponse, status_code=status.HTTP_200_OK)
def analyze_repository(
    payload: AnalyzeRequest,
    db: Session = Depends(get_database)
):
    """
    Analyze a GitHub repository to assess composite open-source dependency risk.
    Collects repository metadata, activity, maintainer concentration, releases, and known vulnerability signals.
    """
    if not payload.repository_url or not payload.repository_url.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Repository URL must be provided."
        )
    
    if "github.com" not in payload.repository_url and not payload.use_demo_fixture:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only GitHub repository URLs (https://github.com/owner/repo) are currently supported."
        )

    try:
        service = AnalysisService(db)
        result = service.analyze_repository(
            repository_url=payload.repository_url.strip(),
            use_demo_fixture=payload.use_demo_fixture
        )
        return result
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(ve)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An unexpected error occurred during risk assessment: {str(e)}"
        )

@router.get("/analysis/{analysis_id}", response_model=AnalysisResponse)
def get_analysis(
    analysis_id: str,
    db: Session = Depends(get_database)
):
    """Retrieve a stored reproducible risk analysis record by Analysis ID."""
    service = AnalysisService(db)
    result = service.get_analysis_by_id(analysis_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis ID '{analysis_id}' not found."
        )
    return result

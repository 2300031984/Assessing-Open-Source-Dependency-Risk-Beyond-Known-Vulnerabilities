from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.app.api.deps import get_database
from backend.app.models.domain import Repository
from backend.app.schemas.analysis import AnalysisResponse
from backend.app.services.analysis_service import AnalysisService

router = APIRouter()

@router.get("/repository/{owner}/{repo}", response_model=AnalysisResponse)
def get_repository_latest_analysis(
    owner: str,
    repo: str,
    db: Session = Depends(get_database)
):
    """Retrieve the latest risk assessment record for a specific repository by owner and repo name."""
    repo_url = f"https://github.com/{owner}/{repo}"
    repo_record = db.query(Repository).filter(Repository.url.ilike(f"%{owner}/{repo}%")).first()
    
    if not repo_record or not repo_record.assessments:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No analysis records found for repository '{owner}/{repo}'."
        )

    # Get latest assessment
    latest_assessment = sorted(repo_record.assessments, key=lambda a: a.created_at, reverse=True)[0]
    service = AnalysisService(db)
    result = service.get_analysis_by_id(latest_assessment.analysis_id)
    return result

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, ConfigDict
from backend.app.schemas.repository import RepositorySchema
from backend.app.schemas.vulnerability import VulnerabilitySchema
from backend.app.schemas.risk import RiskFactorBreakdown

class AnalyzeRequest(BaseModel):
    repository_url: str
    use_demo_fixture: bool = False

class AnalysisResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    analysis_id: str
    repository: RepositorySchema
    vulnerabilities: List[VulnerabilitySchema] = []
    features: Dict[str, float]
    normalized_features: Dict[str, float]
    risk_factors: Dict[str, RiskFactorBreakdown]
    risk_score: float
    risk_level: str
    explanation: str
    scoring_version: str
    feature_version: str
    is_demo_fixture: bool = False
    timestamp: datetime


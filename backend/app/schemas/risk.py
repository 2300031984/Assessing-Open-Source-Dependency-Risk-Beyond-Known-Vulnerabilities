from typing import Dict, List, Optional
from pydantic import BaseModel

class RiskFactorBreakdown(BaseModel):
    factor_name: str
    raw_value: float
    normalized_value: float
    weight: float
    weighted_contribution: float

class RiskAssessmentResult(BaseModel):
    composite_score: float
    risk_level: str
    explanation: str
    risk_factors: Dict[str, RiskFactorBreakdown]
    weights_used: Dict[str, float]
    scoring_version: str
    feature_version: str

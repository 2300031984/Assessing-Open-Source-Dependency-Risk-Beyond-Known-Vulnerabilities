import uuid
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from backend.app.risk.config import risk_config
from backend.app.risk.feature_extractor import FeatureExtractor
from backend.app.risk.normalizer import Normalizer
from backend.app.risk.classifier import RiskClassifier
from backend.app.risk.explanation import ExplanationGenerator
from backend.app.schemas.risk import RiskFactorBreakdown, RiskAssessmentResult

logger = logging.getLogger("cyber100.risk.engine")

class ScoringEngine:
    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
        scoring_version: Optional[str] = None,
        feature_version: Optional[str] = None
    ):
        self.weights = weights or risk_config.DEFAULT_WEIGHTS
        self.scoring_version = scoring_version or risk_config.SCORING_VERSION
        self.feature_version = feature_version or risk_config.FEATURE_VERSION
        
        self.feature_extractor = FeatureExtractor()
        self.normalizer = Normalizer()
        self.classifier = RiskClassifier()
        self.explanation_generator = ExplanationGenerator()

    def calculate_risk(
        self,
        repo_data: Dict[str, Any],
        vulnerabilities_data: List[Dict[str, Any]],
        analysis_id_prefix: str = "RA"
    ) -> Dict[str, Any]:
        """
        Execute full composite risk calculation pipeline.
        Returns a complete reproducible assessment dictionary.
        """
        # 1. Extract raw features
        raw_features = self.feature_extractor.extract_features(repo_data, vulnerabilities_data)

        # 2. Normalize features to [0.0, 1.0]
        normalized_features = self.normalizer.normalize_features(raw_features)

        # 3. Calculate weighted composite score
        composite_score = 0.0
        factor_breakdown: Dict[str, RiskFactorBreakdown] = {}

        for factor_name, norm_val in normalized_features.items():
            weight = self.weights.get(factor_name, 0.0)
            weighted_contrib = round(norm_val * weight, 4)
            composite_score += weighted_contrib

            factor_breakdown[factor_name] = RiskFactorBreakdown(
                factor_name=factor_name,
                raw_value=raw_features.get(factor_name, 0.0),
                normalized_value=norm_val,
                weight=weight,
                weighted_contribution=weighted_contrib
            )

        composite_score = round(min(1.0, max(0.0, composite_score)), 4)

        # 4. Classify risk level
        risk_level = self.classifier.classify(composite_score)

        # 5. Generate transparent explanation
        explanation = self.explanation_generator.generate_explanation(
            composite_score, risk_level, factor_breakdown
        )

        # 6. Generate reproducible analysis ID
        short_uuid = uuid.uuid4().hex[:6].upper()
        analysis_id = f"{analysis_id_prefix}-{short_uuid}"

        return {
            "analysis_id": analysis_id,
            "raw_features": raw_features,
            "normalized_features": normalized_features,
            "risk_factors": factor_breakdown,
            "composite_score": composite_score,
            "risk_level": risk_level,
            "explanation": explanation,
            "weights_used": self.weights,
            "scoring_version": self.scoring_version,
            "feature_version": self.feature_version,
            "timestamp": datetime.now(timezone.utc)
        }

from typing import Dict, Any

class RiskConfig:
    # Prototype initial risk factor weights (Must sum to 1.0)
    DEFAULT_WEIGHTS: Dict[str, float] = {
        "vulnerability": 0.30,
        "repository_health": 0.20,
        "activity": 0.15,
        "maintainer": 0.15,
        "release": 0.10,
        "dependency": 0.10
    }

    # Prototype risk classification thresholds
    CLASSIFICATION_THRESHOLDS: Dict[str, float] = {
        "LOW": 0.24,
        "MODERATE": 0.49,
        "HIGH": 0.74,
        "CRITICAL": 1.00
    }

    SCORING_VERSION: str = "v0.1"
    FEATURE_VERSION: str = "v0.1"

risk_config = RiskConfig()

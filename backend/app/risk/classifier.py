from typing import Dict
from backend.app.risk.config import risk_config

class RiskClassifier:
    def classify(self, score: float, custom_thresholds: Dict[str, float] = None) -> str:
        """
        Classify composite risk score into human-understandable risk levels.
        Thresholds default to config settings:
        0.00 - 0.24 = LOW
        0.25 - 0.49 = MODERATE
        0.50 - 0.74 = HIGH
        0.75 - 1.00 = CRITICAL
        """
        thresholds = custom_thresholds or risk_config.CLASSIFICATION_THRESHOLDS
        
        if score <= thresholds.get("LOW", 0.24):
            return "LOW"
        elif score <= thresholds.get("MODERATE", 0.49):
            return "MODERATE"
        elif score <= thresholds.get("HIGH", 0.74):
            return "HIGH"
        else:
            return "CRITICAL"

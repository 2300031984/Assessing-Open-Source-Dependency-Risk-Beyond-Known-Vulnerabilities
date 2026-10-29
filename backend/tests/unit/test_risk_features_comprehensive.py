import pytest
from backend.app.risk.feature_extractor import FeatureExtractor
from backend.app.risk.normalizer import Normalizer
from backend.app.risk.classifier import RiskClassifier
from backend.app.risk.explanation import ExplanationGenerator
from backend.app.schemas.risk import RiskFactorBreakdown

def test_feature_extractor_archived_repository():
    """Verify archived repository incurs health and governance penalties."""
    extractor = FeatureExtractor()
    repo_data_archived = {
        "owner": "abandoned-owner",
        "name": "dead-project",
        "license": "MIT",
        "archived": True,
        "signals": {
            "stars": 100,
            "forks": 10,
            "open_issues": 5,
            "recent_commits": 0,
            "commit_frequency_per_month": 0.0,
            "contributor_count": 1,
            "top_contributor_commit_ratio": 1.0,
            "release_age_days": 1000,
            "missing_fields": []
        }
    }
    features = extractor.extract_features(repo_data_archived, [])
    # Archived adds 3.0 to health and 0.5 to dependency
    assert features["repository_health"] >= 3.0
    assert features["dependency"] >= 0.5
    assert features["activity"] == 30.0 # max activity risk
    assert features["maintainer"] == 1.0 # single maintainer

def test_feature_extractor_unlicensed_repository():
    """Verify repository without license incurs legal governance risk."""
    extractor = FeatureExtractor()
    repo_data_unlicensed = {
        "owner": "dev",
        "name": "no-license-repo",
        "license": None,
        "archived": False,
        "signals": {"missing_fields": []}
    }
    features = extractor.extract_features(repo_data_unlicensed, [])
    assert features["dependency"] == 0.8

def test_feature_extractor_copyleft_gpl_license():
    """Verify GPL copyleft license incurs governance note."""
    extractor = FeatureExtractor()
    repo_data_gpl = {
        "owner": "gnu-project",
        "name": "gpl-tool",
        "license": "GPL-3.0-or-later",
        "archived": False,
        "signals": {"missing_fields": []}
    }
    features = extractor.extract_features(repo_data_gpl, [])
    assert features["dependency"] == 0.3

def test_feature_extractor_active_healthy_repo():
    """Verify active popular repository produces low raw risk indicators."""
    extractor = FeatureExtractor()
    repo_data = {
        "owner": "popular-org",
        "name": "super-lib",
        "license": "Apache-2.0",
        "archived": False,
        "signals": {
            "stars": 50000,
            "forks": 10000,
            "open_issues": 100,
            "recent_commits": 30,
            "commit_frequency_per_month": 35.0, # Active
            "contributor_count": 25,
            "top_contributor_commit_ratio": 0.15,
            "release_age_days": 10,
            "missing_fields": []
        }
    }
    features = extractor.extract_features(repo_data, [])
    assert features["vulnerability"] == 0.0
    assert features["activity"] == 0.0
    assert features["maintainer"] == 0.15
    assert features["release"] == 10.0
    assert features["dependency"] == 0.0

def test_normalizer_clamping():
    """Verify normalizer strictly clamps all outputs to [0.0, 1.0]."""
    normalizer = Normalizer()
    extreme_raw = {
        "vulnerability": 99.0,
        "repository_health": -5.0,
        "activity": -10.0,
        "maintainer": 2.5,
        "release": 2000.0,
        "dependency": 5.0
    }
    norm = normalizer.normalize_features(extreme_raw)
    assert norm["vulnerability"] == 1.0
    assert norm["repository_health"] == 0.0
    assert norm["activity"] == 0.0
    assert norm["maintainer"] == 1.0
    assert norm["release"] == 1.0
    assert norm["dependency"] == 1.0

def test_classifier_all_boundary_thresholds():
    """Verify risk classification exact threshold boundaries."""
    classifier = RiskClassifier()
    # LOW: 0.00 to 0.24
    assert classifier.classify(0.00) == "LOW"
    assert classifier.classify(0.24) == "LOW"
    # MODERATE: 0.25 to 0.49
    assert classifier.classify(0.241) == "MODERATE"
    assert classifier.classify(0.25) == "MODERATE"
    assert classifier.classify(0.49) == "MODERATE"
    # HIGH: 0.50 to 0.74
    assert classifier.classify(0.491) == "HIGH"
    assert classifier.classify(0.50) == "HIGH"
    assert classifier.classify(0.74) == "HIGH"
    # CRITICAL: 0.75 to 1.00
    assert classifier.classify(0.741) == "CRITICAL"
    assert classifier.classify(0.75) == "CRITICAL"
    assert classifier.classify(1.00) == "CRITICAL"

def test_explanation_generator_high_risk_breakdown():
    """Verify natural language explanation accurately lists dominant risk factors."""
    generator = ExplanationGenerator()
    factors = {
        "maintainer": RiskFactorBreakdown(
            factor_name="maintainer",
            raw_value=0.90,
            normalized_value=0.90,
            weight=0.15,
            weighted_contribution=0.135
        ),
        "vulnerability": RiskFactorBreakdown(
            factor_name="vulnerability",
            raw_value=8.0,
            normalized_value=0.80,
            weight=0.30,
            weighted_contribution=0.24
        ),
        "release": RiskFactorBreakdown(
            factor_name="release",
            raw_value=500.0,
            normalized_value=0.68,
            weight=0.10,
            weighted_contribution=0.068
        ),
        "activity": RiskFactorBreakdown(
            factor_name="activity",
            raw_value=5.0,
            normalized_value=0.16,
            weight=0.15,
            weighted_contribution=0.024
        ),
        "repository_health": RiskFactorBreakdown(
            factor_name="repository_health",
            raw_value=0.5,
            normalized_value=0.10,
            weight=0.20,
            weighted_contribution=0.02
        ),
        "dependency": RiskFactorBreakdown(
            factor_name="dependency",
            raw_value=0.0,
            normalized_value=0.0,
            weight=0.10,
            weighted_contribution=0.0
        )
    }

    explanation = generator.generate_explanation(0.487, "MODERATE", factors)
    assert "Composite Risk Score: 0.49 (MODERATE)" in explanation
    assert "known vulnerability signals" in explanation
    assert "maintainer bottleneck risk" in explanation

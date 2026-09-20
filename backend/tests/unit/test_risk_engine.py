from backend.app.risk.scoring_engine import ScoringEngine
from backend.app.risk.classifier import RiskClassifier

def test_t10_risk_calculation_formula():
    """T10 — weighted composite risk calculation math"""
    custom_weights = {
        "vulnerability": 0.30,
        "repository_health": 0.20,
        "activity": 0.15,
        "maintainer": 0.15,
        "release": 0.10,
        "dependency": 0.10
    }
    engine = ScoringEngine(weights=custom_weights)

    repo_data = {
        "owner": "test",
        "name": "repo",
        "license": "MIT",
        "signals": {
            "stars": 1000,
            "forks": 100,
            "open_issues": 5,
            "commit_frequency_per_month": 20.0,
            "contributor_count": 10,
            "top_contributor_commit_ratio": 0.30,
            "release_age_days": 30,
            "missing_fields": []
        }
    }
    vulns_data = [] # No known vulnerabilities

    result = engine.calculate_risk(repo_data, vulns_data)

    assert 0.0 <= result["composite_score"] <= 1.0
    assert result["scoring_version"] == "v0.1"
    assert "explanation" in result
    assert result["explanation"] != ""

def test_t11_classification_thresholds():
    """T11 — risk classification thresholds mapping"""
    classifier = RiskClassifier()

    assert classifier.classify(0.10) == "LOW"
    assert classifier.classify(0.24) == "LOW"
    assert classifier.classify(0.25) == "MODERATE"
    assert classifier.classify(0.49) == "MODERATE"
    assert classifier.classify(0.50) == "HIGH"
    assert classifier.classify(0.74) == "HIGH"
    assert classifier.classify(0.75) == "CRITICAL"
    assert classifier.classify(0.95) == "CRITICAL"

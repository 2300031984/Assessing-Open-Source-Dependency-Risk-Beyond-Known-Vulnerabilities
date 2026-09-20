from backend.app.risk.feature_extractor import FeatureExtractor
from backend.app.risk.normalizer import Normalizer

def test_t08_feature_extraction():
    """T08 — feature extraction from raw repository signals"""
    extractor = FeatureExtractor()
    repo_data = {
        "owner": "test",
        "name": "repo",
        "url": "https://github.com/test/repo",
        "license": "MIT",
        "archived": False,
        "signals": {
            "stars": 100,
            "forks": 20,
            "open_issues": 10,
            "recent_commits": 5,
            "commit_frequency_per_month": 2.0,
            "contributor_count": 1,
            "top_contributor_commit_ratio": 1.0,
            "release_age_days": 100,
            "missing_fields": []
        }
    }
    vulns_data = [
        {"cvss_score": 8.0, "severity": "HIGH"}
    ]

    features = extractor.extract_features(repo_data, vulns_data)

    assert "vulnerability" in features
    assert "repository_health" in features
    assert "activity" in features
    assert "maintainer" in features
    assert "release" in features
    assert "dependency" in features

    assert features["vulnerability"] >= 8.0
    assert features["maintainer"] == 1.0

def test_t09_normalization_bounds():
    """T09 — normalization feature scaling to [0.0, 1.0] bounds"""
    normalizer = Normalizer()
    raw_features = {
        "vulnerability": 15.0, # Exceeds max scale
        "repository_health": 8.0,
        "activity": 35.0,
        "maintainer": 1.2,
        "release": 900.0,
        "dependency": 0.5
    }

    norm = normalizer.normalize_features(raw_features)

    for factor_name, val in norm.items():
        assert 0.0 <= val <= 1.0, f"Factor {factor_name} out of bounds: {val}"

    assert norm["vulnerability"] == 1.0
    assert norm["release"] == 1.0
    assert norm["dependency"] == 0.5

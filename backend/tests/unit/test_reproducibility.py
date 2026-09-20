import json
from pathlib import Path
from backend.app.risk.scoring_engine import ScoringEngine
from backend.app.services.analysis_service import AnalysisService

def test_t12_reproducibility_determinism():
    """T12 — reproducibility guarantee: identical inputs produce identical scores"""
    fixtures_dir = Path(__file__).resolve().parent.parent / "fixtures"
    with open(fixtures_dir / "repository_fixture.json", "r") as f:
        repo_data = json.load(f)
    with open(fixtures_dir / "vulnerability_fixture.json", "r") as f:
        vulns_data = json.load(f)

    engine = ScoringEngine()

    run1 = engine.calculate_risk(repo_data, vulns_data)
    run2 = engine.calculate_risk(repo_data, vulns_data)

    assert run1["composite_score"] == run2["composite_score"]
    assert run1["risk_level"] == run2["risk_level"]
    assert run1["normalized_features"] == run2["normalized_features"]
    assert run1["weights_used"] == run2["weights_used"]

def test_t13_database_persistence(db_session):
    """T13 — database persistence of analysis record"""
    service = AnalysisService(db_session)
    result = service.analyze_repository("https://github.com/demo-owner/sample-crypto-lib", use_demo_fixture=True)

    analysis_id = result["analysis_id"]
    assert analysis_id.startswith("RA-")

    retrieved = service.get_analysis_by_id(analysis_id)
    assert retrieved is not None
    assert retrieved["analysis_id"] == analysis_id
    assert retrieved["risk_score"] == result["risk_score"]
    assert retrieved["risk_level"] == result["risk_level"]
    assert retrieved["repository"]["owner"] == "demo-owner"

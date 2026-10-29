import pytest
from unittest.mock import patch
from backend.app.services.analysis_service import AnalysisService
from backend.app.models.domain import Repository, RiskAssessment, RiskFeature

def test_database_multiple_analyses_same_repo(db_session):
    """Verify multiple analysis runs on same repository link properly without duplicate repository entities."""
    service = AnalysisService(db_session)
    res1 = service.analyze_repository("https://github.com/demo-owner/sample-crypto-lib", use_demo_fixture=True)
    res2 = service.analyze_repository("https://github.com/demo-owner/sample-crypto-lib", use_demo_fixture=True)

    assert res1["analysis_id"] != res2["analysis_id"]

    # Verify only one Repository record exists
    repos = db_session.query(Repository).filter(Repository.name == "sample-crypto-lib").all()
    assert len(repos) == 1

    # Verify two RiskAssessment records exist linked to this repo
    assessments = db_session.query(RiskAssessment).filter(RiskAssessment.repository_id == repos[0].id).all()
    assert len(assessments) == 2

def test_database_features_cascade(db_session):
    """Verify risk features are correctly saved and linked to assessment ID."""
    service = AnalysisService(db_session)
    result = service.analyze_repository("https://github.com/demo-owner/sample-crypto-lib", use_demo_fixture=True)
    analysis_id = result["analysis_id"]

    assessment = db_session.query(RiskAssessment).filter(RiskAssessment.analysis_id == analysis_id).first()
    assert assessment is not None

    features = db_session.query(RiskFeature).filter(RiskFeature.assessment_id == assessment.id).all()
    assert len(features) == 6
    factor_names = {f.factor_name for f in features}
    expected_names = {"vulnerability", "repository_health", "activity", "maintainer", "release", "dependency"}
    assert factor_names == expected_names

def test_database_rollback_on_persistence_error(db_session):
    """Verify that an exception during persistence triggers transaction rollback."""
    service = AnalysisService(db_session)
    
    # Intentionally corrupt repo_data to trigger integrity/type error
    broken_repo = {
        "owner": "bad",
        "name": "bad",
        "url": None # url is nullable=False
    }
    
    with pytest.raises(Exception):
        service._persist_analysis(
            broken_repo,
            [],
            {"analysis_id": "TEST-FAIL", "composite_score": 0.5, "risk_level": "MODERATE", "explanation": "", "scoring_version": "v0.1", "feature_version": "v0.1", "risk_factors": {}},
            True
        )

    # Database session should still be functional after rollback
    count = db_session.query(Repository).count()
    assert isinstance(count, int)

def test_database_get_nonexistent_id(db_session):
    """Verify get_analysis_by_id returns None for non-existent ID."""
    service = AnalysisService(db_session)
    result = service.get_analysis_by_id("RA-DOESNOTEXIST-999")
    assert result is None

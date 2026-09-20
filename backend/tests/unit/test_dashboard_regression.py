import pytest
from dashboard.app import get_field
from backend.app.schemas.risk import RiskFactorBreakdown
from backend.app.services.analysis_service import AnalysisService

def test_t16_get_field_pydantic_object_access():
    """T16 — Regression test: get_field handles Pydantic model objects without subscriptable TypeError"""
    breakdown_obj = RiskFactorBreakdown(
        factor_name="maintainer",
        raw_value=0.82,
        normalized_value=0.82,
        weight=0.15,
        weighted_contribution=0.123
    )

    # Validate attribute extraction from Pydantic object
    assert get_field(breakdown_obj, "raw_value") == 0.82
    assert get_field(breakdown_obj, "normalized_value") == 0.82
    assert get_field(breakdown_obj, "weight") == 0.15
    assert get_field(breakdown_obj, "weighted_contribution") == 0.123
    assert get_field(breakdown_obj, "non_existent", "default_val") == "default_val"

def test_t17_get_field_dictionary_access():
    """T17 — Regression test: get_field handles standard dictionaries safely"""
    breakdown_dict = {
        "factor_name": "maintainer",
        "raw_value": 0.82,
        "normalized_value": 0.82,
        "weight": 0.15,
        "weighted_contribution": 0.123
    }

    # Validate dictionary extraction
    assert get_field(breakdown_dict, "raw_value") == 0.82
    assert get_field(breakdown_dict, "normalized_value") == 0.82
    assert get_field(breakdown_dict, "weight") == 0.15
    assert get_field(breakdown_dict, "weighted_contribution") == 0.123
    assert get_field(breakdown_dict, "non_existent", "default_val") == "default_val"

def test_t18_dashboard_service_risk_factor_object_rendering(db_session):
    """T18 — Regression test: AnalysisService output rendering in dashboard table format"""
    service = AnalysisService(db_session)
    result = service.analyze_repository("https://github.com/demo-owner/sample-crypto-lib", use_demo_fixture=True)

    risk_factors = get_field(result, "risk_factors", {})
    assert len(risk_factors) > 0

    table_rows = []
    for factor_name, f_data in risk_factors.items():
        raw_val = get_field(f_data, "raw_value", 0.0)
        norm_val = get_field(f_data, "normalized_value", 0.0)
        weight_val = get_field(f_data, "weight", 0.0)
        contrib_val = get_field(f_data, "weighted_contribution", 0.0)

        table_rows.append({
            "Risk Dimension": factor_name,
            "Raw Signal": raw_val,
            "Normalized Risk (0-1)": norm_val,
            "Assigned Weight": weight_val,
            "Weighted Contribution": contrib_val
        })

    assert len(table_rows) == len(risk_factors)
    for row in table_rows:
        assert isinstance(row["Raw Signal"], (int, float))
        assert isinstance(row["Normalized Risk (0-1)"], (int, float))

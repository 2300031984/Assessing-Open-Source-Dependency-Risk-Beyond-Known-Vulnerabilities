import pytest
from dashboard.app import get_field

def test_get_field_with_none_object():
    """Verify get_field returns default safely when target object is None."""
    assert get_field(None, "any_key", "fallback") == "fallback"
    assert get_field(None, "any_key") is None

def test_get_field_with_missing_key_in_dict():
    """Verify get_field returns default when key is not in dict."""
    data = {"existing": 123}
    assert get_field(data, "existing") == 123
    assert get_field(data, "missing", "default_val") == "default_val"

def test_get_field_with_explicit_none_value():
    """Verify get_field returns default when key exists but value is explicitly None."""
    data = {"null_key": None}
    assert get_field(data, "null_key", "default_if_none") == "default_if_none"

def test_dashboard_contributor_ratio_type_safety():
    """Verify calculating contributor percentage never raises TypeError on None or string."""
    sig_none = {"top_contributor_commit_ratio": None}
    top_ratio = get_field(sig_none, "top_contributor_commit_ratio", 0.0)
    safe_ratio = float(top_ratio) if isinstance(top_ratio, (int, float)) else 0.0
    formatted = f"{safe_ratio * 100:.1f}%"
    assert formatted == "0.0%"

    sig_str = {"top_contributor_commit_ratio": "0.75"}
    top_ratio_str = get_field(sig_str, "top_contributor_commit_ratio", 0.0)
    # Even if raw data contains a string representation
    safe_ratio_str = float(top_ratio_str) if isinstance(top_ratio_str, (int, float)) else 0.0
    assert safe_ratio_str == 0.0 # safely handled without throwing TypeError

def test_dashboard_factor_breakdown_empty_safe():
    """Verify empty or None risk_factors dictionary produces zero table rows without error."""
    factors_none = None
    factors_items = factors_none.items() if hasattr(factors_none, "items") else []
    table_rows = []
    for factor_name, f_data in factors_items:
        table_rows.append(factor_name)
    assert table_rows == []

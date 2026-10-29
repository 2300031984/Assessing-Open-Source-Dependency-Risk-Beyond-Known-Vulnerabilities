import pytest
from unittest.mock import patch, MagicMock
from backend.app.collectors.osv_collector import OSVCollector

def test_osv_ecosystem_mapping():
    """Verify primary language maps correctly to package ecosystems."""
    assert OSVCollector.map_language_to_ecosystem("Python") == "PyPI"
    assert OSVCollector.map_language_to_ecosystem("JavaScript") == "npm"
    assert OSVCollector.map_language_to_ecosystem("TypeScript") == "npm"
    assert OSVCollector.map_language_to_ecosystem("Rust") == "crates.io"
    assert OSVCollector.map_language_to_ecosystem("Go") == "Go"
    assert OSVCollector.map_language_to_ecosystem("Ruby") == "RubyGems"
    assert OSVCollector.map_language_to_ecosystem("Java") == "Maven"
    assert OSVCollector.map_language_to_ecosystem("UnknownLang") == "PyPI"
    assert OSVCollector.map_language_to_ecosystem(None) == "PyPI"

def test_osv_deduplication():
    """Verify duplicate vulnerability entries from OSV are deduplicated by vuln_id."""
    collector = OSVCollector()
    with patch("requests.post") as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulns": [
                {
                    "id": "GHSA-dup-001",
                    "summary": "First instance of vulnerability",
                    "severity": [{"type": "CVSS_V3", "score": "7.5"}],
                    "affected": []
                },
                {
                    "id": "GHSA-dup-001",
                    "summary": "Duplicate instance with identical ID",
                    "severity": [{"type": "CVSS_V3", "score": "7.5"}],
                    "affected": []
                },
                {
                    "id": "GHSA-unique-002",
                    "summary": "Distinct vulnerability",
                    "severity": [{"type": "CVSS_V3", "score": "9.2"}],
                    "affected": []
                }
            ]
        }
        mock_post.return_value = mock_response

        results = collector.collect("sample-pkg", "PyPI")
        assert len(results) == 2
        assert results[0]["vuln_id"] == "GHSA-dup-001"
        assert results[1]["vuln_id"] == "GHSA-unique-002"

def test_osv_empty_vulnerabilities_response():
    """Verify empty OSV response returns empty list without error."""
    collector = OSVCollector()
    with patch("requests.post") as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulns": []}
        mock_post.return_value = mock_response

        results = collector.collect("secure-pkg", "PyPI")
        assert results == []

def test_osv_empty_package_name():
    """Verify passing empty or whitespace package name returns empty list immediately."""
    collector = OSVCollector()
    assert collector.collect("") == []
    assert collector.collect("   ") == []

def test_osv_cvss_vector_parsing():
    """Verify CVSS score parsing from vectors, numbers, and null values."""
    # Direct numeric and float string
    assert OSVCollector._parse_cvss_score(8.5) == 8.5
    assert OSVCollector._parse_cvss_score("7.2") == 7.2
    assert OSVCollector._parse_cvss_score(None) == 0.0

    # Vector string containing float score
    assert OSVCollector._parse_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H 9.8") == 9.8
    # Raw vector with no numeric match falls back to 5.0
    assert OSVCollector._parse_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N") == 5.0

def test_osv_severity_labels():
    """Verify mapping of CVSS scores to human labels."""
    assert OSVCollector._cvss_to_label(9.5) == "CRITICAL"
    assert OSVCollector._cvss_to_label(8.0) == "HIGH"
    assert OSVCollector._cvss_to_label(5.5) == "MEDIUM"
    assert OSVCollector._cvss_to_label(2.0) == "LOW"
    assert OSVCollector._cvss_to_label(0.0) == "UNKNOWN"

def test_osv_http_error_graceful_handling():
    """Verify HTTP 500 error from OSV returns empty list without crashing."""
    collector = OSVCollector()
    with patch("requests.post") as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_post.return_value = mock_response

        results = collector.collect("some-pkg", "PyPI")
        assert results == []

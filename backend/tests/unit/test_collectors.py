import pytest
from unittest.mock import patch, MagicMock
from backend.app.collectors.github_collector import GitHubCollector
from backend.app.collectors.osv_collector import OSVCollector

def test_t01_valid_repository_url_parsing():
    """T01 — valid repository URL parsing"""
    owner, repo = GitHubCollector.parse_github_url("https://github.com/psf/requests")
    assert owner == "psf"
    assert repo == "requests"

    owner2, repo2 = GitHubCollector.parse_github_url("https://github.com/torvalds/linux.git")
    assert owner2 == "torvalds"
    assert repo2 == "linux"

def test_t02_invalid_repository_url_parsing():
    """T02 — invalid repository URL handling"""
    with pytest.raises(ValueError) as exc:
        GitHubCollector.parse_github_url("https://invalid-site.com/not-github")
    assert "Invalid GitHub repository URL" in str(exc.value)

def test_t03_repository_not_found():
    """T03 — repository not found 404 response handling"""
    collector = GitHubCollector()
    with patch("requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response
        
        with pytest.raises(ValueError) as exc:
            collector.collect("https://github.com/nonexistent/fake-repo-99999")
        assert "not found" in str(exc.value)

def test_t04_github_api_failure_graceful_handling():
    """T04 — GitHub API failure fallback"""
    collector = GitHubCollector()
    with patch("requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response
        
        result = collector.collect("https://github.com/psf/requests")
        assert result["owner"] == "psf"
        assert "api_failure" in result["signals"]["missing_fields"]

def test_t05_missing_repository_field_record():
    """T05 — missing repository field recording"""
    collector = GitHubCollector()
    with patch("requests.get") as mock_get:
        # Mock main repo call returning object with no license
        mock_main = MagicMock()
        mock_main.status_code = 200
        mock_main.json.return_value = {
            "owner": {"login": "testowner"},
            "name": "testrepo",
            "html_url": "https://github.com/testowner/testrepo",
            "license": None,
            "stargazers_count": 50
        }
        # Mock sub calls returning failure
        mock_sub = MagicMock()
        mock_sub.status_code = 404

        mock_get.side_effect = [mock_main, mock_sub, mock_sub, mock_sub]

        result = collector.collect("https://github.com/testowner/testrepo")
        missing = result["signals"]["missing_fields"]
        assert "license" in missing
        assert "contributors" in missing
        assert "latest_release" in missing

def test_t06_vulnerability_api_success():
    """T06 — OSV vulnerability API query success"""
    collector = OSVCollector()
    with patch("requests.post") as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulns": [
                {
                    "id": "GHSA-1234-TEST",
                    "summary": "Sample test vulnerability",
                    "severity": [{"type": "CVSS_V3", "score": "7.8"}],
                    "affected": []
                }
            ]
        }
        mock_post.return_value = mock_response

        vulns = collector.collect("requests", "PyPI")
        assert len(vulns) == 1
        assert vulns[0]["vuln_id"] == "GHSA-1234-TEST"
        assert vulns[0]["cvss_score"] == 7.8
        assert vulns[0]["severity"] == "HIGH"

def test_t07_vulnerability_api_unavailable():
    """T07 — OSV vulnerability API failure / network timeout handling"""
    collector = OSVCollector()
    with patch("requests.post") as mock_post:
        mock_post.side_effect = Exception("Connection Timeout")

        vulns = collector.collect("requests", "PyPI")
        assert vulns == []

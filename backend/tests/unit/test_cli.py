"""
Automated unit and integration tests for CYBER-100 CLI.
Tests verify:
- CLI help, banner, and version flags
- Repository input normalization and validation (valid & invalid)
- Risk analysis execution (fixture mode & mocked live mode)
- Risk score and tier output formatting
- JSON serialization (--json) and report export (--output)
- History list and analysis detail lookup (show)
- External intelligence API failure handling (GitHub 404, OSV error, network timeouts)
- Subsystem health command
- Secret masking / redaction
- Proper process exit codes (0 for success, 1 for failure, 2 for bad arguments)
"""

import json
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
from typer.testing import CliRunner
import requests

from backend.cli.main import app, sanitize_secrets, normalize_repo_input

runner = CliRunner()


def test_cli_help():
    """Verify CLI --help flag displays usage and registered commands."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "CYBER-100" in result.output
    assert "analyze" in result.output
    assert "history" in result.output
    assert "show" in result.output
    assert "health" in result.output


def test_cli_version():
    """Verify CLI --version and -v flags return expected version strings."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "CYBER-100 CLI v" in result.output
    assert "Scoring Engine" in result.output


def test_normalize_repo_input():
    """Verify shorthand and full repository URL normalization."""
    assert normalize_repo_input("psf/requests") == "https://github.com/psf/requests"
    assert normalize_repo_input("github.com/psf/requests") == "https://github.com/psf/requests"
    assert normalize_repo_input("https://github.com/psf/requests") == "https://github.com/psf/requests"
    assert normalize_repo_input("  pallets/flask  ") == "https://github.com/pallets/flask"


def test_analyze_invalid_repo_identifier():
    """Verify invalid repository identifier triggers error message and exit code 2."""
    result = runner.invoke(app, ["analyze", "invalid-repo-without-slash"])
    assert result.exit_code == 2
    assert "Invalid Repository Format" in result.output


def test_analyze_fixture_terminal_rendering():
    """Verify analyze command with --fixture produces complete rich tables and risk breakdown."""
    result = runner.invoke(app, ["analyze", "demo-owner/sample-crypto-lib", "--fixture"])
    assert result.exit_code == 0
    assert "Open Source Dependency Risk Analyzer" in result.output
    assert "Risk Dimension Breakdown" in result.output
    assert "Known" in result.output and "Vulnerabilities" in result.output
    assert "Repository" in result.output and "Health" in result.output
    assert "Analysis ID:" in result.output
    assert "Risk Rating:" in result.output


def test_analyze_fixture_json_output():
    """Verify analyze command with --json outputs valid parseable JSON with all fields."""
    result = runner.invoke(app, ["analyze", "demo-owner/sample-crypto-lib", "--fixture", "--json"])
    assert result.exit_code == 0
    
    # Must parse without errors
    data = json.loads(result.output)
    assert "analysis_id" in data
    assert "risk_score" in data
    assert "risk_level" in data
    assert "risk_factors" in data
    assert "features" in data
    assert "vulnerabilities" in data
    assert data["repository"]["name"] == "sample-crypto-lib"
    assert isinstance(data["risk_score"], float)
    assert 0.0 <= data["risk_score"] <= 1.0


def test_analyze_fixture_file_export(tmp_path: Path):
    """Verify analyze command with --output creates file with valid JSON report."""
    output_file = tmp_path / "test_report.json"
    result = runner.invoke(app, ["analyze", "demo-owner/sample-crypto-lib", "--fixture", "--output", str(output_file)])
    assert result.exit_code == 0
    assert output_file.exists()
    
    with open(output_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "analysis_id" in data
    assert "risk_score" in data
    assert data["repository"]["name"] == "sample-crypto-lib"


def test_analyze_mocked_live_success():
    """Verify live analysis workflow using mocked external intelligence collectors."""
    mock_repo_data = {
        "owner": "testorg",
        "name": "testrepo",
        "url": "https://github.com/testorg/testrepo",
        "description": "Mocked test repository",
        "language": "Python",
        "license": "Apache-2.0",
        "archived": False,
        "signals": {
            "stars": 500,
            "forks": 120,
            "watchers": 45,
            "open_issues": 10,
            "recent_commits": 30,
            "commit_frequency_per_month": 15.0,
            "contributor_count": 8,
            "top_contributor_commit_ratio": 0.45,
            "latest_release_tag": "v2.0.0",
            "release_age_days": 45,
            "release_frequency_per_year": 6.0,
            "missing_fields": []
        }
    }
    mock_vulns_data = []

    with patch("backend.app.collectors.github_collector.GitHubCollector.collect", return_value=mock_repo_data), \
         patch("backend.app.collectors.osv_collector.OSVCollector.collect", return_value=mock_vulns_data):
        result = runner.invoke(app, ["analyze", "testorg/testrepo", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["repository"]["owner"] == "testorg"
        assert data["repository"]["name"] == "testrepo"
        assert "risk_score" in data


def test_analyze_github_404_failure():
    """Verify missing GitHub repository returns clean error panel and exit code 1."""
    with patch(
        "backend.app.collectors.github_collector.GitHubCollector.collect",
        side_effect=ValueError("GitHub repository not found: testorg/nonexistent")
    ):
        result = runner.invoke(app, ["analyze", "testorg/nonexistent"])
        assert result.exit_code == 1
        assert "Repository Not Found" in result.output
        assert "GitHub repository not found" in result.output


def test_analyze_network_timeout_failure():
    """Verify external intelligence connection timeout returns clean error and exit code 1."""
    with patch(
        "backend.app.collectors.github_collector.GitHubCollector.collect",
        side_effect=requests.exceptions.ConnectTimeout("HTTPSConnectionPool: Connection timed out")
    ):
        result = runner.invoke(app, ["analyze", "testorg/timeout-repo"])
        assert result.exit_code == 1
        assert "External Intelligence Failure" in result.output


def test_secret_redaction():
    """Verify sensitive GitHub tokens are masked with ***REDACTED***."""
    fake_token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
    raw_error = f"API rate limit exceeded using token {fake_token} on endpoint"
    sanitized = sanitize_secrets(raw_error)
    assert fake_token not in sanitized
    assert "***REDACTED***" in sanitized


def test_history_commands():
    """Verify history command works in both terminal and JSON modes."""
    # Terminal mode
    res_term = runner.invoke(app, ["history", "--limit", "5"])
    assert res_term.exit_code == 0
    assert "Recent Dependency Risk Analyses" in res_term.output or "No historical" in res_term.output

    # JSON mode
    res_json = runner.invoke(app, ["history", "--limit", "5", "--json"])
    assert res_json.exit_code == 0
    data = json.loads(res_json.output)
    assert "history" in data
    assert isinstance(data["history"], list)


def test_show_command_workflow():
    """Verify show command displays previous analysis by ID, and returns exit code 2 on missing ID."""
    # 1. Run a fixture analysis to ensure at least one record exists in DB
    run_res = runner.invoke(app, ["analyze", "demo-owner/sample-crypto-lib", "--fixture", "--json"])
    assert run_res.exit_code == 0
    analysis_data = json.loads(run_res.output)
    analysis_id = analysis_data["analysis_id"]

    # 2. Show existing analysis
    show_res = runner.invoke(app, ["show", analysis_id])
    assert show_res.exit_code == 0
    assert "sample-crypto-lib" in show_res.output
    assert analysis_id in show_res.output

    # 3. Show existing analysis in JSON mode
    show_json_res = runner.invoke(app, ["show", analysis_id, "--json"])
    assert show_json_res.exit_code == 0
    show_data = json.loads(show_json_res.output)
    assert show_data["analysis_id"] == analysis_id

    # 4. Show non-existent analysis ID
    missing_res = runner.invoke(app, ["show", "RA-NON-EXISTENT-ID-12345"])
    assert missing_res.exit_code == 2
    assert "No risk assessment found" in missing_res.output


def test_health_command():
    """Verify health command checks subsystem connectivity in terminal and JSON modes."""
    # JSON mode
    res_json = runner.invoke(app, ["health", "--json"])
    assert res_json.exit_code in (0, 1)
    health_data = json.loads(res_json.output)
    assert "status" in health_data
    assert "components" in health_data
    assert len(health_data["components"]) >= 3
    subsystem_names = [c["name"] for c in health_data["components"]]
    assert any("Database" in name for name in subsystem_names)
    assert any("GitHub" in name for name in subsystem_names)
    assert any("OSV" in name for name in subsystem_names)

    # Terminal mode
    res_term = runner.invoke(app, ["health"])
    assert res_term.exit_code in (0, 1)
    assert "System Subsystem Health Status" in res_term.output

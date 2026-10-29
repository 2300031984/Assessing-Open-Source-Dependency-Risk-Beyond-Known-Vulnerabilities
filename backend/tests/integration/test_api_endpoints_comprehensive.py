import pytest
from unittest.mock import patch, MagicMock

def test_api_root_endpoint(client):
    """Verify root GET / endpoint returns system status and docs link."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "operational"
    assert "CYBER-100" in data["project"]
    assert data["docs_url"] == "/docs"

def test_api_health_check_endpoint(client):
    """Verify health check GET /api/v1/health endpoint."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "CYBER-100" in data["project"]
    assert "scoring_version" in data

def test_api_analyze_malformed_github_url_returns_400(client):
    """Verify malformed GitHub URLs return HTTP 400 Bad Request instead of 404."""
    # Malformed path with missing repo
    res = client.post("/api/v1/analyze", json={"repository_url": "https://github.com/justanowner/"})
    assert res.status_code == 400
    assert "Invalid GitHub repository URL" in res.json()["detail"]

def test_api_analyze_nonexistent_repo_returns_404(client):
    """Verify truly non-existent repositories return HTTP 404 Not Found."""
    with patch("requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        res = client.post("/api/v1/analyze", json={"repository_url": "https://github.com/fake-owner-99999/nonexistent-repo-99999"})
        assert res.status_code == 404
        assert "not found" in res.json()["detail"].lower()

def test_api_get_repository_latest_success_and_not_found(client):
    """Verify GET /api/v1/repository/{owner}/{repo} endpoint."""
    # 1. Before analyzing, should return 404
    res_not_found = client.get("/api/v1/repository/demo-owner/sample-crypto-lib")
    assert res_not_found.status_code == 404

    # 2. Perform an analysis via demo fixture
    analyze_res = client.post("/api/v1/analyze", json={
        "repository_url": "https://github.com/demo-owner/sample-crypto-lib",
        "use_demo_fixture": True
    })
    assert analyze_res.status_code == 200

    # 3. Query repository endpoint again, should return 200 with analysis
    res_found = client.get("/api/v1/repository/demo-owner/sample-crypto-lib")
    assert res_found.status_code == 200
    repo_data = res_found.json()
    assert repo_data["repository"]["owner"] == "demo-owner"
    assert repo_data["repository"]["name"] == "sample-crypto-lib"
    assert "risk_score" in repo_data
    assert "warnings" in repo_data

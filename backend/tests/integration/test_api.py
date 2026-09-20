def test_t14_api_validation(client):
    """T14 — API endpoint request validation & error handling"""
    # 1. Empty URL
    res1 = client.post("/api/v1/analyze", json={"repository_url": ""})
    assert res1.status_code == 400
    assert "Repository URL must be provided" in res1.json()["detail"]

    # 2. Non-GitHub URL without demo flag
    res2 = client.post("/api/v1/analyze", json={"repository_url": "https://gitlab.com/some/repo"})
    assert res2.status_code == 400
    assert "Only GitHub repository URLs" in res2.json()["detail"]

    # 3. Non-existent Analysis ID lookup
    res3 = client.get("/api/v1/analysis/RA-NONEXISTENT")
    assert res3.status_code == 404

def test_t15_complete_end_to_end_analysis_flow(client):
    """T15 — complete end-to-end analysis via REST API"""
    # Execute analysis using demo fixture flag
    payload = {
        "repository_url": "https://github.com/demo-owner/sample-crypto-lib",
        "use_demo_fixture": True
    }
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert "analysis_id" in data
    assert data["analysis_id"].startswith("RA-")
    assert "repository" in data
    assert data["repository"]["name"] == "sample-crypto-lib"
    assert "risk_score" in data
    assert 0.0 <= data["risk_score"] <= 1.0
    assert data["risk_level"] in ["LOW", "MODERATE", "HIGH", "CRITICAL"]
    assert "explanation" in data
    assert data["is_demo_fixture"] is True

    # Retrieve saved analysis via GET
    analysis_id = data["analysis_id"]
    get_res = client.get(f"/api/v1/analysis/{analysis_id}")
    assert get_res.status_code == 200
    get_data = get_res.json()
    assert get_data["analysis_id"] == analysis_id
    assert get_data["risk_score"] == data["risk_score"]

import pytest
from backend.app.collectors.github_collector import GitHubCollector

def test_url_validation_clean_urls():
    """Verify parsing of clean standard GitHub URLs."""
    owner, repo = GitHubCollector.parse_github_url("https://github.com/psf/requests")
    assert owner == "psf"
    assert repo == "requests"

def test_url_validation_with_git_suffix():
    """Verify parsing of URLs ending with .git."""
    owner, repo = GitHubCollector.parse_github_url("https://github.com/pallets/flask.git")
    assert owner == "pallets"
    assert repo == "flask"

def test_url_validation_with_trailing_slash():
    """Verify parsing of URLs with trailing slashes."""
    owner, repo = GitHubCollector.parse_github_url("https://github.com/tiangolo/fastapi/")
    assert owner == "tiangolo"
    assert repo == "fastapi"

def test_url_validation_with_query_params():
    """Verify URL query parameters are stripped during parsing."""
    owner, repo = GitHubCollector.parse_github_url("https://github.com/encode/uvicorn?tab=readme-ov-file")
    assert owner == "encode"
    assert repo == "uvicorn"

def test_url_validation_with_fragment():
    """Verify URL fragments are stripped during parsing."""
    owner, repo = GitHubCollector.parse_github_url("https://github.com/pydantic/pydantic#documentation")
    assert owner == "pydantic"
    assert repo == "pydantic"

def test_url_validation_with_whitespace():
    """Verify whitespace is trimmed around URLs."""
    owner, repo = GitHubCollector.parse_github_url("   https://github.com/sqlalchemy/sqlalchemy   ")
    assert owner == "sqlalchemy"
    assert repo == "sqlalchemy"

def test_url_validation_non_github_host():
    """Verify non-GitHub URLs are rejected with ValueError."""
    with pytest.raises(ValueError) as exc:
        GitHubCollector.parse_github_url("https://gitlab.com/group/project")
    assert "Invalid GitHub repository URL" in str(exc.value)

def test_url_validation_missing_repo():
    """Verify URLs missing repository name are rejected."""
    with pytest.raises(ValueError) as exc:
        GitHubCollector.parse_github_url("https://github.com/onlyowner/")
    assert "Invalid GitHub repository URL" in str(exc.value)

def test_url_validation_excessive_length():
    """Verify excessively long URLs (> 512 chars) are rejected."""
    long_url = "https://github.com/owner/" + ("a" * 500)
    with pytest.raises(ValueError) as exc:
        GitHubCollector.parse_github_url(long_url)
    assert "exceeds maximum supported length" in str(exc.value)

def test_url_validation_reserved_routes():
    """Verify reserved GitHub top-level paths are rejected."""
    with pytest.raises(ValueError) as exc:
        GitHubCollector.parse_github_url("https://github.com/explore/trending")
    assert "reserved GitHub route" in str(exc.value)

def test_url_validation_empty_or_non_string():
    """Verify empty or non-string inputs are rejected."""
    with pytest.raises(ValueError) as exc1:
        GitHubCollector.parse_github_url("")
    assert "non-empty string" in str(exc1.value)

    with pytest.raises(ValueError) as exc2:
        GitHubCollector.parse_github_url(None)
    assert "non-empty string" in str(exc2.value)

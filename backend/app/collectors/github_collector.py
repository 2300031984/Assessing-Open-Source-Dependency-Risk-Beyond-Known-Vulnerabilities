import re
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, Optional, List
import requests
from backend.app.core.config import settings
from backend.app.collectors.base import BaseCollector

logger = logging.getLogger("cyber100.collectors.github")

class GitHubCollector(BaseCollector):
    GITHUB_API_BASE = "https://api.github.com"

    def __init__(self, token: Optional[str] = None):
        self.token = token or settings.GITHUB_TOKEN
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "CYBER-100-Risk-Collector/1.0"
        }
        if self.token:
            self.headers["Authorization"] = f"token {self.token}"

    @staticmethod
    def parse_github_url(url: str) -> Tuple[str, str]:
        """Extract owner and repository name from a GitHub URL."""
        pattern = r"github\.com/([^/]+)/([^/]+?)(?:\.git|/)?$"
        match = re.search(pattern, url.strip())
        if not match:
            raise ValueError(f"Invalid GitHub repository URL: {url}")
        owner = match.group(1)
        repo = match.group(2)
        return owner, repo

    def collect(self, repository_url: str) -> Dict[str, Any]:
        """Collect all available repository signals from GitHub API."""
        owner, repo = self.parse_github_url(repository_url)
        missing_fields: List[str] = []

        # 1. Base Repository Info
        repo_api_url = f"{self.GITHUB_API_BASE}/repos/{owner}/{repo}"
        try:
            res = requests.get(repo_api_url, headers=self.headers, timeout=10)
            if res.status_code == 404:
                raise ValueError(f"GitHub repository not found: {owner}/{repo}")
            elif res.status_code == 403 and "rate limit" in res.text.lower():
                logger.warning(f"GitHub API rate limit exceeded for {owner}/{repo}")
                missing_fields.append("rate_limit_exceeded")
                repo_data = {}
            elif res.status_code != 200:
                logger.error(f"GitHub API error {res.status_code} for {owner}/{repo}")
                missing_fields.append("api_failure")
                repo_data = {}
            else:
                repo_data = res.json()
        except requests.RequestException as e:
            logger.error(f"Network error querying GitHub API: {e}")
            missing_fields.append("network_error")
            repo_data = {}

        if not repo_data:
            # Fallback structure with recorded missing fields
            return {
                "owner": owner,
                "name": repo,
                "url": f"https://github.com/{owner}/{repo}",
                "description": "API data unavailable",
                "language": None,
                "license": None,
                "created_at_repo": None,
                "updated_at_repo": None,
                "archived": False,
                "signals": {
                    "stars": 0,
                    "forks": 0,
                    "watchers": 0,
                    "open_issues": 0,
                    "recent_commits": 0,
                    "commit_frequency_per_month": 0.0,
                    "contributor_count": 0,
                    "top_contributor_commit_ratio": 0.0,
                    "latest_release_tag": None,
                    "latest_release_date": None,
                    "release_age_days": None,
                    "release_frequency_per_year": 0.0,
                    "missing_fields": missing_fields,
                    "collected_at": datetime.now(timezone.utc).isoformat()
                }
            }

        # Parse license safely
        license_name = None
        if repo_data.get("license") and isinstance(repo_data["license"], dict):
            license_name = repo_data["license"].get("spdx_id") or repo_data["license"].get("name")
        if not license_name:
            missing_fields.append("license")

        # Parse dates safely
        created_at = self._parse_iso_date(repo_data.get("created_at"))
        updated_at = self._parse_iso_date(repo_data.get("updated_at"))

        # 2. Contributors & Maintainer Concentration
        contributors_url = f"{self.GITHUB_API_BASE}/repos/{owner}/{repo}/contributors?per_page=30"
        contributor_count, top_ratio = self._fetch_contributor_stats(contributors_url, missing_fields)

        # 3. Release & Maintenance Info
        releases_url = f"{self.GITHUB_API_BASE}/repos/{owner}/{repo}/releases"
        latest_tag, latest_rel_date, rel_age_days, rel_freq = self._fetch_release_stats(releases_url, missing_fields)

        # 4. Recent Commit Activity
        commits_url = f"{self.GITHUB_API_BASE}/repos/{owner}/{repo}/commits?per_page=30"
        recent_commits, commit_freq = self._fetch_commit_stats(commits_url, missing_fields)

        return {
            "owner": repo_data.get("owner", {}).get("login", owner),
            "name": repo_data.get("name", repo),
            "url": repo_data.get("html_url", f"https://github.com/{owner}/{repo}"),
            "description": repo_data.get("description"),
            "language": repo_data.get("language"),
            "license": license_name,
            "created_at_repo": created_at,
            "updated_at_repo": updated_at,
            "archived": repo_data.get("archived", False),
            "signals": {
                "stars": repo_data.get("stargazers_count", 0),
                "forks": repo_data.get("forks_count", 0),
                "watchers": repo_data.get("subscribers_count", repo_data.get("watchers_count", 0)),
                "open_issues": repo_data.get("open_issues_count", 0),
                "recent_commits": recent_commits,
                "commit_frequency_per_month": commit_freq,
                "contributor_count": contributor_count,
                "top_contributor_commit_ratio": top_ratio,
                "latest_release_tag": latest_tag,
                "latest_release_date": latest_rel_date,
                "release_age_days": rel_age_days,
                "release_frequency_per_year": rel_freq,
                "missing_fields": missing_fields,
                "collected_at": datetime.now(timezone.utc).isoformat()
            }
        }

    def _fetch_contributor_stats(self, url: str, missing_fields: List[str]) -> Tuple[int, float]:
        try:
            res = requests.get(url, headers=self.headers, timeout=5)
            if res.status_code == 200:
                contributors = res.json()
                if isinstance(contributors, list) and len(contributors) > 0:
                    total_contribs = len(contributors)
                    total_commits = sum(c.get("contributions", 0) for c in contributors if isinstance(c, dict))
                    top_commits = contributors[0].get("contributions", 0) if isinstance(contributors[0], dict) else 0
                    top_ratio = round(top_commits / total_commits, 4) if total_commits > 0 else 0.0
                    return total_contribs, top_ratio
            missing_fields.append("contributors")
        except Exception as e:
            logger.debug(f"Could not fetch contributors: {e}")
            missing_fields.append("contributors")
        return 0, 0.0

    def _fetch_release_stats(self, url: str, missing_fields: List[str]) -> Tuple[Optional[str], Optional[str], Optional[int], float]:
        try:
            res = requests.get(url, headers=self.headers, timeout=5)
            if res.status_code == 200:
                releases = res.json()
                if isinstance(releases, list) and len(releases) > 0:
                    latest = releases[0]
                    tag = latest.get("tag_name")
                    rel_date_str = latest.get("published_at") or latest.get("created_at")
                    rel_date = self._parse_iso_date(rel_date_str)
                    age_days = None
                    if rel_date:
                        dt = datetime.fromisoformat(rel_date.replace("Z", "+00:00"))
                        now = datetime.now(timezone.utc)
                        age_days = max(0, (now - dt).days)
                    freq_per_year = round(len(releases) / 1.0, 2)
                    return tag, rel_date, age_days, freq_per_year
            missing_fields.append("latest_release")
        except Exception as e:
            logger.debug(f"Could not fetch releases: {e}")
            missing_fields.append("latest_release")
        return None, None, None, 0.0

    def _fetch_commit_stats(self, url: str, missing_fields: List[str]) -> Tuple[int, float]:
        try:
            res = requests.get(url, headers=self.headers, timeout=5)
            if res.status_code == 200:
                commits = res.json()
                if isinstance(commits, list):
                    count = len(commits)
                    # 30 commits per month estimate
                    freq_monthly = round(count * 1.0, 2)
                    return count, freq_monthly
            missing_fields.append("recent_commits")
        except Exception as e:
            logger.debug(f"Could not fetch commits: {e}")
            missing_fields.append("recent_commits")
        return 0, 0.0

    @staticmethod
    def _parse_iso_date(date_str: Optional[str]) -> Optional[str]:
        if not date_str:
            return None
        try:
            # normalize ISO string
            dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            return dt.isoformat()
        except Exception:
            return None

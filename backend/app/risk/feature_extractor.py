from typing import Dict, Any, List
import logging

logger = logging.getLogger("cyber100.risk.extractor")

class FeatureExtractor:
    def extract_features(self, repo_data: Dict[str, Any], vulns_data: List[Dict[str, Any]]) -> Dict[str, float]:
        """
        Extract raw quantitative risk features from collected repository signals
        and vulnerability intelligence.
        """
        signals = repo_data.get("signals", {})

        # 1. Vulnerability Risk Raw Feature
        max_cvss = 0.0
        total_vuln_count = len(vulns_data)
        for v in vulns_data:
            cvss = v.get("cvss_score", 0.0) or 0.0
            if cvss > max_cvss:
                max_cvss = cvss
            elif v.get("severity") == "CRITICAL":
                max_cvss = max(max_cvss, 9.5)
            elif v.get("severity") == "HIGH":
                max_cvss = max(max_cvss, 7.5)
            elif v.get("severity") == "MEDIUM":
                max_cvss = max(max_cvss, 5.0)
            elif v.get("severity") == "LOW":
                max_cvss = max(max_cvss, 2.5)
        
        # Combine max CVSS and vulnerability count
        raw_vuln_feature = min(10.0, max_cvss + (total_vuln_count * 0.5))

        # 2. Repository Health Risk Raw Feature
        open_issues = signals.get("open_issues", 0)
        stars = signals.get("stars", 0)
        forks = signals.get("forks", 0)
        archived = repo_data.get("archived", False)
        missing_count = len(signals.get("missing_fields", []))

        # Unbalanced issues-to-popularity ratio or unmaintained state
        issue_ratio = open_issues / (stars + forks + 10.0)
        health_raw = (issue_ratio * 5.0) + (3.0 if archived else 0.0) + (missing_count * 0.5)

        # 3. Activity Risk Raw Feature
        recent_commits = signals.get("recent_commits", 0)
        commit_freq = signals.get("commit_frequency_per_month", 0.0)
        # Low commit count or low monthly activity increases activity risk
        activity_raw = max(0.0, 30.0 - commit_freq)

        # 4. Maintainer / Contributor Concentration Raw Feature
        contrib_count = signals.get("contributor_count", 0)
        top_contrib_ratio = signals.get("top_contributor_commit_ratio", 0.0)
        # High concentration ratio (>0.80) or single contributor increases maintainer risk (Bus Factor = 1)
        if contrib_count <= 1:
            maintainer_raw = 1.0 # High concentration / single maintainer
        else:
            maintainer_raw = top_contrib_ratio

        # 5. Release / Maintenance Risk Raw Feature
        rel_age_days = signals.get("release_age_days")
        if rel_age_days is None:
            release_raw = 730.0 # Default 2 years if no releases found
        else:
            release_raw = float(rel_age_days)

        # 6. Dependency / License / Governance Risk Raw Feature
        license_name = repo_data.get("license")
        dependency_raw = 0.0
        if not license_name or license_name in ["NOASSERTION", "UNKNOWN"]:
            dependency_raw += 0.8 # Unclear legal / licensing status
        elif "GPL" in str(license_name).upper():
            dependency_raw += 0.3 # Copyleft consideration
        
        if archived:
            dependency_raw += 0.5

        return {
            "vulnerability": round(raw_vuln_feature, 4),
            "repository_health": round(health_raw, 4),
            "activity": round(activity_raw, 4),
            "maintainer": round(maintainer_raw, 4),
            "release": round(release_raw, 4),
            "dependency": round(dependency_raw, 4)
        }

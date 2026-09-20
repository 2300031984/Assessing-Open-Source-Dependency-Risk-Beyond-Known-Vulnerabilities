import json
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, Optional, List
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.collectors.github_collector import GitHubCollector
from backend.app.collectors.osv_collector import OSVCollector
from backend.app.risk.scoring_engine import ScoringEngine
from backend.app.models.domain import (
    Repository,
    RepositorySignal,
    Vulnerability,
    RiskAssessment,
    RiskFeature
)

logger = logging.getLogger("cyber100.services.analysis")

class AnalysisService:
    def __init__(self, db: Session):
        self.db = db
        self.github_collector = GitHubCollector()
        self.osv_collector = OSVCollector()
        self.scoring_engine = ScoringEngine()

    def analyze_repository(self, repository_url: str, use_demo_fixture: bool = False) -> Dict[str, Any]:
        """
        Execute end-to-end repository risk assessment flow:
        Input Validation -> Signal Collection -> Feature Extraction -> Scoring -> Classification -> Explanation -> Persistence.
        """
        is_demo = use_demo_fixture or settings.DEMO_MODE

        if is_demo:
            logger.info("Using DEMO FIXTURE mode for analysis.")
            repo_data, vulns_data = self._load_fixtures()
        else:
            logger.info(f"Using LIVE API mode to collect signals for: {repository_url}")
            repo_data = self.github_collector.collect(repository_url)
            # Query OSV for vulnerability signals using repo name
            vulns_data = self.osv_collector.collect(repo_data["name"])

        # Execute scoring engine
        assessment_result = self.scoring_engine.calculate_risk(repo_data, vulns_data)

        # Persist to database
        db_records = self._persist_analysis(repo_data, vulns_data, assessment_result, is_demo)

        # Return combined clean schema response
        return {
            "analysis_id": assessment_result["analysis_id"],
            "repository": {
                "owner": repo_data["owner"],
                "name": repo_data["name"],
                "url": repo_data["url"],
                "description": repo_data.get("description"),
                "language": repo_data.get("language"),
                "license": repo_data.get("license"),
                "created_at_repo": repo_data.get("created_at_repo"),
                "updated_at_repo": repo_data.get("updated_at_repo"),
                "archived": repo_data.get("archived", False),
                "signals": repo_data.get("signals")
            },
            "vulnerabilities": vulns_data,
            "features": assessment_result["raw_features"],
            "normalized_features": assessment_result["normalized_features"],
            "risk_factors": assessment_result["risk_factors"],
            "risk_score": assessment_result["composite_score"],
            "risk_level": assessment_result["risk_level"],
            "explanation": assessment_result["explanation"],
            "scoring_version": assessment_result["scoring_version"],
            "feature_version": assessment_result["feature_version"],
            "is_demo_fixture": is_demo,
            "timestamp": assessment_result["timestamp"]
        }

    def get_analysis_by_id(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve stored analysis record by unique Analysis ID."""
        assessment = self.db.query(RiskAssessment).filter(RiskAssessment.analysis_id == analysis_id).first()
        if not assessment:
            return None
        
        repo = assessment.repository
        signals = repo.signals[0] if repo.signals else None
        
        # Reconstruct factors dictionary
        factors_dict = {}
        for f in assessment.features:
            factors_dict[f.factor_name] = {
                "factor_name": f.factor_name,
                "raw_value": f.raw_value,
                "normalized_value": f.normalized_value,
                "weight": f.weight,
                "weighted_contribution": f.weighted_contribution
            }

        vulns_list = [
            {
                "vuln_id": v.vuln_id,
                "severity": v.severity,
                "cvss_score": v.cvss_score,
                "summary": v.summary,
                "affected_versions": v.affected_versions,
                "fixed_versions": v.fixed_versions,
                "published_date": v.published_date.isoformat() if v.published_date else None,
                "source": v.source
            }
            for v in repo.vulnerabilities
        ]

        return {
            "analysis_id": assessment.analysis_id,
            "repository": {
                "owner": repo.owner,
                "name": repo.name,
                "url": repo.url,
                "description": repo.description,
                "language": repo.language,
                "license": repo.license,
                "archived": repo.archived,
                "signals": {
                    "stars": signals.stars if signals else 0,
                    "forks": signals.forks if signals else 0,
                    "watchers": signals.watchers if signals else 0,
                    "open_issues": signals.open_issues if signals else 0,
                    "recent_commits": signals.recent_commits if signals else 0,
                    "commit_frequency_per_month": signals.commit_frequency_per_month if signals else 0.0,
                    "contributor_count": signals.contributor_count if signals else 0,
                    "top_contributor_commit_ratio": signals.top_contributor_commit_ratio if signals else 0.0,
                    "latest_release_tag": signals.latest_release_tag if signals else None,
                    "release_age_days": signals.release_age_days if signals else None,
                    "missing_fields": signals.missing_fields_json if signals else []
                } if signals else None
            },
            "vulnerabilities": vulns_list,
            "features": {name: factor["raw_value"] for name, factor in factors_dict.items()},
            "normalized_features": {name: factor["normalized_value"] for name, factor in factors_dict.items()},
            "risk_factors": factors_dict,
            "risk_score": assessment.composite_score,
            "risk_level": assessment.risk_level,
            "explanation": assessment.explanation_summary,
            "scoring_version": assessment.scoring_version,
            "feature_version": assessment.feature_version,
            "is_demo_fixture": assessment.is_demo_fixture,
            "timestamp": assessment.created_at
        }

    def _persist_analysis(
        self,
        repo_data: Dict[str, Any],
        vulns_data: List[Dict[str, Any]],
        assessment_result: Dict[str, Any],
        is_demo: bool
    ) -> Tuple[Repository, RiskAssessment]:
        """Save analysis records into SQLAlchemy database."""
        # 1. Get or create Repository entity
        repo = self.db.query(Repository).filter(Repository.url == repo_data["url"]).first()
        if not repo:
            repo = Repository(
                owner=repo_data["owner"],
                name=repo_data["name"],
                url=repo_data["url"],
                description=repo_data.get("description"),
                language=repo_data.get("language"),
                license=repo_data.get("license"),
                archived=repo_data.get("archived", False)
            )
            self.db.add(repo)
            self.db.flush()

        # 2. Add Signal Snapshot
        sig = repo_data.get("signals", {})
        signal_record = RepositorySignal(
            repository_id=repo.id,
            stars=sig.get("stars", 0),
            forks=sig.get("forks", 0),
            watchers=sig.get("watchers", 0),
            open_issues=sig.get("open_issues", 0),
            recent_commits=sig.get("recent_commits", 0),
            commit_frequency_per_month=sig.get("commit_frequency_per_month", 0.0),
            contributor_count=sig.get("contributor_count", 0),
            top_contributor_commit_ratio=sig.get("top_contributor_commit_ratio", 0.0),
            latest_release_tag=sig.get("latest_release_tag"),
            release_age_days=sig.get("release_age_days"),
            release_frequency_per_year=sig.get("release_frequency_per_year", 0.0),
            missing_fields_json=sig.get("missing_fields", [])
        )
        self.db.add(signal_record)

        # 3. Add Vulnerability Snapshots
        for v in vulns_data:
            vuln_record = Vulnerability(
                repository_id=repo.id,
                vuln_id=v.get("vuln_id", "UNKNOWN"),
                severity=v.get("severity"),
                cvss_score=v.get("cvss_score"),
                summary=v.get("summary"),
                affected_versions=v.get("affected_versions"),
                fixed_versions=v.get("fixed_versions"),
                source=v.get("source", "OSV")
            )
            self.db.add(vuln_record)

        # 4. Add Risk Assessment record
        assessment = RiskAssessment(
            analysis_id=assessment_result["analysis_id"],
            repository_id=repo.id,
            composite_score=assessment_result["composite_score"],
            risk_level=assessment_result["risk_level"],
            explanation_summary=assessment_result["explanation"],
            scoring_version=assessment_result["scoring_version"],
            feature_version=assessment_result["feature_version"],
            is_demo_fixture=is_demo
        )
        self.db.add(assessment)
        self.db.flush()

        # 5. Add Risk Features breakdown
        for f_name, f_breakdown in assessment_result["risk_factors"].items():
            rf = RiskFeature(
                assessment_id=assessment.id,
                factor_name=f_name,
                raw_value=f_breakdown.raw_value,
                normalized_value=f_breakdown.normalized_value,
                weight=f_breakdown.weight,
                weighted_contribution=f_breakdown.weighted_contribution
            )
            self.db.add(rf)

        self.db.commit()
        self.db.refresh(assessment)
        return repo, assessment

    @staticmethod
    def _load_fixtures() -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Load deterministic test fixtures from disk."""
        fixtures_dir = Path(__file__).resolve().parent.parent.parent / "tests" / "fixtures"
        repo_file = fixtures_dir / "repository_fixture.json"
        vuln_file = fixtures_dir / "vulnerability_fixture.json"
        
        with open(repo_file, "r") as f:
            repo_data = json.load(f)
        with open(vuln_file, "r") as f:
            vulns_data = json.load(f)

        return repo_data, vulns_data

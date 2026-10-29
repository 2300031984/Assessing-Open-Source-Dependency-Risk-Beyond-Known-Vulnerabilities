import re
import logging
from typing import Dict, Any, List, Optional
import requests
from backend.app.core.config import settings
from backend.app.collectors.base import BaseCollector

logger = logging.getLogger("cyber100.collectors.osv")

class OSVCollector(BaseCollector):
    OSV_API_URL = "https://api.osv.dev/v1/query"

    ECOSYSTEM_MAP: Dict[str, str] = {
        "python": "PyPI",
        "javascript": "npm",
        "typescript": "npm",
        "rust": "crates.io",
        "go": "Go",
        "ruby": "RubyGems",
        "java": "Maven",
        "kotlin": "Maven",
        "scala": "Maven",
        "php": "Packagist",
        "c#": "NuGet",
        "c++": "Conan",
        "c": "Conan"
    }

    @classmethod
    def map_language_to_ecosystem(cls, language: Optional[str]) -> str:
        """Map repository primary language to the standard OSV package ecosystem."""
        if not language:
            return "PyPI"
        return cls.ECOSYSTEM_MAP.get(language.strip().lower(), "PyPI")

    def collect(self, package_name: str, ecosystem: Optional[str] = "PyPI") -> List[Dict[str, Any]]:
        """
        Query OSV API for known vulnerability signals for a package name and ecosystem.
        Returns a list of parsed, deduplicated vulnerability signals.
        """
        if not package_name or not package_name.strip():
            logger.warning("Empty package name provided to OSVCollector; skipping query.")
            return []

        payload: Dict[str, Any] = {
            "package": {
                "name": package_name.strip()
            }
        }
        if ecosystem:
            payload["package"]["ecosystem"] = ecosystem

        vulnerability_signals: List[Dict[str, Any]] = []
        seen_vuln_ids = set()
        timeout = settings.API_TIMEOUT_SECONDS

        try:
            res = requests.post(self.OSV_API_URL, json=payload, timeout=timeout)
            if res.status_code == 200:
                data = res.json()
                vulns = data.get("vulns", [])
                for v in vulns:
                    vuln_id = v.get("id", "UNKNOWN-VULN")
                    if vuln_id in seen_vuln_ids:
                        continue
                    seen_vuln_ids.add(vuln_id)

                    summary = v.get("summary") or v.get("details", "No summary provided.")
                    
                    # Extract severity / CVSS if present
                    cvss_score = 0.0
                    severity_label = "UNKNOWN"
                    severities = v.get("severity", [])
                    if isinstance(severities, list):
                        for s in severities:
                            if isinstance(s, dict) and s.get("type") in ["CVSS_V3", "CVSS_V4", "CVSS_V2"]:
                                cvss_score = self._parse_cvss_score(s.get("score"))
                                severity_label = self._cvss_to_label(cvss_score)
                                break
                    
                    # Extract affected & fixed versions
                    affected_list = []
                    fixed_list = []
                    affected_entries = v.get("affected", [])
                    if isinstance(affected_entries, list):
                        for affected in affected_entries:
                            if isinstance(affected, dict):
                                pkg_ranges = affected.get("ranges", [])
                                if isinstance(pkg_ranges, list):
                                    for r in pkg_ranges:
                                        if isinstance(r, dict):
                                            for event in r.get("events", []):
                                                if isinstance(event, dict):
                                                    if "introduced" in event:
                                                        affected_list.append(f">={event['introduced']}")
                                                    if "fixed" in event:
                                                        fixed_list.append(event['fixed'])
                    
                    # Deduplicate version strings
                    affected_str = ", ".join(dict.fromkeys(affected_list)) if affected_list else "All versions"
                    fixed_str = ", ".join(dict.fromkeys(fixed_list)) if fixed_list else "None available"

                    vulnerability_signals.append({
                        "vuln_id": vuln_id,
                        "severity": severity_label,
                        "cvss_score": round(cvss_score, 1),
                        "summary": str(summary)[:250], # clean summary snippet
                        "affected_versions": affected_str,
                        "fixed_versions": fixed_str,
                        "published_date": v.get("published"),
                        "modified_date": v.get("modified"),
                        "source": "OSV Known Vulnerability Signal"
                    })
            else:
                logger.warning(f"OSV API returned HTTP {res.status_code} for package {package_name}")
        except requests.RequestException as e:
            logger.error(f"Network error querying OSV API for package {package_name}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error parsing OSV response for {package_name}: {e}")

        return vulnerability_signals

    @staticmethod
    def _parse_cvss_score(cvss_val: Any) -> float:
        if cvss_val is None:
            return 0.0
        if isinstance(cvss_val, (int, float)):
            return float(cvss_val)
        if isinstance(cvss_val, str):
            try:
                return float(cvss_val)
            except ValueError:
                # Strip CVSS version prefix (e.g. CVSS:3.1/ or CVSS:3.0/) so the version is not mistaken for the score
                cleaned = re.sub(r"^CVSS:\d+\.\d+/?", "", cvss_val.strip(), flags=re.IGNORECASE)
                vector_match = re.search(r"\b(\d+\.\d+)\b", cleaned)
                if vector_match:
                    try:
                        return float(vector_match.group(1))
                    except ValueError:
                        pass
                return 5.0 # Reasonable fallback mid-range score if unparsed vector
        return 0.0


    @staticmethod
    def _cvss_to_label(score: float) -> str:
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0.0:
            return "LOW"
        return "UNKNOWN"


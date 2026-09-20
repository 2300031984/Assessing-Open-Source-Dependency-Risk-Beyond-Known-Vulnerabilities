import logging
from typing import Dict, Any, List, Optional
import requests
from backend.app.collectors.base import BaseCollector

logger = logging.getLogger("cyber100.collectors.osv")

class OSVCollector(BaseCollector):
    OSV_API_URL = "https://api.osv.dev/v1/query"

    def collect(self, package_name: str, ecosystem: str = "PyPI") -> List[Dict[str, Any]]:
        """
        Query OSV API for known vulnerability signals for a package name and ecosystem.
        Returns a list of parsed vulnerability signals.
        """
        payload = {
            "package": {
                "name": package_name,
                "ecosystem": ecosystem
            }
        }
        vulnerability_signals: List[Dict[str, Any]] = []

        try:
            res = requests.post(self.OSV_API_URL, json=payload, timeout=8)
            if res.status_code == 200:
                data = res.json()
                vulns = data.get("vulns", [])
                for v in vulns:
                    vuln_id = v.get("id", "UNKNOWN-VULN")
                    summary = v.get("summary") or v.get("details", "No summary provided.")
                    
                    # Extract severity / CVSS if present
                    cvss_score = 0.0
                    severity_label = "UNKNOWN"
                    severities = v.get("severity", [])
                    for s in severities:
                        if s.get("type") == "CVSS_V3":
                            cvss_score = self._parse_cvss_score(s.get("score"))
                            severity_label = self._cvss_to_label(cvss_score)
                            break
                    
                    # Extract affected & fixed versions
                    affected_list = []
                    fixed_list = []
                    for affected in v.get("affected", []):
                        pkg_ranges = affected.get("ranges", [])
                        for r in pkg_ranges:
                            for event in r.get("events", []):
                                if "introduced" in event:
                                    affected_list.append(f">={event['introduced']}")
                                if "fixed" in event:
                                    fixed_list.append(event['fixed'])
                    
                    vulnerability_signals.append({
                        "vuln_id": vuln_id,
                        "severity": severity_label,
                        "cvss_score": cvss_score,
                        "summary": summary[:250], # store clean summary snippet
                        "affected_versions": ", ".join(affected_list) if affected_list else "All versions",
                        "fixed_versions": ", ".join(fixed_list) if fixed_list else "None available",
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
    def _parse_cvss_score(cvss_str: Optional[str]) -> float:
        if not cvss_str:
            return 0.0
        # If it's a number string
        try:
            return float(cvss_str)
        except ValueError:
            pass
        # If CVSS vector string like CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        # Parse vector if metric score not directly provided
        return 5.0 # Reasonable fallback mid-range score if unparsed vector

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

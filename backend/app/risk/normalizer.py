from typing import Dict, Any

class Normalizer:
    def normalize_features(self, raw_features: Dict[str, float]) -> Dict[str, float]:
        """
        Normalize raw features to standard [0.0, 1.0] risk scores
        where 0.0 represents minimum risk and 1.0 represents maximum risk.
        """
        normalized = {}

        # 1. Vulnerability (0.0 to 10.0 scale)
        vuln_raw = raw_features.get("vulnerability", 0.0)
        normalized["vulnerability"] = round(min(1.0, max(0.0, vuln_raw / 10.0)), 4)

        # 2. Repository Health (0.0 to 5.0 scale)
        health_raw = raw_features.get("repository_health", 0.0)
        normalized["repository_health"] = round(min(1.0, max(0.0, health_raw / 5.0)), 4)

        # 3. Activity Risk (0.0 to 30.0 inverse scale)
        activity_raw = raw_features.get("activity", 0.0)
        normalized["activity"] = round(min(1.0, max(0.0, activity_raw / 30.0)), 4)

        # 4. Maintainer Concentration (0.0 to 1.0 ratio)
        maintainer_raw = raw_features.get("maintainer", 0.0)
        normalized["maintainer"] = round(min(1.0, max(0.0, maintainer_raw)), 4)

        # 5. Release Risk (0 to 730 days scale)
        release_raw = raw_features.get("release", 0.0)
        normalized["release"] = round(min(1.0, max(0.0, release_raw / 730.0)), 4)

        # 6. Dependency / Governance Risk (0.0 to 1.0 scale)
        dep_raw = raw_features.get("dependency", 0.0)
        normalized["dependency"] = round(min(1.0, max(0.0, dep_raw)), 4)

        return normalized

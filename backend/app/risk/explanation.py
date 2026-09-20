from typing import Dict, Any, List
from backend.app.schemas.risk import RiskFactorBreakdown

class ExplanationGenerator:
    def generate_explanation(
        self,
        composite_score: float,
        risk_level: str,
        factor_breakdown: Dict[str, RiskFactorBreakdown]
    ) -> str:
        """
        Generate transparent, factor-by-factor evidence-based textual risk explanation.
        Avoids making unfounded security claims or black-box assertions.
        """
        # Sort factors by weighted contribution descending
        sorted_factors = sorted(
            factor_breakdown.values(),
            key=lambda f: f.weighted_contribution,
            reverse=True
        )

        top_factors = [f for f in sorted_factors if f.normalized_value >= 0.40]
        
        explanation_lines = []
        explanation_lines.append(f"Composite Risk Score: {composite_score:.2f} ({risk_level}).")
        
        if top_factors:
            primary_names = ", ".join([self._human_factor_name(f.factor_name) for f in top_factors[:3]])
            explanation_lines.append(f"The assessment is primarily influenced by {primary_names}.")
        else:
            explanation_lines.append("The dependency exhibits stable metrics across repository activity, releases, and maintainer signals with minimal known vulnerability alerts.")

        # Specific signal details
        vuln_factor = factor_breakdown.get("vulnerability")
        if vuln_factor and vuln_factor.normalized_value > 0.0:
            explanation_lines.append(f"Known vulnerability signals contribute {vuln_factor.weighted_contribution:.2f} to the overall score.")
        
        maint_factor = factor_breakdown.get("maintainer")
        if maint_factor and maint_factor.normalized_value >= 0.60:
            explanation_lines.append("High contributor concentration ratio indicates potential maintainer bottleneck risk (bus factor = 1).")

        rel_factor = factor_breakdown.get("release")
        if rel_factor and rel_factor.normalized_value >= 0.50:
            explanation_lines.append("Extended period since the last tag or release suggests slow maintenance cadence.")

        return " ".join(explanation_lines)

    @staticmethod
    def _human_factor_name(name: str) -> str:
        mapping = {
            "vulnerability": "known vulnerability signals",
            "repository_health": "repository health and issue indicators",
            "activity": "reduced commit activity",
            "maintainer": "contributor concentration",
            "release": "release and maintenance recency",
            "dependency": "licensing and archive governance status"
        }
        return mapping.get(name, name)

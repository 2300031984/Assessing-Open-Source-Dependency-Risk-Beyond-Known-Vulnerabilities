import sys
from pathlib import Path
from datetime import datetime
from typing import Any

# Add project root to path for backend imports
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import streamlit as st
from backend.app.database.session import SessionLocal, init_db
from backend.app.services.analysis_service import AnalysisService

# Streamlit Page Config
st.set_page_config(
    page_title="KL University CYBER-100 Risk Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Helper function to safely extract attributes or dict keys from Pydantic models, objects, or dicts
def get_field(obj: Any, field_name: str, default: Any = None) -> Any:
    """
    Safely retrieve a field from a Pydantic model, object, or dictionary.
    Supports both typed-object attribute access and dictionary key access.
    Handles missing attributes, dictionary keys, and None values gracefully.
    """
    if obj is None:
        return default
    if hasattr(obj, field_name):
        val = getattr(obj, field_name)
    elif isinstance(obj, dict):
        val = obj.get(field_name)
    else:
        val = None
    return val if val is not None else default

# Custom CSS for rich aesthetics
st.markdown("""
<style>
    /* Dark Theme Accent Styling */
    .stApp {
        background-color: #0E1117;
        color: #E0E6ED;
        font-family: 'Inter', sans-serif;
    }
    
    /* Title Banner */
    .main-header {
        background: linear-gradient(135deg, #1E2640 0%, #0D1B2A 100%);
        padding: 24px;
        border-radius: 12px;
        border: 1px solid #2A3654;
        margin-bottom: 24px;
    }
    .main-title {
        font-size: 26px;
        font-weight: 700;
        color: #4CC9F0;
        margin-bottom: 4px;
    }
    .sub-title {
        font-size: 14px;
        color: #94A3B8;
    }

    /* Metric Cards */
    .metric-card {
        background: #161B26;
        border: 1px solid #232D42;
        border-radius: 10px;
        padding: 16px;
        text-align: center;
    }
    .metric-value {
        font-size: 24px;
        font-weight: 700;
        color: #F8FAFC;
    }
    .metric-label {
        font-size: 12px;
        color: #94A3B8;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    /* Risk Badges */
    .risk-badge {
        display: inline-block;
        padding: 6px 16px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 16px;
        letter-spacing: 1px;
    }
    .risk-low { background-color: #064E3B; color: #34D399; border: 1px solid #059669; }
    .risk-moderate { background-color: #78350F; color: #FBBF24; border: 1px solid #D97706; }
    .risk-high { background-color: #7C2D12; color: #F97316; border: 1px solid #EA580C; }
    .risk-critical { background-color: #7F1D1D; color: #F87171; border: 1px solid #DC2626; }

    /* Mode Badge */
    .mode-live {
        background-color: #065F46;
        color: #A7F3D0;
        padding: 4px 12px;
        border-radius: 6px;
        font-size: 12px;
        font-weight: 600;
    }
    .mode-fixture {
        background-color: #3730A3;
        color: #C7D2FE;
        padding: 4px 12px;
        border-radius: 6px;
        font-size: 12px;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)

# Initialize DB on start
init_db()

# Main Title Header
st.markdown("""
<div class="main-header">
    <div class="main-title">🛡️ Assessing Open Source Dependency Risk Beyond Known Vulnerabilities</div>
    <div class="sub-title">KL University Capstone Project CYBER-100 | Review-2 Executable Prototype (CP1)</div>
</div>
""", unsafe_allow_html=True)

# Sidebar Configuration
st.sidebar.header("⚙️ Execution Configuration")

execution_mode = st.sidebar.radio(
    "Data Source Mode",
    ["LIVE DATA (GitHub + OSV API)", "DEMO FIXTURE (Offline Mode)"],
    index=1,
    help="Select LIVE DATA to fetch real-time GitHub repository & OSV vulnerability signals, or DEMO FIXTURE for reliable offline demo execution."
)

use_fixture = (execution_mode == "DEMO FIXTURE (Offline Mode)")

st.sidebar.markdown("---")
st.sidebar.markdown("### 📋 CP1 Scope")
st.sidebar.markdown("- **O1**: Repository Signal Collection")
st.sidebar.markdown("- **O2**: Composite Risk Scoring Engine")
st.sidebar.markdown("- **O3 - O5**: *PLANNED / CP2*")
st.sidebar.markdown("---")
st.sidebar.markdown("**Scoring Version:** `v0.1`")
st.sidebar.markdown("**Feature Version:** `v0.1`")

# Main Content Form
st.subheader("🔍 Repository Risk Assessment")

col1, col2 = st.columns([3, 1])
with col1:
    default_url = "https://github.com/demo-owner/sample-crypto-lib" if use_fixture else "https://github.com/psf/requests"
    repo_url_input = st.text_input(
        "Enter GitHub Repository URL",
        value=default_url,
        placeholder="https://github.com/owner/repository"
    )

with col2:
    st.write("") # vertical spacing
    st.write("")
    analyze_button = st.button("🚀 ANALYZE RISK", use_container_width=True, type="primary")

# Execute Analysis
if analyze_button or "current_analysis" in st.session_state:
    if analyze_button:
        with st.spinner("Collecting signals, extracting features, and computing composite risk score..."):
            try:
                db = SessionLocal()
                service = AnalysisService(db)
                result = service.analyze_repository(
                    repository_url=repo_url_input.strip(),
                    use_demo_fixture=use_fixture
                )
                db.close()
                st.session_state["current_analysis"] = result
            except Exception as e:
                st.error(f"Analysis failed: {str(e)}")
                st.stop()

    data = st.session_state["current_analysis"]

    # Safely extract repository info
    repo_info = get_field(data, "repository", {})
    repo_owner = get_field(repo_info, "owner", "Unknown")
    repo_name = get_field(repo_info, "name", "Unknown")
    is_fixture = get_field(data, "is_demo_fixture", False)

    # Header Row with Mode Badge
    mode_html = '<span class="mode-fixture">DEMO FIXTURE MODE</span>' if is_fixture else '<span class="mode-live">LIVE DATA MODE</span>'
    st.markdown(f"### Results for `{repo_owner}/{repo_name}` &nbsp; {mode_html}", unsafe_allow_html=True)
    st.write("")

    # Tabbed View
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "📊 Executive Summary",
        "📦 Repository Overview",
        "⚠️ Vulnerability Signals",
        "📈 Risk Factors & Scoring",
        "💡 Explanation",
        "🔬 Audit & Reproducibility"
    ])

    # TAB 1: EXECUTIVE SUMMARY
    with tab1:
        st.markdown("#### Composite Risk Score & Classification")
        c1, c2, c3 = st.columns([1, 1, 2])
        
        score = get_field(data, "risk_score", 0.0)
        level = get_field(data, "risk_level", "UNKNOWN")
        explanation = get_field(data, "explanation", "No explanation available.")

        risk_class_map = {
            "LOW": "risk-low",
            "MODERATE": "risk-moderate",
            "HIGH": "risk-high",
            "CRITICAL": "risk-critical"
        }
        badge_class = risk_class_map.get(level, "risk-moderate")

        with c1:
            st.metric(label="Composite Risk Score", value=f"{score:.2f} / 1.00")

        with c2:
            st.markdown(f"**Risk Classification**")
            st.markdown(f'<div class="risk-badge {badge_class}">{level}</div>', unsafe_allow_html=True)

        with c3:
            st.markdown("**Key Recommendation Summary**")
            st.info(explanation)

        st.markdown("---")
        st.markdown("#### Primary Signal Metrics")
        m1, m2, m3, m4, m5 = st.columns(5)
        signals = get_field(repo_info, "signals", {})
        
        stars = get_field(signals, "stars", 0)
        forks = get_field(signals, "forks", 0)
        contribs = get_field(signals, "contributor_count", 0)
        release_age = get_field(signals, "release_age_days")
        vulns = get_field(data, "vulnerabilities", [])

        m1.metric("Stars", f"{stars:,}" if isinstance(stars, int) else str(stars))
        m2.metric("Forks", f"{forks:,}" if isinstance(forks, int) else str(forks))
        m3.metric("Contributors", f"{contribs}")
        m4.metric("Release Age", f"{release_age} days" if release_age is not None else "N/A")
        m5.metric("Known Vulns", f"{len(vulns) if isinstance(vulns, list) else 0}")

    # TAB 2: REPOSITORY OVERVIEW
    with tab2:
        st.markdown("#### Repository Identity & Activity Signals")
        
        col_a, col_b = st.columns(2)
        with col_a:
            repo_url = get_field(repo_info, "url", "#")
            st.write(f"**Repository Name:** `{repo_name}`")
            st.write(f"**Owner:** `{repo_owner}`")
            st.write(f"**URL:** [{repo_url}]({repo_url})")
            st.write(f"**Primary Language:** `{get_field(repo_info, 'language', 'Unknown')}`")
            st.write(f"**License:** `{get_field(repo_info, 'license', 'Unlicensed / Unknown')}`")
            st.write(f"**Archived Status:** `{'Yes (Unmaintained)' if get_field(repo_info, 'archived', False) else 'No (Active)'}`")

        with col_b:
            sig = get_field(repo_info, "signals", {})
            st.write(f"**Open Issues:** `{get_field(sig, 'open_issues', 0)}`")
            st.write(f"**Monthly Commit Frequency:** `{get_field(sig, 'commit_frequency_per_month', 0.0)} commits/mo`")
            top_ratio = get_field(sig, "top_contributor_commit_ratio", 0.0)
            st.write(f"**Top Contributor Concentration:** `{top_ratio * 100:.1f}%`")
            st.write(f"**Latest Release Tag:** `{get_field(sig, 'latest_release_tag', 'None')}`")
            st.write(f"**Missing Signals Logged:** `{get_field(sig, 'missing_fields', 'None')}`")

    # TAB 3: KNOWN VULNERABILITY SIGNALS
    with tab3:
        st.markdown("#### Known Vulnerability Signals (OSV Intelligence)")
        vulns_list = get_field(data, "vulnerabilities", [])
        
        if not vulns_list:
            st.success("No public known vulnerability signals reported for this package.")
        else:
            st.warning(f"Associated with {len(vulns_list)} known vulnerability signals.")
            for v in vulns_list:
                v_id = get_field(v, "vuln_id", "UNKNOWN-VULN")
                v_sev = get_field(v, "severity", "UNKNOWN")
                v_cvss = get_field(v, "cvss_score", 0.0)
                v_summary = get_field(v, "summary", "No summary provided.")
                v_affected = get_field(v, "affected_versions", "N/A")
                v_fixed = get_field(v, "fixed_versions", "N/A")
                v_source = get_field(v, "source", "OSV")

                with st.expander(f"🔴 {v_id} — Severity: {v_sev} (CVSS {v_cvss})"):
                    st.write(f"**Summary:** {v_summary}")
                    st.write(f"**Affected Versions:** `{v_affected}`")
                    st.write(f"**Fixed Versions:** `{v_fixed}`")
                    st.write(f"**Intelligence Source:** `{v_source}`")

    # TAB 4: RISK FACTORS & SCORING BREAKDOWN
    with tab4:
        st.markdown("#### Transparent Factor-by-Factor Risk Breakdown")
        st.caption("Composite Score = Sum of (Normalized Risk Factor × Assigned Weight)")

        factors = get_field(data, "risk_factors", {})
        
        # Prepare Data Table safely supporting both model objects and dicts
        table_rows = []
        factors_items = factors.items() if hasattr(factors, "items") else []

        for factor_name, f_data in factors_items:
            raw_val = get_field(f_data, "raw_value", 0.0)
            norm_val = get_field(f_data, "normalized_value", 0.0)
            weight_val = get_field(f_data, "weight", 0.0)
            contrib_val = get_field(f_data, "weighted_contribution", 0.0)

            table_rows.append({
                "Risk Dimension": str(factor_name).replace("_", " ").title(),
                "Raw Signal": round(float(raw_val), 4) if isinstance(raw_val, (int, float)) else raw_val,
                "Normalized Risk (0-1)": round(float(norm_val), 4) if isinstance(norm_val, (int, float)) else norm_val,
                "Assigned Weight": round(float(weight_val), 4) if isinstance(weight_val, (int, float)) else weight_val,
                "Weighted Contribution": round(float(contrib_val), 4) if isinstance(contrib_val, (int, float)) else contrib_val
            })
        
        st.dataframe(table_rows, use_container_width=True)

        # Progress bar breakdown per factor
        st.markdown("#### Individual Factor Risk Contributions")
        for factor_name, f_data in factors_items:
            norm_val = get_field(f_data, "normalized_value", 0.0)
            weight_val = get_field(f_data, "weight", 0.0)
            
            norm_float = float(norm_val) if isinstance(norm_val, (int, float)) else 0.0
            norm_float = min(1.0, max(0.0, norm_float))
            weight_float = float(weight_val) if isinstance(weight_val, (int, float)) else 0.0

            st.write(f"**{str(factor_name).replace('_', ' ').title()} Risk** (Weight: {weight_float:.2f})")
            st.progress(norm_float)

    # TAB 5: EXPLANATION
    with tab5:
        st.markdown("#### Explainable Risk Diagnosis")
        st.info(get_field(data, "explanation", "No explanation available."))
        
        st.markdown("""
        **Scoring Transparency Rationale:**
        - **No Black-Box Metrics**: Every component of the composite risk score is derived directly from inspectable repository activity signals and public vulnerability intelligence.
        - **Configurable Weights**: Prototype weights are maintained in configuration and can be tuned during experimentation.
        - **Non-Sensationalist Language**: Results reflect "Known Vulnerability Signals" and repository activity risks rather than absolute security claims.
        """)

    # TAB 6: AUDIT & REPRODUCIBILITY
    with tab6:
        st.markdown("#### Analysis Audit Trail & Reproducibility Record")
        analysis_id = get_field(data, "analysis_id", "N/A")
        scoring_ver = get_field(data, "scoring_version", "v0.1")
        feature_ver = get_field(data, "feature_version", "v0.1")
        ts = get_field(data, "timestamp", "N/A")
        fixture_flag = get_field(data, "is_demo_fixture", False)
        repo_url_val = get_field(repo_info, "url", "N/A")
        final_score = get_field(data, "risk_score", 0.0)
        final_level = get_field(data, "risk_level", "UNKNOWN")

        st.code(f"""
Analysis ID:        {analysis_id}
Scoring Version:    {scoring_ver}
Feature Version:    {feature_ver}
Execution Timestamp:{ts}
Is Demo Fixture:   {fixture_flag}
Repository URL:     {repo_url_val}
Composite Score:    {final_score}
Risk Level:         {final_level}
        """, language="yaml")

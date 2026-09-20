import sys
from pathlib import Path
from datetime import datetime

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

    # Header Row with Mode Badge
    mode_html = '<span class="mode-fixture">DEMO FIXTURE MODE</span>' if data.get("is_demo_fixture") else '<span class="mode-live">LIVE DATA MODE</span>'
    st.markdown(f"### Results for `{data['repository']['owner']}/{data['repository']['name']}` &nbsp; {mode_html}", unsafe_allow_html=True)
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
        
        score = data["risk_score"]
        level = data["risk_level"]

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
            st.info(data["explanation"])

        st.markdown("---")
        st.markdown("#### Primary Signal Metrics")
        m1, m2, m3, m4, m5 = st.columns(5)
        signals = data["repository"].get("signals") or {}
        
        m1.metric("Stars", f"{signals.get('stars', 0):,}")
        m2.metric("Forks", f"{signals.get('forks', 0):,}")
        m3.metric("Contributors", f"{signals.get('contributor_count', 0)}")
        m4.metric("Release Age", f"{signals.get('release_age_days', 'N/A')} days")
        m5.metric("Known Vulns", f"{len(data.get('vulnerabilities', []))}")

    # TAB 2: REPOSITORY OVERVIEW
    with tab2:
        st.markdown("#### Repository Identity & Activity Signals")
        repo_info = data["repository"]
        
        col_a, col_b = st.columns(2)
        with col_a:
            st.write(f"**Repository Name:** `{repo_info['name']}`")
            st.write(f"**Owner:** `{repo_info['owner']}`")
            st.write(f"**URL:** [{repo_info['url']}]({repo_info['url']})")
            st.write(f"**Primary Language:** `{repo_info.get('language') or 'Unknown'}`")
            st.write(f"**License:** `{repo_info.get('license') or 'Unlicensed / Unknown'}`")
            st.write(f"**Archived Status:** `{'Yes (Unmaintained)' if repo_info.get('archived') else 'No (Active)'}`")

        with col_b:
            sig = repo_info.get("signals") or {}
            st.write(f"**Open Issues:** `{sig.get('open_issues', 0)}`")
            st.write(f"**Monthly Commit Frequency:** `{sig.get('commit_frequency_per_month', 0.0)} commits/mo`")
            st.write(f"**Top Contributor Concentration:** `{sig.get('top_contributor_commit_ratio', 0.0) * 100:.1f}%`")
            st.write(f"**Latest Release Tag:** `{sig.get('latest_release_tag') or 'None'}`")
            st.write(f"**Missing Signals Logged:** `{sig.get('missing_fields') or 'None'}`")

    # TAB 3: KNOWN VULNERABILITY SIGNALS
    with tab3:
        st.markdown("#### Known Vulnerability Signals (OSV Intelligence)")
        vulns = data.get("vulnerabilities", [])
        
        if not vulns:
            st.success("No public known vulnerability signals reported for this package.")
        else:
            st.warning(f"Associated with {len(vulns)} known vulnerability signals.")
            for v in vulns:
                with st.expander(f"🔴 {v['vuln_id']} — Severity: {v['severity']} (CVSS {v['cvss_score']})"):
                    st.write(f"**Summary:** {v['summary']}")
                    st.write(f"**Affected Versions:** `{v['affected_versions']}`")
                    st.write(f"**Fixed Versions:** `{v['fixed_versions']}`")
                    st.write(f"**Intelligence Source:** `{v['source']}`")

    # TAB 4: RISK FACTORS & SCORING BREAKDOWN
    with tab4:
        st.markdown("#### Transparent Factor-by-Factor Risk Breakdown")
        st.caption("Composite Score = Sum of (Normalized Risk Factor × Assigned Weight)")

        factors = data.get("risk_factors", {})
        
        # Prepare Data Table
        table_rows = []
        for factor_name, f_data in factors.items():
            table_rows.append({
                "Risk Dimension": factor_name.replace("_", " ").title(),
                "Raw Signal": f_data["raw_value"],
                "Normalized Risk (0-1)": f_data["normalized_value"],
                "Assigned Weight": f_data["weight"],
                "Weighted Contribution": f_data["weighted_contribution"]
            })
        
        st.dataframe(table_rows, use_container_width=True)

        # Progress bar breakdown per factor
        st.markdown("#### Individual Factor Risk Contributions")
        for factor_name, f_data in factors.items():
            norm_val = f_data["normalized_value"]
            st.write(f"**{factor_name.replace('_', ' ').title()} Risk** (Weight: {f_data['weight']:.2f})")
            st.progress(norm_val)

    # TAB 5: EXPLANATION
    with tab5:
        st.markdown("#### Explainable Risk Diagnosis")
        st.info(data["explanation"])
        
        st.markdown("""
        **Scoring Transparency Rationale:**
        - **No Black-Box Metrics**: Every component of the composite risk score is derived directly from inspectable repository activity signals and public vulnerability intelligence.
        - **Configurable Weights**: Prototype weights are maintained in configuration and can be tuned during experimentation.
        - **Non-Sensationalist Language**: Results reflect "Known Vulnerability Signals" and repository activity risks rather than absolute security claims.
        """)

    # TAB 6: AUDIT & REPRODUCIBILITY
    with tab6:
        st.markdown("#### Analysis Audit Trail & Reproducibility Record")
        st.code(f"""
Analysis ID:        {data['analysis_id']}
Scoring Version:    {data['scoring_version']}
Feature Version:    {data['feature_version']}
Execution Timestamp:{data['timestamp']}
Is Demo Fixture:   {data['is_demo_fixture']}
Repository URL:     {data['repository']['url']}
Composite Score:    {data['risk_score']}
Risk Level:         {data['risk_level']}
        """, language="yaml")

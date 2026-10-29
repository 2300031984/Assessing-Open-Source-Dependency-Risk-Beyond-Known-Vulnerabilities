# REQUIREMENTS SPECIFICATION & TRACEABILITY MATRIX

**Project Title:** Assessing Open Source Dependency Risk Beyond Known Vulnerabilities  
**Project ID:** CYBER-100  
**Standard Reference:** ISO/IEC/IEEE 29148:2018 (Systems and software engineering — Life cycle processes — Requirements engineering)  

---

## 1. Project Objectives

- **Objective O1 — Signal Collection**: Automated extraction of repository metadata, activity cadence, contributor concentration, release recency, and public vulnerability signals.
- **Objective O2 — Composite Risk Scoring**: Deterministic, non-blackbox scoring engine combining vulnerability impact with multi-dimensional repository health indicators ($R = \sum w_i f_i$).
- **Objective O3 — Incident Prediction Validation** *(Phase 2 / CP2)*: Empirical validation against historical software supply-chain compromises.
- **Objective O4 — Comparative Evaluation** *(Phase 2 / CP2)*: Benchmarking against traditional vulnerability-count scanners.
- **Objective O5 — Operational Acceptance** *(Phase 2 / CP2)*: Independent usability and impact assessment.

---

## 2. Functional Requirements (FR)

| Req ID | Category | Requirement Description | Implementation Component | Verification Test ID |
| :--- | :--- | :--- | :--- | :--- |
| **FR-01** | Input Validation | The system shall validate GitHub repository URLs, stripping query parameters, fragments, and trailing slashes, rejecting malformed formats. | `GitHubCollector.parse_github_url` | `T01, T02, test_url_validation_*` |
| **FR-02** | Metadata Harvesting | The system shall collect repository identity signals (owner, name, stars, forks, issues, license, archived state). | `GitHubCollector.collect` | `T01, T05, test_url_validation_clean_urls` |
| **FR-03** | Contributor Analysis | The system shall compute total contributor count and top-contributor commit concentration ratio (bus factor risk). | `GitHubCollector._fetch_contributor_stats` | `T05, T08, test_feature_extractor_archived_repository` |
| **FR-04** | Release Cadence | The system shall retrieve latest release tags, release dates, and days elapsed since latest release. | `GitHubCollector._fetch_release_stats` | `T05, T08, test_feature_extractor_active_healthy_repo` |
| **FR-05** | Commit Activity | The system shall measure monthly commit cadence from recent commit history. | `GitHubCollector._fetch_commit_stats` | `T08, test_feature_extractor_active_healthy_repo` |
| **FR-06** | OSV Querying | The system shall query OSV API for published package vulnerabilities mapped by repository primary language. | `OSVCollector.collect` | `T06, test_osv_ecosystem_mapping` |
| **FR-07** | Vuln Deduplication | The system shall deduplicate vulnerability advisories by unique vulnerability ID (`vuln_id`). | `OSVCollector.collect` | `test_osv_deduplication` |
| **FR-08** | Feature Extraction | The system shall extract 6 quantitative raw risk metrics across vulnerability, health, activity, maintainer, release, and governance. | `FeatureExtractor.extract_features` | `T08, test_feature_extractor_*` |
| **FR-09** | Normalization | The system shall map all raw features into strictly bounded $[0.0, 1.0]$ scales using deterministic curves. | `Normalizer.normalize_features` | `T09, test_normalizer_clamping` |
| **FR-10** | Composite Scoring | The system shall calculate composite risk score as a weighted linear combination of normalized factors ($\sum w_i f_i$). | `ScoringEngine.calculate_risk` | `T10, T12, test_t10_risk_calculation_formula` |
| **FR-11** | Classification | The system shall categorize risk scores into `LOW`, `MODERATE`, `HIGH`, or `CRITICAL` based on configurable thresholds. | `RiskClassifier.classify` | `T11, test_classifier_all_boundary_thresholds` |
| **FR-12** | Natural Explanation | The system shall generate transparent, factor-by-factor textual explanations highlighting primary risk contributors. | `ExplanationGenerator.generate_explanation` | `test_explanation_generator_high_risk_breakdown` |
| **FR-13** | Audit Persistence | The system shall store immutable analysis records with a unique Analysis ID in SQLite. | `AnalysisService._persist_analysis` | `T13, test_database_multiple_analyses_same_repo` |
| **FR-14** | REST Endpoints | The system shall expose `/api/v1/analyze`, `/api/v1/analysis/{id}`, `/api/v1/repository/{owner}/{repo}`, and `/api/v1/health`. | `backend/app/api/` | `T14, T15, test_api_endpoints_comprehensive.py` |
| **FR-15** | Interactive Dashboard | The system shall provide an interactive Streamlit UI with dual-mode execution (LIVE vs DEMO FIXTURE) and 6 detailed tabs. | `dashboard/app.py` | `T16, T17, T18, test_dashboard_robustness.py` |

---

## 3. Non-Functional Requirements (NFR)

| Req ID | Category | Requirement Description | Implementation / Verification |
| :--- | :--- | :--- | :--- |
| **NFR-01** | Determinism | Repeated evaluation of identical inputs with identical configuration shall produce identical composite risk scores. | Verified by `T12` (`test_t12_reproducibility_determinism`). |
| **NFR-02** | Response Time | Unit and integration test suite shall execute under 5 seconds locally without external service coupling. | Total test suite runs in ~1.3 seconds (57 tests). |
| **NFR-03** | Resilience | Network timeouts or external API rate limits shall not crash the application or silently produce false zero-risk scores. | Verified by `T04, T07, test_osv_http_error_graceful_handling`. |
| **NFR-04** | Security & Privacy | No API secrets, tokens, or private credentials shall be logged or committed to version control. | Verified via `.gitignore`, `.env.example`, and manual security audit. |
| **NFR-05** | SQL Injection Defense | Database interactions shall strictly use parameterized ORM statements. | Verified across all SQLAlchemy queries in `domain.py` and `analysis_service.py`. |
| **NFR-06** | CORS Hardening | Cross-origin access shall be restricted to specified origins when credentials are enabled. | Implemented via `settings.ALLOWED_ORIGINS` in `main.py`. |
| **NFR-07** | Portability | System shall run on standard Python 3.11+ virtual environments on Windows, Linux, and macOS. | Verified in local Windows PowerShell environment. |
| **NFR-08** | Academic Integrity | Research assumptions, heuristic weights, and prototype boundaries shall be explicitly documented. | Documented in `README.md`, `RISK_MODEL.md`, and dashboard UI. |

---

## 4. Requirement-to-Test Traceability Matrix

| Requirement ID | Pytest Test Identifier | Test Module | Result |
| :--- | :--- | :--- | :---: |
| FR-01 (URL Parsing) | `test_t01_valid_repository_url_parsing`<br>`test_url_validation_*` (11 tests) | `test_collectors.py`<br>`test_url_validation.py` | **PASS** |
| FR-02 (Metadata) | `test_t05_missing_repository_field_record` | `test_collectors.py` | **PASS** |
| FR-03 (Contributors) | `test_feature_extractor_archived_repository` | `test_risk_features_comprehensive.py` | **PASS** |
| FR-04 (Releases) | `test_feature_extractor_active_healthy_repo` | `test_risk_features_comprehensive.py` | **PASS** |
| FR-05 (Commit Cadence) | `test_t08_feature_extraction` | `test_normalization.py` | **PASS** |
| FR-06 (OSV Query) | `test_t06_vulnerability_api_success`<br>`test_osv_ecosystem_mapping` | `test_collectors.py`<br>`test_osv_collector_advanced.py` | **PASS** |
| FR-07 (Vuln Deduplication)| `test_osv_deduplication` | `test_osv_collector_advanced.py` | **PASS** |
| FR-08 (Feature Extractor)| `test_t08_feature_extraction`<br>`test_feature_extractor_*` | `test_normalization.py`<br>`test_risk_features_comprehensive.py` | **PASS** |
| FR-09 (Normalization) | `test_t09_normalization_bounds`<br>`test_normalizer_clamping` | `test_normalization.py`<br>`test_risk_features_comprehensive.py` | **PASS** |
| FR-10 (Scoring Engine) | `test_t10_risk_calculation_formula`<br>`test_t12_reproducibility_determinism` | `test_risk_engine.py`<br>`test_reproducibility.py` | **PASS** |
| FR-11 (Classification) | `test_t11_classification_thresholds`<br>`test_classifier_all_boundary_thresholds`| `test_risk_engine.py`<br>`test_risk_features_comprehensive.py` | **PASS** |
| FR-12 (Explanation) | `test_explanation_generator_high_risk_breakdown` | `test_risk_features_comprehensive.py` | **PASS** |
| FR-13 (Persistence) | `test_t13_database_persistence`<br>`test_database_*` (4 tests) | `test_reproducibility.py`<br>`test_database_advanced.py` | **PASS** |
| FR-14 (REST Endpoints) | `test_t14_api_validation`<br>`test_t15_complete_end_to_end_analysis_flow`<br>`test_api_*` | `test_api.py`<br>`test_api_endpoints_comprehensive.py` | **PASS** |
| FR-15 (Dashboard) | `test_t16_get_field_pydantic_object_access`<br>`test_t17_get_field_dictionary_access`<br>`test_t18_dashboard_service_risk_factor_object_rendering`<br>`test_dashboard_robustness.py` (5 tests) | `test_dashboard_regression.py`<br>`test_dashboard_robustness.py` | **PASS** |

# IMPLEMENTATION STATUS — CYBER-100 (Capstone Review-2 / PDR)

**Project Title:** Assessing Open Source Dependency Risk Beyond Known Vulnerabilities  
**Project ID:** CYBER-100  
**Domain:** Cybersecurity and Blockchain Technology  
**Capstone Stage:** CP1 / Review-2 Working Prototype & PDR Complete  
**Last Updated:** 2026-10-29  

---

## 1. Executive Summary

This document captures the finalized implementation status of the CYBER-100 Capstone Project for Review-2 and the Preliminary Design Review (PDR). It details the verified system architecture, implemented components for CP1, defect remediations, and the roadmap reserved for Phase 2 (CP2).

**Current Completion Status:** **100% of CP1 / Review-2 Scope Implemented, Verified, and Ready for Faculty Review.**

---

## 2. Workspace & Environment Baseline

- **Language & Runtime:** Python 3.11.9
- **Core Frameworks:** FastAPI 0.100+, SQLAlchemy 2.0+, Streamlit 1.25+, Pydantic v2
- **Testing Framework:** Pytest 9.1.1 with `pytest-asyncio`
- **Database Engine:** SQLite 3 with SQLAlchemy ORM and `StaticPool` test isolation
- **Automated Tests:** **57 tests collected, 57 passed (100% pass rate in ~1.2s)**

---

## 3. Functionality Implemented for Review-2 (CP1 Scope)

### Objective O1 — Repository & Vulnerability Signal Collection
- **GitHub Repository Signal Collector (`backend/app/collectors/github_collector.py`)**:
  - Validates and sanitizes repository URLs (strips query parameters, fragments, trailing slashes, caps input length at 512 chars, and rejects reserved GitHub route keywords).
  - Identity signals: Owner, repo name, URL, description, primary language, license SPDX ID, creation date, update date, archived status.
  - Activity signals: Star count, fork count, watchers, open issue count, recent commit frequency, update recency.
  - Maintainer & contributor signals: Total contributor count, top-contributor commit concentration ratio (bus factor risk).
  - Release signals: Latest release tag, release publication date, days since last release, annualized release frequency.
  - Missing signal handling: Records `null`/`unknown` gracefully without failing analysis, logging `missing_fields` (`api_failure`, `rate_limit_exceeded`, `network_error`).
- **OSV Vulnerability Collector (`backend/app/collectors/osv_collector.py`)**:
  - Dynamically maps repository primary language to package ecosystems (Python → PyPI, JavaScript/TypeScript → npm, Rust → crates.io, Go → Go, Ruby → RubyGems, Java → Maven).
  - Queries OSV API for published security advisories.
  - Extracts CVSS score, severity level (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`), affected/fixed version ranges.
  - Automatically deduplicates multiple vulnerability records sharing identical `vuln_id`.
  - Handles network failures, timeouts (via `settings.API_TIMEOUT_SECONDS`), and rate limits gracefully.

### Objective O2 — Composite Risk Assessment Engine
- **Feature Extractor (`backend/app/risk/feature_extractor.py`)**: Extracts raw numerical and categorical signals into 6 structured raw features.
- **Normalizer (`backend/app/risk/normalizer.py`)**: Transforms raw features into normalized risk factors ($0.0 \le f \le 1.0$) using bounded deterministic transformations.
- **Scoring Engine (`backend/app/risk/scoring_engine.py`)**: Computes weighted sum:
  $$\text{Composite Risk Score} = \sum_{i=1}^{6} (w_i \times f_i)$$
- **Classifier (`backend/app/risk/classifier.py`)**: Maps score into configurable tiers: `LOW` (0.00–0.24), `MODERATE` (0.25–0.49), `HIGH` (0.50–0.74), `CRITICAL` (0.75–1.00).
- **Explanation Generator (`backend/app/risk/explanation.py`)**: Generates transparent, factor-by-factor natural language risk justifications.
- **Reproducibility Layer**: Generates reproducible analysis records containing unique `analysis_id` (e.g. `RA-87C164`), `scoring_version` (`v0.1`), feature snapshot, weights, and timestamps.

### Database & API Layer
- **SQLite Database (`backend/app/database/`, `models/domain.py`)**: SQLAlchemy models for `Repository`, `RepositorySignal`, `Vulnerability`, `RiskAssessment`, `RiskFeature`, and `RiskConfiguration` with rollback protection.
- **FastAPI REST API (`backend/app/main.py`, `api/v1/`)**: Endpoints for `/api/v1/analyze`, `/api/v1/analysis/{analysis_id}`, `/api/v1/repository/{owner}/{repo}`, `/api/v1/health`, and root `/`.
- **CORS Hardening**: Enforces explicit trusted origins (`settings.ALLOWED_ORIGINS`).

### Demo Dashboard & Test Suite
- **Streamlit Dashboard (`dashboard/app.py`)**: Interactive UI with dual-mode support (`LIVE DATA` vs `DEMO FIXTURE`), onboarding card, 6 analytical tabs, data quality warnings, and academic disclaimer.
- **Automated Tests (`backend/tests/`)**: 57 automated test cases covering valid/invalid URLs, collector fallbacks, normalization math, scoring determinism, DB persistence, API contracts, dashboard type safety, and E2E flows.

---

## 4. Key Defects Remediated During CP1 Finalization

| Defect ID | Component | Description & Root Cause | Resolution | Verification Test |
| :--- | :--- | :--- | :--- | :--- |
| **DEF-01** | Dashboard | `TypeError: 'RiskFactorBreakdown' object is not subscriptable` when rendering risk factors. | Implemented universal `get_field` helper supporting both attribute and dict key extraction. | `test_t16, test_t17, test_t18` |
| **DEF-02** | REST API | Malformed URLs returned HTTP 404 instead of HTTP 400 Bad Request. | Differentiated syntax errors (400) from resource not found (404) in `analyze.py`. | `test_api_analyze_malformed_github_url_returns_400` |
| **DEF-03** | Collectors | OSV CVSS vector regex matched version number `3.1` instead of metric score `9.8`. | Stripped `CVSS:\d+\.\d+/` version prefix before numeric matching in `osv_collector.py`. | `test_osv_cvss_vector_parsing` |
| **DEF-04** | Testing | In-memory SQLite lost schema across connections during integration tests. | Configured `StaticPool` in `conftest.py` and registered dependency overrides for `get_database`. | `test_api_endpoints_comprehensive.py` |
| **DEF-05** | Dashboard | `top_ratio * 100` threw TypeError when `top_ratio` was None. | Coerced values safely using `float(top_ratio) if isinstance(...) else 0.0`. | `test_dashboard_contributor_ratio_type_safety` |
| **DEF-06** | Database | Database exceptions during persistence could leave transactions uncommitted or open. | Added explicit `try ... except ... self.db.rollback() ... raise` in `_persist_analysis`. | `test_database_rollback_on_persistence_error` |

---

## 5. Functionality Reserved for CP2 (Future Scope)

| Objective | Description | CP1 Status | Target Phase |
| :--- | :--- | :---: | :---: |
| **O3** | Historical Supply-Chain Incident Prediction Validation | Interface Placeholder | CP2 |
| **O4** | Comparative Evaluation against Vulnerability-Count Baselines | Planned | CP2 |
| **O5** | Independent Acceptance & Operational Impact Assessment | Planned | CP2 |
| **Lockfiles** | Multi-Language Transitive Lockfile Dependency Tree Parsing | Out of Scope for CP1 | CP2 |

*Note: No fake accuracy metrics, benchmark claims, or unverified predictions are presented in CP1.*

---

## 6. Architectural Decisions & Quality Attributes

1. **Modular Package Hierarchy**: Decoupled collectors, risk engine, database models, and API endpoints to allow easy swapping of vulnerability providers or scoring models.
2. **Transparent Scoring Configuration**: All risk weights and thresholds reside in `backend/app/risk/config.py` rather than being hardcoded.
3. **Dual Execution Modes**: Support for offline `DEMO FIXTURE` mode using deterministic JSON test fixtures ensures reliable live demonstrations.
4. **Reproducibility Guarantee**: Every analysis is saved with an immutable snapshot of features, weights, and scoring version.
5. **Fault Isolation**: Network outages or rate limits are treated as degraded signals rather than application crashes.

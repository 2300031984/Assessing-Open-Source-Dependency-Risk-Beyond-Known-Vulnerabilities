# IMPLEMENTATION STATUS — CYBER-100 (Review-2 CP1 Prototype)

**Project Title:** Assessing Open Source Dependency Risk Beyond Known Vulnerabilities  
**Project ID:** CYBER-100  
**Domain:** Cybersecurity and Blockchain Technology  
**Capstone Stage:** CP1 / Review-2 Partial Working Prototype  

---

## 1. Executive Summary

This document captures the implementation status of the CYBER-100 Capstone Project for Review-2. It details the existing project baseline, implemented components for CP1, architectural decisions, and the roadmap reserved for Phase 2 (CP2).

---

## 2. Existing Workspace Baseline

- **Initial Workspace State**: Clean baseline repo.
- **Existing Source Code**: None prior to this implementation step.
- **Existing Database**: None.
- **Dependencies & Tools**: Standard Python 3.11 environment with FastAPI, SQLAlchemy 2.0, Streamlit, Pytest, and Pydantic v2.

---

## 3. Functionality Implemented for Review-2 (CP1 Scope)

### Objective O1 — Repository & Vulnerability Signal Collection
- **GitHub Repository Signal Collector (`backend/app/collectors/github_collector.py`)**:
  - Identity signals: Owner, repo name, URL, description, primary language, license, creation date, update date, archived status.
  - Activity signals: Star count, fork count, watchers, open issue count, recent commit frequency, update recency.
  - Maintainer & contributor signals: Total contributor count, top-contributor commit concentration ratio.
  - Release signals: Latest release tag, release publication date, days since last release, release frequency.
  - Missing signal handling: Records `null`/`unknown` gracefully without failing analysis.
- **OSV Vulnerability Collector (`backend/app/collectors/osv_collector.py`)**:
  - Queries OSV API for ecosystem vulnerabilities linked to repository dependencies.
  - Extracts CVSS score, severity level, affected/fixed versions, and tags results as "Known vulnerability signals".
  - Handles network failures, timeouts, and rate limits gracefully.

### Objective O2 — Composite Risk Assessment Engine
- **Feature Extractor (`backend/app/risk/feature_extractor.py`)**: Extracts raw numerical and categorical signals into structured raw features.
- **Normalizer (`backend/app/risk/normalizer.py`)**: Transforms raw features into normalized risk factors ($0.0 \le f \le 1.0$) using min-max and non-linear sigmoid transformations.
- **Scoring Engine (`backend/app/risk/scoring_engine.py`)**: Computes weighted sum:
  $$\text{Composite Risk Score} = \sum_{i} (w_i \times f_i)$$
- **Classifier (`backend/app/risk/classifier.py`)**: Maps score into configurable tiers: `LOW` (0.00–0.24), `MODERATE` (0.25–0.49), `HIGH` (0.50–0.74), `CRITICAL` (0.75–1.00).
- **Explanation Generator (`backend/app/risk/explanation.py`)**: Generates transparent, factor-by-factor natural language risk justifications.
- **Reproducibility Layer**: Generates reproducible analysis records containing unique `analysis_id` (e.g. `RA-000001`), `scoring_version` (`v0.1`), feature snapshot, weights, and timestamps.

### Database & API Layer
- **SQLite Database (`backend/app/database/`, `models/domain.py`)**: SQLAlchemy models for `Repository`, `RepositorySignal`, `Vulnerability`, `RiskAssessment`, `RiskFeature`, and `RiskConfiguration`.
- **FastAPI REST API (`backend/app/main.py`, `api/v1/`)**: Endpoints for `/api/v1/analyze`, `/api/v1/analysis/{analysis_id}`, `/api/v1/repository/{owner}/{repo}`, and `/api/v1/health`.

### Demo Dashboard & Test Suite
- **Streamlit Dashboard (`dashboard/app.py`)**: Interactive UI with dual-mode support (`LIVE DATA` vs `DEMO FIXTURE`).
- **Automated Tests (`backend/tests/`)**: 15 automated test cases (`T01`–`T15`) covering valid/invalid URLs, collector fallbacks, normalization math, scoring determinism, DB persistence, API contracts, and E2E flows.

---

## 4. Functionality Reserved for CP2 (Future Scope)

| Objective | Description | CP1 Status | Target Phase |
| :--- | :--- | :--- | :--- |
| **O3** | Historical Supply-Chain Incident Prediction Validation | Interface Placeholder | CP2 |
| **O4** | Comparative Evaluation against Vulnerability-Count Baselines | Planned | CP2 |
| **O5** | Independent Acceptance & Operational Impact Assessment | Planned | CP2 |

*Note: No fake accuracy metrics or unverified predictions are presented in CP1.*

---

## 5. Architectural Decisions

1. **Modular Package Hierarchy**: Decoupled collectors, risk engine, database models, and API endpoints to allow easy swapping of vulnerability providers or scoring models.
2. **Transparent Scoring Configuration**: All risk weights and thresholds reside in `backend/app/risk/config.py` rather than being hardcoded.
3. **Dual Execution Modes**: Support for offline `DEMO FIXTURE` mode using deterministic JSON test fixtures ensures reliable live demonstrations.
4. **Reproducibility Guarantee**: Every analysis is saved with a immutable snapshot of features, weights, and scoring version.

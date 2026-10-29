# PRELIMINARY DESIGN REVIEW (PDR) PRESENTATION SPECIFICATION

**Project Title:** Assessing Open Source Dependency Risk Beyond Known Vulnerabilities  
**Project ID:** CYBER-100  
**Domain:** Cybersecurity & Software Supply Chain Security  
**Milestone:** Capstone Preliminary Design Review (PDR)  

---

## Slide 1: Title & Project Identity
- **Slide Title:** Assessing Open Source Dependency Risk Beyond Known Vulnerabilities
- **Sub-Title:** A Transparent, Multi-Dimensional Risk Assessment Engine for Software Supply Chains
- **Project Identifier:** CYBER-100 (Department of Cybersecurity and Blockchain Technology, KL University)
- **Team Details:** [Student Names & Roll Numbers Placeholder]
- **Faculty Guide / Supervisor:** [Supervisor Name & Designation Placeholder]
- **Evaluation Milestone:** Review-2 / Preliminary Design Review (PDR)

---

## Slide 2: Problem Statement
- **Core Problem:** Modern applications are built on thousands of open-source components. Current security scanners evaluate third-party dependencies exclusively by matching installed versions against known vulnerability databases (e.g., CVE, NVD, OSV).
- **The Critical Blindspot:**
  - Known CVEs are **lagging indicators**; vulnerabilities are cataloged only after discovery and public disclosure.
  - Latent governance hazards—unannounced project abandonment, bus factor of 1, abrupt cessation of commits, and licensing ambiguity—precede real-world supply chain compromises.
  - Unmaintained dependencies with zero reported CVEs are dangerously classified as "zero risk" by conventional scanners.

---

## Slide 3: Motivation & Research Gap
- **High-Profile Catalysts:**
  - *event-stream* (2018): Abandoned repository handed over to a malicious maintainer who injected cryptocurrency-stealing payloads.
  - *ua-parser-js* (2021): Account takeover of a single maintainer account leading to credential-stealing trojans.
  - *xz-utils* (2024): Multi-year social engineering targeting an isolated, burnt-out single maintainer to introduce a sophisticated backdoor.
- **Identified Research Gap:** Lack of accessible, transparent, reproducible frameworks that synthesize real-time repository health signals, contributor concentration, and release recency into a unified composite metric alongside published CVE data.

---

## Slide 4: Objectives & Scope
- **Current CP1 Prototype Objectives (Completed & Review-Ready):**
  - **Objective O1 — Signal Collection:** Automated extraction of repository activity, maintainer concentration, commit cadence, release governance, and OSV known vulnerability intelligence.
  - **Objective O2 — Composite Risk Scoring:** Transparent, non-blackbox scoring engine calculating a bounded Composite Risk Score ($0.00 \le R \le 1.00$) with natural language explanations.
- **Phase 2 Scope (CP2 Roadmap):**
  - **Objective O3:** Empirical validation against historical supply-chain incident datasets.
  - **Objective O4:** Comparative evaluation against traditional vulnerability-count baselines.
  - **Objective O5:** Operational impact benchmarking.

---

## Slide 5: Existing Approaches & Limitations
- **Approach 1: Vulnerability Scanners (e.g., Snyk, Dependabot, OSV-Scanner)**
  - *Limitation:* Evaluate only known CVEs. Incapable of detecting maintainer burnout, abandonment, or bus factor risks before an exploit is published.
- **Approach 2: Complex Machine Learning Classifiers**
  - *Limitation:* Black-box prediction models lacking explainability, requiring opaque training sets, and difficult to audit or tune in enterprise procurement.
- **CYBER-100 Value Proposition:** Deterministic, fully transparent, rule-based composite scoring engine with factor-by-factor explainability and reproducible audit trails.

---

## Slide 6: Proposed System Overview
- **Modular Pipeline:**
  1. Strict URL validation and sanitization.
  2. Multi-source signal harvesting (GitHub REST API + OSV API).
  3. Feature extraction across 6 quantitative dimensions.
  4. Non-linear normalization into bounded $[0.0, 1.0]$ scales.
  5. Weighted composite linear scoring ($R = \sum w_i f_i$).
  6. Transparent classification into 4 tiers (`LOW`, `MODERATE`, `HIGH`, `CRITICAL`).
  7. Automated natural-language diagnosis generation.
  8. Immutable persistence in SQLite database.
  9. Interactive visualization via FastAPI and Streamlit dashboard.

---

## Slide 7: System Architecture Diagram
- **Visual Asset:** Include the Mermaid architecture diagram from `docs/ARCHITECTURE.md`.
- **Key Talking Points:**
  - Clean separation between Collectors, Risk Engine, Persistence, and Presentation.
  - Dual execution modes: Real-time **LIVE DATA** vs Deterministic **DEMO FIXTURE** (offline resilience).
  - Explicit fault boundaries: Network failures or rate limits do not crash the system.

---

## Slide 8: Data Collection Methodology
- **GitHub API Collector:**
  - Extracts 12 raw signals: stars, forks, watchers, open issues, commit frequency, contributor count, top contributor commit ratio, latest release tag, release age in days, annualized release frequency, license SPDX, and archive flag.
  - Defensive error handling: Appends `missing_fields` (`rate_limit_exceeded`, `api_failure`, `network_error`) without silent failure.
- **OSV Intelligence Collector:**
  - Maps detected programming language to standard package ecosystem (Python → PyPI, JS → npm, Rust → crates.io, etc.).
  - Extracts CVSS scores and severity labels (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
  - Automatic deduplication of advisories by `vuln_id`.

---

## Slide 9: Feature Extraction & Normalization
- **Feature 1: Known Vulnerabilities ($f_{\text{vuln}}$):** $\min(1.0, (\text{CVSS}_{\text{max}} + 0.5 \cdot N_{\text{vuln}}) / 10.0)$.
- **Feature 2: Repository Health ($f_{\text{health}}$):** $\min(1.0, (\text{IssueRatio} \cdot 5.0 + 3.0 \cdot \mathbf{1}_{\text{archived}} + 0.5 \cdot N_{\text{missing}}) / 5.0)$.
- **Feature 3: Commit Cadence ($f_{\text{activity}}$):** $\min(1.0, \max(0.0, 30.0 - C_{\text{month}}) / 30.0)$.
- **Feature 4: Maintainer Concentration ($f_{\text{maintainer}}$):** $1.0 \text{ if } N_{\text{contrib}} \le 1 \text{ else } \text{TopRatio}$.
- **Feature 5: Release Recency ($f_{\text{release}}$):** $\min(1.0, D_{\text{release}} / 730.0)$.
- **Feature 6: Governance / License ($f_{\text{dep}}$):** Permissive (0.0), Copyleft (0.3), Missing License (0.8), Archived (+0.5).

---

## Slide 10: Risk Scoring & Classification Methodology
- **Scoring Formula:**
  $$\text{Composite Risk Score } R = 0.30 f_{\text{vuln}} + 0.20 f_{\text{health}} + 0.15 f_{\text{activity}} + 0.15 f_{\text{maintainer}} + 0.10 f_{\text{release}} + 0.10 f_{\text{gov}}$$
- **Heuristic Clarification:** Weights are rule-based heuristic baselines designed for demonstration, faculty inspection, and configurable tuning in `risk/config.py`.
- **Classification Tiers:**
  - `0.00 – 0.24`: **LOW** (Safe to depend on with standard review)
  - `0.25 – 0.49`: **MODERATE** (Acceptable; review release and maintainer alerts)
  - `0.50 – 0.74`: **HIGH** (Noticeable maintainer stagnation or single maintainer risk)
  - `0.75 – 1.00`: **CRITICAL** (Severe vulnerability alerts or complete abandonment)

---

## Slide 11: Implementation Status
- **Current Completion State:** 100% of CP1 / Review-2 planned deliverables implemented, tested, and operational.
- **Components Built & Verified:**
  - FastAPI backend with 4 REST endpoints (`/api/v1/analyze`, `/api/v1/analysis/{id}`, `/api/v1/repository/{owner}/{repo}`, `/api/v1/health`).
  - SQLite database with 6 domain models and transactional rollback protection.
  - Streamlit dashboard with 6 analytical tabs, dual execution modes, and data warning banners.
  - Automated test suite with 57 verified tests.

---

## Slide 12: Testing Strategy & Empirical Results
- **Test Framework:** Pytest 9.1.1 on Python 3.11.9.
- **Coverage Summary:**
  - 57 automated tests across 8 test suites.
  - 100% pass rate (0 failures, 0 skipped) in ~1.31 seconds execution time.
- **Verified Coverage Areas (Phases A through P):**
  - URL sanitization & validation (13 tests).
  - External collector fallbacks, rate limits, and timeouts (8 tests).
  - Feature extraction and bounded normalization (8 tests).
  - Scoring determinism & classification boundary thresholds (4 tests).
  - Database persistence, cascading, and rollback safety (5 tests).
  - REST API contracts, status codes (400, 404, 500) (7 tests).
  - Dashboard type safety and regression prevention (12 tests).

---

## Slide 13: Live Demonstration Sequence
- **Step 1:** System Startup: Launch FastAPI backend on port 8000 and Streamlit dashboard on port 8501.
- **Step 2:** Demo Fixture Execution: Analyze `https://github.com/demo-owner/sample-crypto-lib` in offline fixture mode.
  - Composite Score: **0.55 (HIGH)**.
  - Transparent breakdown: High maintainer concentration (82%), release age (315 days), CVSS 7.5 vulnerability.
- **Step 3:** Live Repository Execution: Analyze `https://github.com/psf/requests` in live API mode.
  - Shows real-time metadata, contributor statistics, and zero active critical OSV alerts.
- **Step 4:** Negative Testing: Submit malformed URL (`https://github.com/invalid/`) → Displays clean HTTP 400 validation error.

---

## Slide 14: Security, Privacy & Standards Compliance
- **Defensive Engineering:**
  - Zero hardcoded secrets; tokens stored in `.env` excluded from version control.
  - Input sanitization preventing path traversal and injection.
  - SQLAlchemy parameterized ORM preventing SQL injection.
  - CORS hardened with explicit `ALLOWED_ORIGINS`.
- **Standards Guidance:**
  - ISO/IEC/IEEE 29148 (Requirements Traceability).
  - ISO/IEC/IEEE 42010 (Architecture Description).
  - ISO/IEC 25010 (Software Product Quality).
  - OWASP Top 10 Security Controls.

---

## Slide 15: Current Limitations
1. **Repository-Level vs Lockfile Scope:** Current prototype assesses the repository as a package entity. Scanning full transitive lockfile trees (`package-lock.json`, `Cargo.lock`) is reserved for Phase 2.
2. **Heuristic Weighting:** Current weights are rule-based and configurable; they do not represent statistical probability of compromise.
3. **API Rate Limiting:** Unauthenticated GitHub API calls are subject to GitHub's 60 req/hr ceiling.

---

## Slide 16: Phase 2 (CP2) Roadmap
- **O3 Incident Benchmark Validation:** Validate scoring accuracy against known historical supply-chain incident repositories.
- **O4 Comparative Evaluation:** Compare CYBER-100 risk warnings against traditional CVE-only scanners to prove predictive lead time.
- **O5 Operational Impact:** Evaluate false positive rates and developer friction.
- **Lockfile Graph Parser:** Implement multi-language dependency tree parsing for Python, Node.js, and Rust lockfiles.

---

## Slide 17: Conclusion & Q&A
- **Summary:** CYBER-100 proves that holistic repository activity, maintainer concentration, and governance signals can be successfully synthesized with public CVEs into an explainable, reproducible, and verifiable supply-chain risk engine.
- **Artifacts Ready for Review:**
  - Live Streamlit Dashboard (`http://localhost:8501`)
  - Live OpenAPI Swagger Docs (`http://localhost:8000/docs`)
  - 57 Passing Automated Unit & Integration Tests
  - Comprehensive Technical Documentation (`docs/`)
- **Thank You:** Open for Faculty Questions and Evaluator Feedback.

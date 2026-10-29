# CAPSTONE RESEARCH DIARY ENTRIES (WEEKS 13–15)

**Project Title:** Assessing Open Source Dependency Risk Beyond Known Vulnerabilities  
**Project ID:** CYBER-100  
**Phase:** Phase 5 — System Integration, Verification & PDR Preparation  
**Student Team Details:** [Team Member Names & IDs Placeholder]  
**Supervisor / Guide:** [Guide Name & Designation Placeholder]  

---

## Section 5.1 — Initial Integration

| Subsystems Involved | Integration Objective | Actual Result | Issues Identified & Resolved |
| :--- | :--- | :--- | :--- |
| **Collectors (O1) + Risk Engine (O2)** | Connect GitHub/OSV harvested signal dictionaries to Feature Extractor and Normalizer. | Feature extractor correctly derived 6 quantitative metrics; normalizer bounded factors into $[0.0, 1.0]$. | OSV response initially collided on CVSS vector version string (CVSS:3.1); regex fixed to isolate metric score. |
| **Risk Engine (O2) + Persistence Layer** | Store composite risk scores, factor breakdowns, and signals in SQLite via SQLAlchemy. | Assessments persisted with unique IDs (`RA-XXXXXX`); audit snapshots saved and retrievable via foreign keys. | SQLite in-memory test engine lost schema between connections; resolved with `StaticPool` in testing fixtures. |
| **Backend REST API + Service Layer** | Expose FastAPI endpoints (`/analyze`, `/analysis/{id}`, `/repository/{owner}/{repo}`) backed by `AnalysisService`. | Synchronous POST and GET requests executed successfully with JSON schema validation. | Malformed URLs previously raised ValueError mapped incorrectly to 404; updated to return HTTP 400 Bad Request. |
| **Service Layer + Streamlit Dashboard** | Deliver real-time signal inspection and offline demo execution via Streamlit UI. | Interactive 6-tab dashboard displayed executive metrics, tables, warning banners, and audit YAML. | `TypeError` on `RiskFactorBreakdown` subscripting resolved using universal `get_field` attribute/dict helper. |

---

## Section 5.2 — Standards and Compliance

| Standard / Protocol | Relevance to Subsystem | Compliance Step / Evidence Produced | Actual Status |
| :--- | :--- | :--- | :---: |
| **ISO/IEC/IEEE 29148:2018** | Requirements engineering and verification traceability. | Formalized FR-01 to FR-15 and NFR-01 to NFR-08 with bidirectional traceability matrix mapped to 57 Pytest tests. | **Compliant in Scope** |
| **ISO/IEC/IEEE 42010:2011** | Architectural description and viewpoint clarity. | Produced `docs/ARCHITECTURE.md` with complete Mermaid data flow, subsystem breakdown, and schema diagrams. | **Compliant in Scope** |
| **ISO/IEC 25010:2011** | Software product quality and reliability evaluation. | Automated test suite verifying calculation determinism, graceful API timeout degradation, and input sanitization. | **Compliant in Scope** |
| **ISO/IEC 27001:2022** | Defensive secret management and error confidentiality. | Configured `.env` exclusion in `.gitignore`; zero hardcoded credentials; suppressed internal stack traces in API errors. | **Aligned with Best Practices** |
| **OWASP Top 10** | Prevention of injection and access misconfiguration. | Parameterized SQLAlchemy ORM queries; strict regex URL validation; explicit origin CORS configuration. | **Aligned with Best Practices** |

---

## Section 5.3 — Ethics, Privacy, IP, and Academic Integrity Declaration

### 1. Ethical & Privacy Considerations
Signal collection is strictly restricted to public repository metadata and public vulnerability advisories. The application does not collect private email addresses, full real names, or private communications. No active vulnerability scanning, exploit probing, or intrusion testing is performed against third-party systems.

### 2. Data Sources & Licensing
Repository signals are retrieved from the GitHub REST API v3 in accordance with its usage policies. Known vulnerability data is retrieved from the Open Source Vulnerabilities (OSV) API (`https://osv.dev`). All underlying software libraries (FastAPI, SQLAlchemy, Streamlit, Pydantic, Requests, Pytest) are used under their respective permissive MIT and Apache 2.0 open-source licenses.

### 3. Truthful Disclosure of AI Assistance
In compliance with university academic integrity requirements, the team truthfully discloses the use of an AI coding assistant (Antigravity) during Weeks 13–15 for:
- Investigating and resolving the Streamlit dashboard `TypeError` using the `get_field` helper.
- Designing and expanding automated test coverage from 18 to 57 test cases across Areas A through P.
- Refactoring URL validation regex, OSV CVSS vector parsing, and SQLite `StaticPool` session isolation.
- Formatting structured documentation artifacts (Architecture, Requirements Traceability, Standards, and PDR Outline).
All generated code, mathematical calculations, and test suites were independently executed, inspected, and verified in the project's local Python virtual environment. No test findings or vulnerability data were fabricated.

### 4. Team Declaration
- **Declaration:** We certify that the implementation, documentation, and test evidence presented in this diary reflect actual engineering work undertaken for CYBER-100.
- **Signatures:** [To be signed physically by team members; no AI signature applied]

---

## Weekly Research Diary Logs

### Week 13: Subsystem Integration & Bug Remediation
- **Dates:** [Week 13 Dates Placeholder, e.g., 2026-10-06 to 2026-10-12]
- **Planned Agenda:** Integrate collectors with the composite scoring engine; connect backend to Streamlit UI; resolve dashboard rendering issues.
- **Member Name & Student ID:** [Student Name / ID Placeholder]
- **Tasks Undertaken:**
  - Audited existing codebase and verified Review-2 prototype baseline.
  - Investigated Streamlit dashboard `TypeError` during risk factor rendering.
  - Implemented safe `get_field` utility in `dashboard/app.py` supporting both Pydantic model attributes and dictionary keys.
  - Added regression test cases `T16`, `T17`, and `T18` in `backend/tests/unit/test_dashboard_regression.py`.
- **Actual Progress:** 100% of integration agenda completed.
- **Challenges & Resolutions:** `TypeError: 'RiskFactorBreakdown' object is not subscriptable` was resolved by replacing raw dictionary indexing with `get_field`.
- **Evidence Produced:** Passing regression test execution logs; functional Streamlit table rendering.
- **Guide Feedback:** [Guide Comments Placeholder]
- **Action Plan for Next Week:** Expand automated test coverage to include edge cases, external API fallbacks, and database transaction safety.
- **Member-Wise Contribution:** [Member Contributions Placeholder]

---

### Week 14: Quality Assurance, Security Hardening & Compliance
- **Dates:** [Week 14 Dates Placeholder, e.g., 2026-10-13 to 2026-10-19]
- **Planned Agenda:** Perform defensive security review, expand automated test coverage across Areas A–P, and conduct standards alignment.
- **Member Name & Student ID:** [Student Name / ID Placeholder]
- **Tasks Undertaken:**
  - Hardened URL parser with query parameter stripping, fragment removal, length caps, and reserved route checks.
  - Enhanced OSV collector with advisory deduplication by `vuln_id` and language-to-ecosystem dynamic mapping.
  - Added rollback transaction protection (`db.rollback()`) to `AnalysisService._persist_analysis`.
  - Configured CORS middleware with explicit `ALLOWED_ORIGINS` in `main.py`.
  - Added unit test suites for URL validation, OSV collector, comprehensive risk features, database operations, and dashboard robustness.
- **Actual Progress:** Test suite expanded from 18 to 57 automated tests; 100% pass rate achieved.
- **Challenges & Resolutions:**
  - Malformed URLs returned HTTP 404 instead of 400; resolved in `analyze.py` exception mapping.
  - OSV CVSS vector regex matched version `3.1`; resolved by stripping CVSS version prefix before number matching.
  - SQLite in-memory test database lost schema across connections; resolved using `StaticPool` in `conftest.py`.
- **Evidence Produced:** `docs/TEST_RESULTS.md` with 57 verified tests; `docs/STANDARDS_COMPLIANCE.md`.
- **Guide Feedback:** [Guide Comments Placeholder]
- **Action Plan for Next Week:** Prepare PDR presentation materials, finalize demonstration scripts, and verify setup reproducibility.
- **Member-Wise Contribution:** [Member Contributions Placeholder]

---

### Week 15: Final Validation, PDR Preparation & Demonstration
- **Dates:** [Week 15 Dates Placeholder, e.g., 2026-10-20 to 2026-10-26]
- **Planned Agenda:** Validate full end-to-end reproducible execution, prepare PDR slide outline, and finalize academic documentation.
- **Member Name & Student ID:** [Student Name / ID Placeholder]
- **Tasks Undertaken:**
  - Tested dual execution modes: verified offline **DEMO FIXTURE** mode and real-time **LIVE DATA** mode.
  - Added empty-state onboarding card, data quality warning banners, and academic disclaimers to Streamlit dashboard.
  - Documented complete architecture with Mermaid diagram in `docs/ARCHITECTURE.md`.
  - Formulated functional/non-functional requirements and bidirectional traceability matrix in `docs/REQUIREMENTS.md`.
  - Updated `README.md` with step-by-step reproduction instructions and API contract examples.
  - Prepared 17-slide Preliminary Design Review outline in `docs/PDR_PRESENTATION_OUTLINE.md`.
- **Actual Progress:** System fully demonstrable, reproducible, and ready for PDR evaluation.
- **Challenges & Resolutions:** Ensuring clean separation between confirmed vulnerability signals and heuristic repository indicators; clearly labeled in UI tabs and documentation.
- **Evidence Produced:** `docs/PDR_PRESENTATION_OUTLINE.md`, `docs/ARCHITECTURE.md`, `README.md`, passing test run of 57 tests.
- **Guide Feedback:** [Guide Comments Placeholder]
- **Action Plan for Next Phase (CP2):** Execute Phase 2 objectives (O3 incident validation, O4 comparative benchmarking, lockfile parsing).
- **Member-Wise Contribution:** [Member Contributions Placeholder]

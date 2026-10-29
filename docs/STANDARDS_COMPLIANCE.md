# STANDARDS, COMPLIANCE & RESEARCH GOVERNANCE SPECIFICATION

**Project Title:** Assessing Open Source Dependency Risk Beyond Known Vulnerabilities  
**Project ID:** CYBER-100  
**Capstone Stage:** Engineering Capstone & Preliminary Design Review (PDR)  

---

## 1. Compliance Disclaimer

> [!IMPORTANT]
> **Academic Compliance Statement:** This project implements selected engineering best practices, security controls, and architectural conventions informed by the standards listed below. CYBER-100 does **not** claim formal commercial certification or third-party audit compliance under ISO, IEEE, or OWASP programs.

---

## 2. Standards Review & Compliance Checklist

| Standard / Guidance | Relevance to CYBER-100 | Applicable Practice / Requirement | Project Evidence Available | Status | Remaining Action (CP2) |
| :--- | :--- | :--- | :--- | :---: | :--- |
| **ISO/IEC/IEEE 29148:2018** *(Requirements Engineering)* | High: Guides functional and non-functional requirements formalization and bidirectional verification. | Unambiguous requirement definitions, unique identifiers, and bidirectional requirements-to-test traceability. | `docs/REQUIREMENTS.md` containing FR-01 through FR-15, NFR-01 through NFR-08, and traceability matrix to 57 Pytest tests. | **Compliant in Scope** | Expand requirements for lockfile parsing in Phase 2. |
| **ISO/IEC/IEEE 42010:2011** *(Architecture Description)* | High: Governs transparent representation of software architecture, viewpoints, and data flows. | Component diagrams, explicit data flow pipelines, module responsibility definitions, and interface specifications. | `docs/ARCHITECTURE.md` with Mermaid diagram, subsystem descriptions, data contracts, and schema diagrams. | **Compliant in Scope** | Document distributed queue architecture if scaled in CP2. |
| **ISO/IEC 25010:2011** *(Systems and Software Quality Requirements and Evaluation — SQuaRE)* | High: Evaluates software product quality characteristics (functional suitability, reliability, security, maintainability). | Determinism of calculation, fault tolerance against external API outages, input sanitization, test coverage. | 57 automated tests running in 1.3s with zero failures; offline fixture mode; structured logging. | **Compliant in Scope** | Add load and stress testing under high concurrency. |
| **ISO/IEC 27001:2022** *(Information Security Management)* | Moderate: Establishes defensive practices for credential management, access boundaries, and vulnerability logging. | Never exposing tokens or secrets; isolating local credentials from version control; defensive error handling. | `.gitignore` excluding `.env`, `.env.example` with placeholders; zero committed keys; no stack trace exposure. | **Aligned with Best Practices** | Add rate-limiting middleware for production deployment. |
| **OWASP Top 10 & API Security Guidance** | High: Prevents injection, broken access, security misconfiguration, and excessive data exposure. | Parameterized queries (preventing SQLi); URL validation & length caps; CORS restriction; exception suppression. | SQLAlchemy ORM parameterized queries; regex URL sanitization; `ALLOWED_ORIGINS` CORS; custom exception handling. | **Aligned with Best Practices** | Add Content Security Policy (CSP) headers in reverse proxy. |
| **GitHub REST API Terms of Service** | High: Regulates interaction with GitHub API resources and rate limiting. | Respecting rate limits; user-agent identification; caching/avoiding redundant polling; public data only. | Custom `User-Agent: CYBER-100-Risk-Collector/1.0`; timeout controls; explicit `rate_limit_exceeded` fallback. | **Compliant** | Implement Redis caching layer to minimize request volume. |
| **OSV.dev API Usage Terms** | High: Regulates querying of open-source vulnerability intelligence. | Batch querying, respecting timeouts, attributing OSV as intelligence source in UI and documentation. | `OSVCollector` queries; explicit attribution in Streamlit Tab 3; deduplication of advisory entries. | **Compliant** | Support local OSV zip database dumps for fully offline scanning. |
| **Academic Integrity & AI Assistance** | High: Ensures intellectual honesty, third-party code attribution, and transparency of AI assistance. | Truthful attribution of libraries; disclosure of AI coding assistance; avoiding fabricated metrics. | Section 3 of this document; `docs/RESEARCH_DIARY_WEEKS_13_15.md`; zero fabricated test data. | **Fully Disclosed** | Complete formal capstone supervisor sign-off. |

---

## 3. Ethics, Privacy, Intellectual Property & Academic Integrity Declaration

### 3.1 Ethical Considerations & Privacy
- **Public Data Only:** The system interacts solely with public GitHub repositories and public vulnerability databases (OSV/CVE). It does not access private repositories, private organizations, or personal private data.
- **Minimization of Personal Information:** The application does not collect, harvest, or persist developers' email addresses, full real names, or personal communication. Contributor analysis is based strictly on public commit counts and anonymized GitHub logins.
- **No Active Scanning or Exploitation:** CYBER-100 performs passive metadata and intelligence correlation only. It performs **no** dynamic vulnerability scanning, port scanning, exploitation, fuzzing, or intrusive probing of remote servers.

### 3.2 Intellectual Property & Third-Party Code Attribution
- The project is built using standard, widely accepted open-source components under permissive licenses:
  - **FastAPI** (MIT License) — Sebastián Ramírez
  - **SQLAlchemy** (MIT License) — Michael Bayer
  - **Streamlit** (Apache 2.0 License) — Snowflake Inc.
  - **Pydantic** (MIT License) — Samuel Colvin
  - **Requests** (Apache 2.0 License) — Kenneth Reitz & PSF
  - **Pytest** (MIT License) — Holger Krekel and pytest development team
- All third-party libraries are declared in `requirements.txt` and preserved without license violation.

### 3.3 Data Provenance
- Vulnerability intelligence is sourced directly from **Open Source Vulnerabilities (OSV)** (`https://osv.dev`), an open-source initiative by Google and the OpenSSF.
- Repository signals are retrieved directly from the **GitHub REST API v3**.
- Demo fixtures represent synthetic and real-world public test fixtures clearly labeled as demonstration artifacts in `backend/tests/fixtures/`.

### 3.4 Disclosure of AI Assistance
In compliance with academic integrity guidelines, the team explicitly discloses the use of AI assistance (Antigravity AI coding assistant) during Capstone Phase 1 (Weeks 13–15) for:
- Codebase auditing and refactoring assistance.
- Resolving the Streamlit dashboard `RiskFactorBreakdown` TypeError using the `get_field` helper.
- Expanding automated test coverage from 18 to 57 test cases across Areas A through P.
- Drafting documentation templates, standards checklists, and PDR presentation outlines.
- All code logic, mathematical formulas, and architectural decisions have been inspected, executed, tested, and verified directly in the local environment. No test results or metrics were fabricated.

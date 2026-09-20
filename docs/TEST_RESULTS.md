# AUTOMATED TEST RESULTS REPORT — CYBER-100 (Review-2 CP1)

**Project Title:** Assessing Open Source Dependency Risk Beyond Known Vulnerabilities  
**Project ID:** CYBER-100  
**Test Framework:** Pytest 9.1.1 (Python 3.11)  
**Execution Timestamp:** 2026-09-20  
**Total Tests:** 15  
**Passed:** 15  
**Failed:** 0  
**Execution Time:** 0.20s  

---

## Summary Matrix

| Test ID | Module / Area | Test Description | Input / Condition | Expected Result | Observed Result | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :---: |
| **T01** | Collectors | GitHub URL parsing | `https://github.com/psf/requests` | Owner: `psf`, Repo: `requests` | Owner: `psf`, Repo: `requests` | **PASS** |
| **T02** | Collectors | Invalid URL handling | `https://invalid-site.com/not-github` | `ValueError` raised | `ValueError` raised | **PASS** |
| **T03** | Collectors | Repo not found (404) | Non-existent repo URL | `ValueError` stating not found | `ValueError` stating not found | **PASS** |
| **T04** | Collectors | GitHub API failure | HTTP 500 API response | Record missing signal, no crash | Recorded `api_failure` in missing fields | **PASS** |
| **T05** | Collectors | Missing fields log | Repo response lacking license | Log `license` in missing fields | `license` logged in missing fields list | **PASS** |
| **T06** | Collectors | OSV API query success | Package `requests` query | Extract CVSS score and severity label | CVSS `7.8`, Severity `HIGH` extracted | **PASS** |
| **T07** | Collectors | OSV API timeout/failure | Network timeout exception | Graceful fallback returning empty list | Returned `[]` gracefully without crash | **PASS** |
| **T08** | Risk Engine | Feature extraction | Raw signal dictionary | Extract 6 raw feature values | All 6 features extracted correctly | **PASS** |
| **T09** | Risk Engine | Normalization scaling | Raw features exceeding bounds | Scale features into $[0.0, 1.0]$ | All normalized features $\in [0.0, 1.0]$ | **PASS** |
| **T10** | Risk Engine | Risk calculation | Normalized features & weights | Composite Score = $\sum w_i f_i$ | Score calculated deterministically | **PASS** |
| **T11** | Risk Engine | Risk classification | Scores 0.10, 0.40, 0.60, 0.85 | Map to `LOW`, `MODERATE`, `HIGH`, `CRITICAL` | Exact classification boundaries matched | **PASS** |
| **T12** | Reproducibility | Deterministic scoring | Dual run on identical fixture | Identical scores & normalized factors | `run1['composite_score'] == run2['composite_score']` | **PASS** |
| **T13** | Database | SQLite DB persistence | `AnalysisService.analyze_repository()` | Assessment & features saved in DB | Record retrieved via Analysis ID | **PASS** |
| **T14** | REST API | Request validation | Invalid payloads & missing IDs | HTTP 400 & HTTP 404 responses | Proper HTTP status codes & detail msgs | **PASS** |
| **T15** | Integration | End-to-end flow | POST `/api/v1/analyze` | Complete analysis response schema | HTTP 200 with full schema & DB record | **PASS** |

---

## Test Execution Command

```bash
$env:PYTHONPATH="."
python -m pytest backend/tests/
```

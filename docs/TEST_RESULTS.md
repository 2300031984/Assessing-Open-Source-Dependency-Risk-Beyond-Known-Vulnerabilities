# AUTOMATED TEST EXECUTION REPORT — CYBER-100

**Project Title:** Assessing Open Source Dependency Risk Beyond Known Vulnerabilities  
**Project ID:** CYBER-100  
**Test Framework:** Pytest 9.1.1 (Python 3.11.9)  
**Execution Timestamp:** 2026-10-29  
**Total Tests Collected:** 57  
**Passed:** 57  
**Failed:** 0  
**Skipped:** 0  
**Execution Duration:** 1.31s  
**Status:** **ALL TESTS PASSING (100% SUCCESS RATE)**  

---

## 1. Test Execution Command

```powershell
$env:PYTHONPATH="."
.\.venv\Scripts\python.exe -m pytest backend/tests/ -v
```

---

## 2. Test Execution Summary Matrix (Areas A through P)

| Category / Area | Test File | Test Count | Description | Status |
| :--- | :--- | :---: | :--- | :---: |
| **A. URL Validation** | `test_url_validation.py`<br>`test_collectors.py` | 13 | Tests parsing of clean URLs, `.git` suffix, trailing slashes, query parameters, fragments, whitespace, length limits, reserved routes, and empty inputs. | **PASS** |
| **B. Valid Repo Collection** | `test_collectors.py` | 2 | Verified GitHub repository metadata, stars, forks, commits, and contributor extraction using controlled mocks. | **PASS** |
| **C. Invalid Repo Handling** | `test_collectors.py`<br>`test_api_endpoints_comprehensive.py` | 3 | Verifies rejection of invalid URLs, non-existent 404 repositories, and malformed inputs. | **PASS** |
| **D. Missing Metadata** | `test_collectors.py` | 1 | Verifies missing licenses, missing release dates, and uncommunicative endpoints are recorded in `missing_fields`. | **PASS** |
| **E. OSV Response Parsing** | `test_osv_collector_advanced.py`<br>`test_collectors.py` | 5 | Tests CVSS float parsing, CVSS vector string parsing, ecosystem translation, and deduplication of advisories by `vuln_id`. | **PASS** |
| **F. Empty Vulnerabilities** | `test_osv_collector_advanced.py` | 2 | Verifies empty OSV vulnerability responses and empty package names return `[]` without exceptions. | **PASS** |
| **G. API Failure Handling** | `test_collectors.py`<br>`test_osv_collector_advanced.py` | 3 | Tests handling of HTTP 500 responses, network timeouts, and GitHub rate limits without application crash. | **PASS** |
| **H. Feature Extraction** | `test_normalization.py`<br>`test_risk_features_comprehensive.py` | 5 | Tests extraction of all 6 raw features: archived penalties, single maintainer bus factor, active cadence, and license risk. | **PASS** |
| **I. Feature Normalization** | `test_normalization.py`<br>`test_risk_features_comprehensive.py` | 3 | Tests deterministic normalization curves and strict clamping to $[0.0, 1.0]$ bounds under extreme raw inputs. | **PASS** |
| **J. Risk Score Math** | `test_risk_engine.py`<br>`test_reproducibility.py` | 2 | Verifies composite score calculation matches weighted sum formula $\sum w_i f_i$. | **PASS** |
| **K. Classification Tiers** | `test_risk_engine.py`<br>`test_risk_features_comprehensive.py` | 2 | Tests all exact threshold boundaries: 0.00, 0.24, 0.241, 0.25, 0.49, 0.491, 0.50, 0.74, 0.741, 0.75, 1.00. | **PASS** |
| **L. Missing Data Handling** | `test_risk_features_comprehensive.py`<br>`test_collectors.py` | 2 | Verifies missing signals generate informative user warnings and do not falsely zero out risk scores. | **PASS** |
| **M. Database Persistence** | `test_database_advanced.py`<br>`test_reproducibility.py` | 5 | Tests SQLite storage, multi-analysis repo linkage, feature cascading, rollback safety, and ID lookups. | **PASS** |
| **N. REST API Responses** | `test_api.py`<br>`test_api_endpoints_comprehensive.py` | 5 | Tests GET `/`, GET `/api/v1/health`, POST `/api/v1/analyze`, GET `/api/v1/analysis/{id}`, and GET `/api/v1/repository/{owner}/{repo}`. | **PASS** |
| **O. Dashboard Robustness** | `test_dashboard_regression.py`<br>`test_dashboard_robustness.py` | 8 | Regression tests for `get_field` attribute and dict access, handling None values, type-safe ratio calculations, and empty tables. | **PASS** |
| **P. Error Code Mapping** | `test_api.py`<br>`test_api_endpoints_comprehensive.py` | 3 | Validates HTTP 400 for bad input, HTTP 404 for missing resources, and HTTP 500 for internal errors. | **PASS** |
| **TOTAL** | **8 Test Modules** | **57** | **Complete Subsystem Verification** | **PASS** |

---

## 3. Defects Identified, Root Causes & Fixes

### Defect 1: Dashboard TypeError on Risk Factor Display
- **Symptom:** `TypeError: 'RiskFactorBreakdown' object is not subscriptable` occurred when rendering risk factors table in Streamlit.
- **Root Cause:** Pydantic model objects were being accessed using dictionary bracket syntax (`f_data["raw_value"]`).
- **Fix:** Implemented universal `get_field(obj, field_name, default)` helper supporting both Pydantic model attribute access (`getattr`) and standard dictionary key access (`.get()`). Added regression tests `T16`, `T17`, `T18`.

### Defect 2: Malformed GitHub URLs Returning HTTP 404 Instead of HTTP 400
- **Symptom:** Submitting invalid GitHub URLs (e.g. `https://github.com/invalid/`) returned HTTP 404 Not Found.
- **Root Cause:** `endpoints/analyze.py` caught all `ValueError` exceptions and blindly raised `HTTPException(404)`.
- **Fix:** Differentiated input syntax errors from resource not found errors: if `"not found" in str(ve).lower()`, return 404; otherwise return 400 Bad Request.

### Defect 3: OSV CVSS Vector Parsing Collision with CVSS Version String
- **Symptom:** When parsing vectors like `CVSS:3.1/AV:N/... 9.8`, regex matched the version number `3.1` instead of the metric score `9.8`.
- **Root Cause:** Naive regex `\d+\.\d+` picked up the CVSS version prefix.
- **Fix:** Added regex substitution `re.sub(r"^CVSS:\d+\.\d+/?", "", text)` to strip version prefixes before searching for numeric scores.

### Defect 4: Test Database Isolation with In-Memory SQLite
- **Symptom:** In integration tests, `OperationalError: no such table: repositories` occurred intermittently.
- **Root Cause:** Standard SQLite `:memory:` creates a new isolated database per connection. When the table creation connection closed, tables vanished. Additionally, `conftest.py` had not overridden `get_database`.
- **Fix:** Applied `StaticPool` (`from sqlalchemy.pool import StaticPool`) and registered dependency overrides for both `get_db` and `get_database`.

### Defect 5: Contributor Percentage TypeError on None or String Values
- **Symptom:** In dashboard Tab 2, `top_ratio * 100` could raise a `TypeError` if `top_ratio` was None or a string.
- **Fix:** Coerced value with `safe_ratio = float(top_ratio) if isinstance(top_ratio, (int, float)) else 0.0`.

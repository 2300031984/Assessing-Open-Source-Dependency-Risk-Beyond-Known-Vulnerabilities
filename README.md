# Assessing Open Source Dependency Risk Beyond Known Vulnerabilities

**Project ID:** CYBER-100  
**Domain:** Cybersecurity and Blockchain Technology  
**Capstone Stage:** Engineering Capstone & Preliminary Design Review (PDR) Ready  

---

## 1. Executive Summary & Problem Statement

Modern software engineering relies extensively on third-party open-source dependencies. Traditional Software Composition Analysis (SCA) tools assess dependency risk almost exclusively by matching package versions against known vulnerability databases, such as the National Vulnerability Database (NVD) or Open Source Vulnerabilities (OSV).

However, known vulnerability records represent **lagging indicators**:
- Security advisories are published only after a flaw has been discovered, reported, and assigned a CVE.
- Latent supply-chain risks—such as single-maintainer abandonment (Bus Factor = 1), abrupt cessation of commit activity, unmaintained release cadence, or licensing ambiguity—frequently precede security compromises (e.g., account hijacking, unpatched memory safety bugs, or malicious takeover).
- Traditional vulnerability scanners silently treat unmaintained, inactive packages with zero reported CVEs as "zero risk."

**CYBER-100** addresses this gap by implementing a transparent, deterministic composite risk assessment engine. It synthesizes real-time public vulnerability intelligence with multi-dimensional repository governance, maintainer concentration, commit velocity, and release recency signals to evaluate open-source dependency risk **beyond known vulnerabilities**.

---

## 2. Core Implemented Features

### Objective O1 — Multi-Source Signal Collection
- **GitHub Repository Signal Collector (`backend/app/collectors/github_collector.py`)**:
  - Validates and parses repository URLs (stripping query parameters, fragments, and trailing slashes).
  - Collects identity metadata: owner, repository name, primary language, license, creation date, update date, and archived status.
  - Measures activity cadence: star count, fork count, watchers, open issue count, and monthly commit frequency.
  - Evaluates maintainer governance: total contributor count and top-contributor commit concentration ratio (bus factor risk).
  - Assesses release recency: latest release tag, publication timestamp, days elapsed since last release, and annualized release frequency.
  - Explicitly logs missing or degraded signals (`missing_fields`) without silently zeroing risk.
- **OSV Vulnerability Intelligence Collector (`backend/app/collectors/osv_collector.py`)**:
  - Dynamically maps detected repository language to standard package ecosystems (Python → PyPI, JavaScript/TypeScript → npm, Rust → crates.io, Go → Go, Ruby → RubyGems, Java → Maven).
  - Queries OSV REST API (`https://api.osv.dev/v1/query`) for published security advisories.
  - Extracts CVSS scores, severity tiers (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), affected version ranges, and fixed version tags.
  - Automatically deduplicates vulnerability records by `vuln_id`.

### Objective O2 — Transparent Composite Risk Engine
- **Feature Extractor (`backend/app/risk/feature_extractor.py`)**: Transforms collected repository and vulnerability signals into 6 quantitative raw risk features.
- **Normalizer (`backend/app/risk/normalizer.py`)**: Maps raw features into bounded $[0.0, 1.0]$ scales using deterministic transformation curves.
- **Scoring Engine (`backend/app/risk/scoring_engine.py`)**: Computes the composite risk score using a weighted linear combination:
  $$\text{Composite Risk Score} = \sum_{i=1}^{6} (w_i \times f_i)$$
- **Classifier (`backend/app/risk/classifier.py`)**: Classifies the score into 4 documented tiers: `LOW` (0.00–0.24), `MODERATE` (0.25–0.49), `HIGH` (0.50–0.74), `CRITICAL` (0.75–1.00).
- **Explanation Generator (`backend/app/risk/explanation.py`)**: Produces natural-language justifications identifying dominant risk contributors.
- **Reproducibility Layer**: Persists an immutable analysis snapshot with a unique Analysis ID (e.g., `RA-A1B2C3`), scoring version (`v0.1`), feature version (`v0.1`), raw and normalized features, weights, and timestamp.

### Interfaces & Developer Tooling
- **FastAPI REST API (`backend/app/main.py`)**: Fully documented OpenAPI endpoints for synchronous repository analysis, historical record retrieval, and health checks.
- **Streamlit Interactive Dashboard (`dashboard/app.py`)**: Real-time analytical dashboard with dual execution modes (**LIVE DATA** vs **DEMO FIXTURE**), 6-tab analytical breakdown, signal warning banners, and academic limitation notices.
- **Developer Terminal CLI (`backend/cli/`)**: Production terminal tool inspired by `driftctl` featuring interactive panels, risk meters, `--json` streaming, report export (`--output`), analysis history (`history`), analysis detail inspection (`show`), and diagnostic health verification (`health`). See [CLI Reference](file:///d:/CyberTools/OpenSource%20Dependency%20Risk%20Beyond%20Known%20Vulnerabilities/docs/CLI_REFERENCE.md).

---

## 3. Architecture Overview

```
User Input (URL / Mode)
         │
         ▼
[ URL Validation & Sanitization ]
         │
         ├───► GitHub Collector (Metadata, Commits, Contributors, Releases)
         └───► OSV Collector (Ecosystem-Mapped Vulnerability Advisories)
         │
         ▼
[ Feature Extractor ] ──► Computes 6 Raw Signal Dimensions
         │
         ▼
[ Normalizer ] ──────────► Bounded [0.0, 1.0] Feature Mapping
         │
         ▼
[ Scoring Engine ] ──────► Weighted Sum Composite Calculation (R = Σ w_i * f_i)
         │
         ▼
[ Classifier & Explanation ] ──► Tiers (LOW/MODERATE/HIGH/CRITICAL) & Explanations
         │
         ▼
[ Persistence Layer ] ───► SQLite / SQLAlchemy (Repositories, Signals, Vulns, Assessments)
         │
         ├───► FastAPI REST Endpoints (/api/v1/analyze, /api/v1/analysis/{id})
         └───► Streamlit Analytical Dashboard (Dual Mode, Tabs 1-6)
```

---

## 4. Risk Scoring Methodology

### 6 Risk Dimensions & Baseline Weights (`v0.1`)

| Dimension ($i$) | Weight ($w_i$) | Raw Signal Metrics | Normalization Formula ($f_i$) | Risk Interpretation |
| :--- | :---: | :--- | :--- | :--- |
| **1. Vulnerability** | **0.30** | Max CVSS + $0.5 \times N_{\text{vuln}}$ | $f_{\text{vuln}} = \min\left(1.0, \frac{\text{CVSS}_{\text{max}} + 0.5 \cdot N_{\text{vuln}}}{10.0}\right)$ | Impact of known OSV/CVE advisories |
| **2. Repository Health** | **0.20** | Issue-to-popularity ratio + Archived state + Missing signals | $f_{\text{health}} = \min\left(1.0, \frac{\text{Ratio} \cdot 5.0 + 3.0 \cdot \mathbf{1}_{\text{archived}} + 0.5 \cdot N_{\text{missing}}}{5.0}\right)$ | Repository issue backlog and maintainer presence |
| **3. Commit Activity** | **0.15** | Monthly commit frequency ($C_{\text{month}}$) | $f_{\text{activity}} = \min\left(1.0, \frac{\max(0.0, 30.0 - C_{\text{month}})}{30.0}\right)$ | Ongoing development pace (low commits = high risk) |
| **4. Maintainer** | **0.15** | Contributor count + Top contributor commit ratio | $f_{\text{maint}} = 1.0 \text{ if } N_{\text{contrib}} \le 1 \text{ else } \text{TopRatio}$ | Bus factor vulnerability (single-maintainer reliance) |
| **5. Release Recency** | **0.10** | Days elapsed since latest tag/release ($D_{\text{rel}}$) | $f_{\text{release}} = \min\left(1.0, \frac{D_{\text{rel}}}{730.0}\right)$ | Maintenance recency (730 days = 2 years max scale) |
| **6. Governance** | **0.10** | SPDX license clarity + Copyleft + Archive state | $f_{\text{gov}} = \min(1.0, \text{LegalRisk})$ | Legal licensing clarity and abandonment risk |

$$\sum_{i=1}^{6} w_i = 0.30 + 0.20 + 0.15 + 0.15 + 0.10 + 0.10 = 1.00$$

### Classification Thresholds
- **$0.00 \le R \le 0.24$**: `LOW` — Healthy activity, diverse maintainers, active releases, minimal known CVEs.
- **$0.25 \le R \le 0.49$**: `MODERATE` — Minor concerns in release recency, maintainer concentration, or low-severity alerts.
- **$0.50 \le R \le 0.74$**: `HIGH` — Evident maintainer stagnation, single maintainer dominance, or high-severity vulnerabilities.
- **$0.75 \le R \le 1.00$**: `CRITICAL` — Unmaintained/archived state, zero recent activity, or critical active vulnerabilities.

---

## 5. Technology Stack & Prerequisites

- **Language:** Python 3.11+
- **Backend Framework:** FastAPI 0.100+, Uvicorn 0.22+
- **Database & ORM:** SQLite 3, SQLAlchemy 2.0+
- **Validation & Serialization:** Pydantic v2
- **Dashboard UI:** Streamlit 1.25+
- **HTTP Client:** Requests 2.31+, HTTPX 0.24+
- **Testing Framework:** Pytest 9.1+, Pytest-Asyncio

---

## 6. Installation & Environment Configuration

### Step 1: Clone and Navigate to Repository
```bash
git clone <repository-url>
cd "d:/CyberTools/OpenSource Dependency Risk Beyond Known Vulnerabilities"
```

### Step 2: Create and Activate Virtual Environment
On Windows (PowerShell):
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables
Copy the example environment file:
```bash
copy .env.example .env
```
Configuration options in `.env`:
```ini
PROJECT_NAME="CYBER-100: Assessing Open Source Dependency Risk Beyond Known Vulnerabilities"
ENV="development"
DEBUG=True
DATABASE_URL="sqlite:///./risk_assessment.db"
GITHUB_TOKEN=""
DEMO_MODE=False
DEFAULT_SCORING_VERSION="v0.1"
API_TIMEOUT_SECONDS=10
ALLOWED_ORIGINS="http://localhost:8501,http://127.0.0.1:8501,http://localhost:3000,http://localhost:8000,http://localhost:8001"
```
*(Optional: Add your personal GitHub API token to `GITHUB_TOKEN` to enjoy GitHub's 5,000 req/hr rate limit instead of the unauthenticated 60 req/hr limit).*

---

## 7. Execution Guide

### Option A: Launching Backend (Terminal 1)
```powershell
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH="."
python -m uvicorn backend.app.main:app --reload --port 8000
```
- Interactive API Documentation (Swagger UI): `http://localhost:8000/docs`
- Service Health Endpoint: `http://localhost:8000/api/v1/health`
- Root Service Status: `http://localhost:8000/`

### Option B: Launching Streamlit Dashboard (Terminal 2)
In a separate terminal:
```powershell
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH="."
python -m streamlit run dashboard/app.py
```
- Open browser at: `http://localhost:8501`
- Toggle between **DEMO FIXTURE (Offline Mode)** and **LIVE DATA (GitHub + OSV API)** in the left sidebar.

### Option C: Developer Terminal CLI (Terminal 3)
Execute commands directly from PowerShell or Linux/macOS terminals:
```powershell
$env:PYTHONPATH="."

# 1. Analyze a package directly (shorthand or full URL)
python -m backend.cli analyze psf/requests

# 2. Analyze using deterministic offline fixture
python -m backend.cli analyze psf/requests --fixture

# 3. Export machine-readable JSON (ideal for CI/CD)
python -m backend.cli analyze psf/requests --json

# 4. Save report directly to JSON file
python -m backend.cli analyze psf/requests --output report.json

# 5. View recent analyses history
python -m backend.cli history --limit 5

# 6. Inspect specific past analysis by ID
python -m backend.cli show RA-0D4964

# 7. Verify subsystem health and latencies
python -m backend.cli health

# 8. Check version
python -m backend.cli --version
```
*For complete argument details, exit codes, and formatting options, see [docs/CLI_REFERENCE.md](file:///d:/CyberTools/OpenSource%20Dependency%20Risk%20Beyond%20Known%20Vulnerabilities/docs/CLI_REFERENCE.md).*

---

## 8. Automated Testing

CYBER-100 includes a comprehensive test suite of **71 automated test cases** covering URL validation, collectors, feature extraction, normalization bounds, scoring math, database operations, REST endpoints, UI data processing, and complete CLI command flows.

Run all automated tests:
```powershell
$env:PYTHONPATH="."
.\.venv\Scripts\python.exe -m pytest backend/tests/ -v
```

Expected result:
```
======================= 71 passed, 2 warnings in ~14s =======================
```

---

## 9. Sample API Interaction

### Analyze Repository (`POST /api/v1/analyze`)
**Request:**
```bash
curl -X POST "http://localhost:8000/api/v1/analyze" \
     -H "Content-Type: application/json" \
     -d '{"repository_url": "https://github.com/demo-owner/sample-crypto-lib", "use_demo_fixture": true}'
```

**Response (`HTTP 200 OK`):**
```json
{
  "analysis_id": "RA-4E8F2A",
  "repository": {
    "owner": "demo-owner",
    "name": "sample-crypto-lib",
    "url": "https://github.com/demo-owner/sample-crypto-lib",
    "description": "Demonstration repository fixture for CP1 Review-2 faculty live demo",
    "language": "Python",
    "license": "MIT",
    "archived": false,
    "signals": {
      "stars": 1250,
      "forks": 320,
      "open_issues": 42,
      "commit_frequency_per_month": 4.5,
      "contributor_count": 3,
      "top_contributor_commit_ratio": 0.82,
      "release_age_days": 315
    }
  },
  "vulnerabilities": [
    {
      "vuln_id": "GHSA-4v9c-982m-4786",
      "severity": "HIGH",
      "cvss_score": 7.5,
      "summary": "Potential buffer overflow in crypto signature validation routine when parsing untrusted payloads.",
      "affected_versions": "<=1.3.2",
      "fixed_versions": "1.4.0",
      "source": "OSV Known Vulnerability Signal"
    }
  ],
  "risk_score": 0.49,
  "risk_level": "MODERATE",
  "explanation": "Composite Risk Score: 0.49 (MODERATE). The assessment is primarily influenced by known vulnerability signals, contributor concentration, release and maintenance recency.",
  "scoring_version": "v0.1",
  "feature_version": "v0.1",
  "is_demo_fixture": true,
  "warnings": [],
  "timestamp": "2026-10-29T11:45:00Z"
}
```

### Retrieve Historical Assessment (`GET /api/v1/analysis/{analysis_id}`)
```bash
curl -X GET "http://localhost:8000/api/v1/analysis/RA-4E8F2A"
```

---

## 10. Security & Ethical Considerations

- **API Token Protection**: Secrets are stored in `.env` (excluded by `.gitignore`). Default configuration provides placeholder values only.
- **Defensive Input Sanitization**: URLs are strictly sanitized, query strings stripped, input lengths capped, and reserved routes rejected.
- **SQL Injection Prevention**: SQLAlchemy parameterized ORM queries are utilized exclusively.
- **CORS Hardening**: CORS middleware enforces explicit trusted origins rather than unauthenticated wildcards.
- **Ethical Collection**: All signal collection adheres strictly to GitHub and OSV public REST API terms, requesting only public repository metadata.

---

## 11. Academic Limitations & Phase 2 Roadmap

### Current Scope & Known Limitations
1. **Package vs Lockfile Distinction**: The current prototype resolves packages at the repository level. Transitive lockfile dependency graph parsing (`requirements.txt`, `package-lock.json`, `Cargo.lock`) is scheduled for Phase 2.
2. **Heuristic Risk Model**: Prototype weights ($w_i$) are rule-based heuristic values designed for transparency and faculty inspection. They do not represent empirically validated machine-learning probabilities of real-world compromise.
3. **External API Dependence**: Real-time signal collection depends on GitHub and OSV API availability; offline demo mode (`use_demo_fixture=True`) is provided for deterministic live presentations.

### Planned Phase 2 (CP2) Roadmap
- **Objective O3**: Validation against historical supply-chain incident datasets (e.g., event-stream, ua-parser, xz-utils).
- **Objective O4**: Comparative statistical evaluation against traditional vulnerability-count baselines.
- **Objective O5**: Independent acceptance testing and operational impact benchmarking.

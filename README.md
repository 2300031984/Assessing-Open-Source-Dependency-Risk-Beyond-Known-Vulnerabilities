# Assessing Open Source Dependency Risk Beyond Known Vulnerabilities

**Project ID:** CYBER-100  
**Domain:** Cybersecurity and Blockchain Technology  
**Milestone:** Capstone Project Phase 1 (CP1) / Review-2 Working Prototype  

---

## 1. Project Overview

**CYBER-100** provides a transparent, reproducible composite risk assessment system for open-source software dependencies. Beyond looking up existing Common Vulnerabilities and Exposures (CVEs), CYBER-100 collects and analyzes repository activity, maintainer concentration, commit cadence, release recency, and licensing governance signals to identify latent supply-chain risks before vulnerabilities are publicly disclosed.

---

## 2. Problem Addressed

Modern software applications rely on hundreds of third-party open-source dependencies. Standard security tools evaluate open-source risk solely by matching installed package versions against known vulnerability databases (e.g. NVD, OSV). However:
- **Lagging Indicator**: Known vulnerability databases only reflect security issues after discovery and disclosure.
- **Maintainer Stagnation & Abandonment**: Abandoned or single-maintainer dependencies pose significant supply-chain risks (e.g. account takeover, malicious PR injections, unpatched bugs).
- **Lack of Holistic Signal Integration**: Existing tools rarely combine repository health, bus factor concentration, and release recency into a unified scoring model.

---

## 3. Current CP1 Scope (Review-2 Prototype)

This prototype implements Phase 1 objectives:
- **O1 — Repository & Vulnerability Signal Collection**: Automated extraction of metadata, activity metrics, contributor concentration, release recency, and OSV known vulnerability signals.
- **O2 — Composite Risk Assessment Engine**: A non-blackbox scoring engine featuring signal feature extraction, non-linear normalization, weighted composite scoring ($\text{Score} = \sum w_i f_i$), transparent classification (`LOW`, `MODERATE`, `HIGH`, `CRITICAL`), factor breakdown, and evidence-based risk explanations.
- **Dual Execution Modes**: Real-time **LIVE DATA** mode (queries GitHub API & OSV API) and deterministic **DEMO FIXTURE** mode (runs offline with zero external network dependencies for live faculty demonstrations).

---

## 4. Architecture Overview

```
Repository URL Input
        │
        ▼
Signal Collection Layer (O1) ──► GitHub API Collector + OSV Vulnerability Collector
        │
        ▼
Feature Extractor (O2) ────────► Quantitative Signal Derivation
        │
        ▼
Normalizer ────────────────────► Bounded [0.0, 1.0] Feature Risk Mapping
        │
        ▼
Scoring Engine ────────────────► Weighted Sum Composite Score Calculation
        │
        ▼
Classifier & Explanation ──────► Risk Level Tiering & Textual Rationale
        │
        ▼
Persistence Layer ─────────────► SQLite Database Storage (Analysis ID: RA-XXXXXX)
        │
        ▼
API & Dashboard Layer ─────────► FastAPI REST Endpoints & Streamlit Dashboard
```

---

## 5. Objectives & Risk Model

### Objective O1 — Signal Collection
Collects repository identity (owner, name, license, language), activity metrics (stars, forks, open issues, commit frequency), contributor signals (contributor count, top-contributor commit concentration ratio), release info (release age in days, release frequency), and OSV known vulnerability signals. Missing API signals are logged gracefully without failing the assessment.

### Objective O2 — Composite Scoring Formula

$$\text{Composite Risk Score} = \sum_{i=1}^{6} (w_i \times f_i)$$

Where prototype initial weights are:
- `vulnerability`: 0.30
- `repository_health`: 0.20
- `activity`: 0.15
- `maintainer`: 0.15
- `release`: 0.10
- `dependency`: 0.10

### Classification Tiers
- **0.00 – 0.24**: `LOW`
- **0.25 – 0.49**: `MODERATE`
- **0.50 – 0.74**: `HIGH`
- **0.75 – 1.00**: `CRITICAL`

---

## 6. Installation & Environment Configuration

### Prerequisites
- Python 3.11+
- Git

### Setup Instructions

1. **Clone & Navigate to Workspace**:
   ```bash
   cd "d:/CyberTools/OpenSource Dependency Risk Beyond Known Vulnerabilities"
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Environment Variables**:
   Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```
   *(Optional: Add your personal GitHub API token to `GITHUB_TOKEN` in `.env` for higher API rate limits).*

---

## 7. Running the Prototype

### 1. Launch FastAPI Backend
```bash
python -m uvicorn backend.app.main:app --reload --port 8000
```
- API Documentation: `http://localhost:8000/docs`
- Health Check: `http://localhost:8000/api/v1/health`

### 2. Launch Streamlit Demo Dashboard
In a separate terminal window:
```bash
streamlit run dashboard/app.py
```
- Open `http://localhost:8501` in your browser.
- Toggle between **DEMO FIXTURE (Offline Mode)** and **LIVE DATA (GitHub + OSV API)**.

---

## 8. Running Automated Tests

Run the complete test suite (T01 – T15):
```bash
$env:PYTHONPATH="."
python -m pytest backend/tests/
```

All 15 test cases execute in ~0.2s and cover valid/invalid URL parsing, API fallbacks, feature extraction, normalization bounds, scoring determinism, DB persistence, API endpoints, and E2E analysis.

---

## 9. Example Analysis Request & Response

### REST Request (`POST /api/v1/analyze`)
```json
{
  "repository_url": "https://github.com/psf/requests",
  "use_demo_fixture": false
}
```

### Sample REST Response
```json
{
  "analysis_id": "RA-4E8F2A",
  "repository": {
    "owner": "psf",
    "name": "requests",
    "url": "https://github.com/psf/requests",
    "language": "Python",
    "license": "Apache-2.0"
  },
  "risk_score": 0.18,
  "risk_level": "LOW",
  "explanation": "Composite Risk Score: 0.18 (LOW). The dependency exhibits stable metrics across repository activity, releases, and maintainer signals with minimal known vulnerability alerts.",
  "scoring_version": "v0.1",
  "feature_version": "v0.1",
  "is_demo_fixture": false
}
```

---

## 10. Current Limitations & CP2 Roadmap

- **Current CP1 Scope**: O1 Signal Collection & O2 Composite Risk Engine.
- **Planned for CP2**:
  - **O3**: Validation against historical supply-chain incident benchmarks.
  - **O4**: Comparative evaluation against traditional vulnerability-count tools.
  - **O5**: Independent operational impact assessment.
  - Deep lockfile parsing (`requirements.txt`, `package.json`, `Cargo.lock`).

# RISK MODEL FORMULATION & TRANSPARENCY DOCUMENTATION — CYBER-100

**Project Title:** Assessing Open Source Dependency Risk Beyond Known Vulnerabilities  
**Project ID:** CYBER-100  
**Scoring Model Version:** `v0.1`  
**Feature Model Version:** `v0.1`  

---

## 1. Executive Overview

The CYBER-100 risk model computes a **Composite Risk Score** ($0.00 \le \text{Score} \le 1.00$) for open-source software dependencies by synthesizing public vulnerability intelligence (Objective O1) with quantitative repository health, maintainer concentration, commit activity, and release governance signals (Objective O2).

Unlike traditional tools that rely solely on known vulnerability databases (e.g., CVE count), CYBER-100 models multi-dimensional repository signals to identify latent supply-chain risk before a CVE is published.

---

## 2. Mathematical Formulation

The final **Composite Risk Score** $R$ is calculated as a weighted sum of $N=6$ normalized risk factors $f_i \in [0.0, 1.0]$:

$$R = \sum_{i=1}^{N} (w_i \times f_i)$$

Subject to:
$$\sum_{i=1}^{N} w_i = 1.0, \quad 0.0 \le f_i \le 1.0$$

---

## 3. Feature Definitions & Normalization Curves

| Risk Dimension ($i$) | Raw Signal Metrics | Normalization Formula ($f_i$) | Risk Interpretation |
| :--- | :--- | :--- | :--- |
| **1. Vulnerability Risk** | Max CVSS score + $0.5 \times \text{Vuln Count}$ | $f_{\text{vuln}} = \min\left(1.0, \frac{\text{CVSS}_{\text{max}} + 0.5 \times N_{\text{vuln}}}{10.0}\right)$ | Impact of known OSV/CVE signals |
| **2. Repository Health** | Issue ratio + Archived state + Missing fields | $f_{\text{health}} = \min\left(1.0, \frac{\text{IssueRatio} \times 5.0 + 3.0 \cdot \mathbf{1}_{\text{archived}} + 0.5 \times N_{\text{missing}}}{5.0}\right)$ | Balance between issues, stars, and repository health |
| **3. Commit Activity** | Monthly commit frequency ($C_{\text{month}}$) | $f_{\text{activity}} = \min\left(1.0, \frac{\max(0.0, 30.0 - C_{\text{month}})}{30.0}\right)$ | Active commit cadence (lower activity = higher risk) |
| **4. Maintainer Concentration** | Top contributor commit ratio / Bus Factor | $f_{\text{maintainer}} = \min(1.0, \max(0.0, \text{TopContribRatio}))$ | Dependency on a single maintainer (Bus Factor = 1) |
| **5. Release Governance** | Days since last tag/release ($D_{\text{release}}$) | $f_{\text{release}} = \min\left(1.0, \frac{D_{\text{release}}}{730.0}\right)$ | Time elapsed since last stable release (730d = 2 years) |
| **6. Dependency & License** | License clarity + Copyleft + Archived status | $f_{\text{dep}} = \min(1.0, \text{RawLegalRisk})$ | Licensing status & archive governance risk |

---

## 4. Prototype Weights & Classification Thresholds

### Initial Configurable Risk Weights (`v0.1`)

```yaml
risk_weights:
  vulnerability: 0.30
  repository_health: 0.20
  activity: 0.15
  maintainer: 0.15
  release: 0.10
  dependency: 0.10
```

> [!NOTE]
> Initial weights represent prototype baseline configurations designed for live demonstration and experimentation. They are configurable in `backend/app/risk/config.py`.

### Classification Thresholds

$$\text{Risk Level} = \begin{cases} 
\text{LOW} & \text{if } 0.00 \le R \le 0.24 \\
\text{MODERATE} & \text{if } 0.25 \le R \le 0.49 \\
\text{HIGH} & \text{if } 0.50 \le R \le 0.74 \\
\text{CRITICAL} & \text{if } 0.75 \le R \le 1.00 
\end{cases}$$

---

## 5. Reproducibility Protocol

To guarantee that any analysis can be independently verified and audited:
1. Every run generates a unique Analysis ID (e.g. `RA-A1B2C3`).
2. An immutable record containing the raw signals, normalized features, exact weights used, scoring model version (`v0.1`), feature model version (`v0.1`), and execution timestamp is persisted in SQLite.
3. Re-evaluating the same inputs with identical configuration yields identical composite risk scores.

---

## 6. Assumptions & Current Prototype Limitations

1. **GitHub API Scope**: Phase 1 signal collection focuses on GitHub repositories.
2. **Ecosystem Name Resolution**: Package name is derived from repo name; detailed multi-language lockfile parsing (e.g. `Cargo.lock`, `go.sum`) is scheduled for CP2.
3. **No Unvalidated ML Claims**: Machine learning predictive calibration (Objectives O3 & O4) is explicitly reserved for CP2 validation.


## Interpretation
The score is an explainable engineering baseline and should be validated against project-specific evidence before being treated as a predictive measure.

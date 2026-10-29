# RISK MODEL FORMULATION & TRANSPARENCY DOCUMENTATION

**Project Title:** Assessing Open Source Dependency Risk Beyond Known Vulnerabilities  
**Project ID:** CYBER-100  
**Scoring Model Version:** `v0.1`  
**Feature Model Version:** `v0.1`  
**Domain:** Software Supply Chain Security  

---

## 1. Executive Summary & Rationale

Traditional Software Composition Analysis (SCA) tools evaluate dependency risk by querying public vulnerability databases (e.g., NVD, OSV) for known Common Vulnerabilities and Exposures (CVEs). This approach has a fundamental flaw: **known vulnerabilities are lagging indicators**. A component with zero reported CVEs may be completely abandoned, maintained by a single person (Bus Factor = 1), lacking releases for years, and exposed to silent account hijacking or malicious injection.

The CYBER-100 model calculates a **Composite Risk Score** ($0.00 \le R \le 1.00$) synthesizing both **known vulnerability intelligence** and **multi-dimensional repository governance signals** to assess latent risk *beyond known vulnerabilities*.

---

## 2. Mathematical Formulation

The composite risk score $R$ is formulated as a linear weighted sum of $N=6$ normalized risk factors $f_i \in [0.0, 1.0]$:

$$R = \sum_{i=1}^{N} (w_i \times f_i)$$

Subject to the following operational constraints:
$$\sum_{i=1}^{N} w_i = 1.0, \quad 0.0 \le f_i \le 1.0, \quad 0.0 \le R \le 1.0$$

---

## 3. The 6 Risk Dimensions in Detail

### Dimension 1: Known Vulnerability Risk ($f_{\text{vuln}}$)
- **Meaning:** Measures the severity and volume of confirmed, publicly disclosed security vulnerabilities associated with the dependency.
- **Data Source:** Open Source Vulnerabilities (OSV) API (`https://api.osv.dev/v1/query`), mapped to package ecosystem (e.g. PyPI, npm, crates.io).
- **Extraction Method:**
  $$\text{Raw} = \min\left(10.0, \text{CVSS}_{\text{max}} + 0.5 \times N_{\text{vuln}}\right)$$
  Where $\text{CVSS}_{\text{max}}$ is the maximum CVSS score among reported advisories, and $N_{\text{vuln}}$ is the count of deduplicated advisories. If CVSS is missing, fallback values are mapped from severity labels (`CRITICAL` = 9.5, `HIGH` = 7.5, `MEDIUM` = 5.0, `LOW` = 2.5).
- **Normalization Formula:**
  $$f_{\text{vuln}} = \min\left(1.0, \max\left(0.0, \frac{\text{Raw}}{10.0}\right)\right)$$
- **Missing Data Treatment:** When OSV returns zero matching advisories, $\text{Raw} = 0.0$ and $f_{\text{vuln}} = 0.0$.
- **Assigned Weight:** $w_1 = 0.30$.

### Dimension 2: Repository Health Risk ($f_{\text{health}}$)
- **Meaning:** Evaluates the balance between open issues and repository popularity, maintainer presence, and project archive status.
- **Data Source:** GitHub REST API (`stargazers_count`, `forks_count`, `open_issues_count`, `archived`).
- **Extraction Method:**
  $$\text{IssueRatio} = \frac{\text{OpenIssues}}{\text{Stars} + \text{Forks} + 10.0}$$
  $$\text{Raw} = (\text{IssueRatio} \times 5.0) + (3.0 \times \mathbf{1}_{\text{archived}}) + (0.5 \times N_{\text{missing}})$$
- **Normalization Formula:**
  $$f_{\text{health}} = \min\left(1.0, \max\left(0.0, \frac{\text{Raw}}{5.0}\right)\right)$$
- **Missing Data Treatment:** Degraded API responses increment $N_{\text{missing}}$, adding a controlled penalty while triggering explicit user warnings.
- **Assigned Weight:** $w_2 = 0.20$.

### Dimension 3: Commit Activity Cadence ($f_{\text{activity}}$)
- **Meaning:** Measures the frequency and recency of ongoing source-code maintenance. Projects with zero recent commits exhibit higher risk of abandonment.
- **Data Source:** GitHub REST API (`/commits?per_page=30`).
- **Extraction Method:**
  $$\text{Raw} = \max(0.0, 30.0 - C_{\text{month}})$$
  Where $C_{\text{month}}$ is the estimated monthly commit cadence based on recent activity.
- **Normalization Formula:**
  $$f_{\text{activity}} = \min\left(1.0, \max\left(0.0, \frac{\text{Raw}}{30.0}\right)\right)$$
- **Missing Data Treatment:** If commits cannot be retrieved, $C_{\text{month}} = 0.0$ resulting in maximum activity penalty ($f_{\text{activity}} = 1.0$) with appropriate warning.
- **Assigned Weight:** $w_3 = 0.15$.

### Dimension 4: Maintainer Concentration / Bus Factor Risk ($f_{\text{maintainer}}$)
- **Meaning:** Evaluates reliance on a single primary developer. A project where one contributor authors $>80\%$ of commits has high fragility if that person leaves or is compromised.
- **Data Source:** GitHub REST API (`/contributors?per_page=10`).
- **Extraction Method:**
  $$\text{Raw} = \begin{cases} 1.0 & \text{if } N_{\text{contrib}} \le 1 \\ \text{TopContributorRatio} & \text{otherwise} \end{cases}$$
- **Normalization Formula:**
  $$f_{\text{maintainer}} = \min(1.0, \max(0.0, \text{Raw}))$$
- **Missing Data Treatment:** If contributor stats are blocked or empty, defaults to conservative baseline ($0.80$) with missing signal warning.
- **Assigned Weight:** $w_4 = 0.15$.

### Dimension 5: Release Practices Recency ($f_{\text{release}}$)
- **Meaning:** Assesses whether releases are actively tagged and published. Unreleased code for $>1$ year increases lag in delivering security patches.
- **Data Source:** GitHub REST API (`/releases/latest` and `/tags`).
- **Extraction Method:**
  $$\text{Raw} = \text{ReleaseAgeInDays}$$
- **Normalization Formula:**
  $$f_{\text{release}} = \min\left(1.0, \max\left(0.0, \frac{\text{Raw}}{730.0}\right)\right)$$
  *(730 days / 2 years scales to maximum penalty 1.0).*
- **Missing Data Treatment:** Repositories without formal releases are assigned raw penalty based on time since repository creation.
- **Assigned Weight:** $w_5 = 0.10$.

### Dimension 6: Governance & Licensing Risk ($f_{\text{dep}}$)
- **Meaning:** Evaluates legal ambiguity and repository abandonment. Missing SPDX licenses or archived upstream repositories prevent safe enterprise adoption.
- **Data Source:** GitHub REST API (`license.spdx_id`, `archived`).
- **Extraction Method:**
  $$\text{Raw} = (1.0 \times \mathbf{1}_{\text{no\_license}}) + (0.5 \times \mathbf{1}_{\text{copyleft\_gpl}}) + (1.0 \times \mathbf{1}_{\text{archived}})$$
- **Normalization Formula:**
  $$f_{\text{dep}} = \min(1.0, \max(0.0, \text{Raw}))$$
- **Assigned Weight:** $w_6 = 0.10$.

---

## 4. Risk Classification Tiers

| Score Range | Risk Tier | Interpretation & Recommended Action |
| :---: | :---: | :--- |
| **0.00 – 0.24** | `LOW` | Strong health, active community, permissive license, no critical advisories. Approved for production. |
| **0.25 – 0.49** | `MODERATE` | Minor maintenance lag or moderate advisory history. Acceptable with periodic review. |
| **0.50 – 0.74** | `HIGH` | High bus factor, unmaintained releases, or serious vulnerability signals. Requires security review. |
| **0.75 – 1.00** | `CRITICAL` | Confirmed critical CVEs, archived repository, or total maintainer abandonment. Block from production. |

---

## 5. Worked Example Calculation (`sample-crypto-lib` Fixture)

### Input Signals
- **Max CVSS:** 7.5 (GHSA-4v9c-982m-4786)
- **Total Vulns:** 2
- **Open Issues:** 42, **Stars:** 1250, **Forks:** 320
- **Monthly Commits:** 4.5 commits/mo
- **Contributor Count:** 3, **Top Contributor Ratio:** 0.82
- **Release Age:** 315 days
- **License:** MIT (permissive, active, non-archived)

### Calculations

1. **Vulnerability Factor:**
   $$\text{Raw} = 7.5 + (2 \times 0.5) = 8.5 \implies f_{\text{vuln}} = \frac{8.5}{10.0} = 0.8500$$
   $$\text{Contribution} = 0.8500 \times 0.30 = \mathbf{0.2550}$$

2. **Repository Health Factor:**
   $$\text{Ratio} = \frac{42}{1250 + 320 + 10} = 0.0266$$
   $$\text{Raw} = 0.0266 \times 5.0 = 0.1330 \implies f_{\text{health}} = \frac{0.1330}{5.0} = 0.0266$$
   $$\text{Contribution} = 0.0266 \times 0.20 = \mathbf{0.0053}$$

3. **Activity Factor:**
   $$\text{Raw} = 30.0 - 4.5 = 25.5 \implies f_{\text{activity}} = \frac{25.5}{30.0} = 0.8500$$
   $$\text{Contribution} = 0.8500 \times 0.15 = \mathbf{0.1275}$$

4. **Maintainer Factor:**
   $$\text{Raw} = 0.8200 \implies f_{\text{maintainer}} = 0.8200$$
   $$\text{Contribution} = 0.8200 \times 0.15 = \mathbf{0.1230}$$

5. **Release Recency Factor:**
   $$\text{Raw} = 315.0 \implies f_{\text{release}} = \frac{315.0}{730.0} = 0.4315$$
   $$\text{Contribution} = 0.4315 \times 0.10 = \mathbf{0.0432}$$

6. **Governance Factor:**
   $$\text{Raw} = 0.0000 \implies f_{\text{dep}} = 0.0000$$
   $$\text{Contribution} = 0.0000 \times 0.10 = \mathbf{0.0000}$$

### Composite Risk Sum:
$$R = 0.2550 + 0.0053 + 0.1275 + 0.1230 + 0.0432 + 0.0000 = \mathbf{0.5540} \implies \text{Classification: } \mathbf{HIGH}$$

---

## 6. Reproducibility & Audit Protocol

1. **Unique Analysis ID:** Every run generates an audit-traceable ID (e.g. `RA-4E8F2A`).
2. **Deterministic Execution:** Evaluating the same repository with identical configuration produces byte-for-byte identical composite scores (verified by Pytest test `T12`).
3. **Database Audit Snapshot:** SQLite stores the complete feature breakdown, weights applied, scoring version, and timestamp.

---

## 7. Scope & Engineering Interpretation

1. **GitHub API Scope**: Phase 1 signal collection focuses on GitHub repositories.
2. **Ecosystem Name Resolution**: Package name is derived from repo name; detailed multi-language lockfile parsing (e.g. `Cargo.lock`, `go.sum`) is scheduled for CP2.
3. **No Unvalidated ML Claims**: Machine learning predictive calibration (Objectives O3 & O4) is explicitly reserved for CP2 validation.
4. **Heuristic Assessment**: The score is an explainable engineering baseline and heuristic risk assessment, not definitive proof that a repository is secure or compromised.

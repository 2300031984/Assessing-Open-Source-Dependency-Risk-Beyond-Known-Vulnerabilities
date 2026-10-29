# CYBER-100 CLI Reference Manual

**Assessing Open Source Dependency Risk Beyond Known Vulnerabilities**  
*Production Developer Terminal Interface (inspired by `driftctl`)*

---

## 1. Overview & Capabilities

The CYBER-100 CLI provides a modern, production-grade terminal tool for evaluating open-source dependency security. It executes directly from the command line, integrating with the core risk analysis engine, GitHub collector, OSV intelligence provider, database persistence layer, and 6-dimensional scoring model.

### Key Capabilities
- **Direct Repository Analysis**: Analyzes packages directly using shorthand `owner/repo` (e.g., `psf/requests`) or full GitHub URLs.
- **Dual Live / Offline Modes**: Conducts live API queries or deterministic offline analysis using `--fixture`.
- **Structured Driftctl-Inspired UI**: Renders clean rounded panels, progress meters, multi-tier risk breakdown tables, and diagnostic narratives.
- **Machine-Readable Export**: Generates clean, parseable JSON via `--json` or saves structured reports to disk via `--output report.json`.
- **Historical Analysis Inspection**: Queries recent assessments (`history`) and inspects prior reports by unique Analysis ID (`show`).
- **Subsystem Diagnostics**: Verifies database and external intelligence API health and latency (`health`).
- **Standardized Process Exit Codes**: Facilitates seamless integration into CI/CD pipelines and automated security scanners.

---

## 2. Technology Stack & Design Principles

| Component | Library / Standard | Purpose |
| :--- | :--- | :--- |
| **Command Dispatcher** | `typer>=0.9.0` | CLI argument parsing, subcommands, flags, and help menus |
| **Terminal Rendering** | `rich>=13.0.0` | Rounded panels, color-coded tiers, ASCII progress meters, tables |
| **Data Validation** | `pydantic>=2.0.0` | Schema verification and type-safe data serialization |
| **Persistence** | `SQLAlchemy` | Local SQLite ORM transaction management and audit persistence |
| **Color Mapping** | Modern restrained palette | `LOW` (Green), `MODERATE` (Yellow), `HIGH` (Dark Orange), `CRITICAL` (Bold Red) |
| **Platform Portability** | UTF-8 auto-reconfiguration | Robust execution across Windows PowerShell, Linux, and macOS |

---

## 3. Command Synopsis

All commands are executed using the Python module syntax from the project root:

```bash
python -m backend.cli [OPTIONS] COMMAND [ARGS]...
```

### Global Options
- `--version`, `-v`: Display CLI and scoring engine version.
- `--no-color`: Disable all ANSI colors and styling (useful for plain text logs or dumb terminals).
- `--help`: Display available commands, arguments, and options.

---

## 4. Commands Reference

### 4.1. `analyze`

Perform deep multi-dimensional risk analysis on an open-source repository.

```bash
python -m backend.cli analyze REPOSITORY [OPTIONS]
```

#### Arguments
- `REPOSITORY` *(Required)*: Repository identifier in `owner/repo` (e.g., `psf/requests`) or full URL format (`https://github.com/psf/requests`).

#### Options
- `--json`: Output raw analysis results as unadorned, parseable JSON to stdout.
- `-o`, `--output PATH`: Save the complete analysis report as formatted JSON to the specified file path.
- `--fixture`, `--offline`: Run deterministic offline analysis using pre-collected test fixtures (no live API calls required).

#### Examples

**Standard Interactive Live Analysis:**
```powershell
python -m backend.cli analyze psf/requests
```

**Offline Analysis with Deterministic Fixture:**
```powershell
python -m backend.cli analyze demo-owner/sample-crypto-lib --fixture
```

**JSON Output for Scripting / CI Pipeline:**
```powershell
python -m backend.cli analyze psf/requests --json
```

**Export Report to JSON File:**
```powershell
python -m backend.cli analyze psf/requests --output reports/requests_audit.json
```

---

### 4.2. `history`

List recent repository risk analyses stored in the local SQLite database.

```bash
python -m backend.cli history [OPTIONS]
```

#### Options
- `-n`, `--limit INTEGER`: Maximum number of records to display (default: 10).
- `--json`: Output historical records as formatted JSON.

#### Examples

**View 5 Most Recent Analyses:**
```powershell
python -m backend.cli history --limit 5
```

**Export History as JSON:**
```powershell
python -m backend.cli history --limit 20 --json
```

---

### 4.3. `show`

Inspect the complete detailed results of a previously executed risk assessment by unique Analysis ID.

```bash
python -m backend.cli show ANALYSIS_ID [OPTIONS]
```

#### Arguments
- `ANALYSIS_ID` *(Required)*: Unique Analysis ID (e.g., `RA-0D4964`).

#### Options
- `--json`: Output analysis record as formatted JSON.

#### Examples

**Inspect Assessment in Terminal:**
```powershell
python -m backend.cli show RA-0D4964
```

**Export Assessment by ID as JSON:**
```powershell
python -m backend.cli show RA-0D4964 --json
```

---

### 4.4. `health`

Verify connectivity, latency, and status of internal database and external intelligence APIs.

```bash
python -m backend.cli health [OPTIONS]
```

#### Options
- `--json`: Output subsystem diagnostics as formatted JSON.

#### Checks Performed
1. **Local Database (SQLite)**: Executes test ping query and returns count of indexed repositories.
2. **GitHub REST Intelligence API**: Pings rate-limit endpoint, measures latency, and reports remaining request quota.
3. **OSV Vulnerability Intelligence API**: Verifies public OSV vulnerability database connectivity and latency.

#### Examples

**Run Diagnostic Check:**
```powershell
python -m backend.cli health
```

**Output Diagnostics as JSON:**
```powershell
python -m backend.cli health --json
```

---

## 5. Visual Design & Terminal Layout

The CLI presents analysis output with structured visual hierarchy:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Open Source Dependency Risk Analyzer                                       │
│  Dependency security and health beyond known CVEs                           │
└─────────────────────────────────────────────────────────────────────────────┘
┌───────────────────────────── Overview & Target ─────────────────────────────┐
│  Repository:  psf/requests                              Mode:  LIVE DATA    │
│  Target URL:  https://github.com/psf/requests         Status:  Active       │
│    Language:  Python                                 License:  Apache-2.0   │
│ Risk Rating:  0.38 / 1.00  [MODERATE]         Classification:  MODERATE     │
└─────────────────────────────────────────────────────────────────────────────┘
                           Risk Dimension Breakdown                            
┌──────────────────┬────────────┬────────────┬──────┬────────────┬────────────┐
│ Risk Dimension   │ Raw Signal │ Normalized │ Wgt  │ Contribut. │ Risk Meter │
├──────────────────┼────────────┼────────────┼──────┼────────────┼────────────┤
│ Known Vulns      │      13.00 │     1.0000 │ 0.30 │     0.3000 │ ██████████ │
│ Repository Health│       0.15 │     0.0300 │ 0.20 │     0.0060 │ ░░░░░░░░░░ │
│ Project Activity │       0.00 │     0.0000 │ 0.15 │     0.0000 │ ░░░░░░░░░░ │
│ Maintainer Health│       0.35 │     0.3487 │ 0.15 │     0.0523 │ ███░░░░░░░ │
│ Release Practices│     167.00 │     0.2288 │ 0.10 │     0.0229 │ ██░░░░░░░░ │
│ Governance       │       0.00 │     0.0000 │ 0.10 │     0.0000 │ ░░░░░░░░░░ │
└──────────────────┴────────────┴────────────┴──────┴────────────┴────────────┘
                   Known Vulnerability Signals (16 reported)                   
┌───────────────┬────────┬────────┬────────────────────────────┬──────────────┐
│ Advisory ID   │ Sever… │   CVSS │ Summary Snippet            │ Fixed Vers.  │
├───────────────┼────────┼────────┼────────────────────────────┼──────────────┤
│ GHSA-9hjg-9r… │ MEDIUM │    5.0 │ Requests vulnerable to ... │ 2.32.4       │
└───────────────┴────────┴────────┴────────────────────────────┴──────────────┘
┌─────────────────────────── Diagnostic Assessment ───────────────────────────┐
│  Composite Risk Score: 0.38 (MODERATE). The assessment is primarily         │
│  influenced by known vulnerability signals.                                 │
└─────────────────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────────────────┐
│  Analysis ID: RA-0D4964  •  Version: v0.1  •  Duration: 16.15s              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Process Exit Codes

The CLI follows standard UNIX exit code conventions:

| Exit Code | Meaning | Typical Causes |
| :---: | :--- | :--- |
| **`0`** | **Success** | Analysis completed successfully, command executed cleanly. |
| **`1`** | **Runtime / Service Error** | Repository not found (404), network timeout, external API failure, database unreachable. |
| **`2`** | **Invalid Input / Arguments** | Malformed repository syntax, invalid analysis ID on `show`, unwriteable output file path. |

---

## 7. Security & Credential Protection

- **Zero Secret Exposure**: The CLI actively scrubs API keys and GitHub personal access tokens (`ghp_...`, `github_pat_...`) before printing any error message or panel.
- **TLS Verification**: All HTTPS requests to GitHub and OSV enforce strict TLS certificate validation.
- **Non-Destructive**: The tool performs passive intelligence collection only. It never modifies local repositories or runs untrusted package code.
- **Environment Configuration**: Reuses existing `.env` credentials (`GITHUB_TOKEN`, `DATABASE_URL`, `API_TIMEOUT_SECONDS`).

---

## 8. Heuristic Assessment Notice & Disclaimer

> [!IMPORTANT]
> The composite risk score produced by the CYBER-100 CLI is a **heuristic risk assessment** based on multi-dimensional repository governance, release cadence, maintainer concentration, and public vulnerability advisories.
> 
> A **LOW** risk score indicates strong hygiene signals but does not prove the absence of latent zero-day vulnerabilities or malicious code. Conversely, a **HIGH** risk score reflects elevated maintenance fragility or vulnerability density but does not constitute conclusive evidence that a dependency has been actively compromised.

# System Architecture

CYBER-100 is a transparent and reproducible dependency-risk assessment prototype. CP1 focuses on O1 signal collection and O2 composite risk assessment.

## Data Flow
1. Repository URL input.
2. Signal collection: repository metadata, activity, contributor concentration, release information, and OSV vulnerability signals.
3. Feature extraction converts collected signals into quantitative features.
4. Normalization maps features to 0.0–1.0 risk values.
5. Scoring applies the configured weighted composite model.
6. Classification maps the score to LOW, MODERATE, HIGH, or CRITICAL.
7. Explanation returns factor breakdown and evidence-oriented rationale.
8. SQLite persistence stores analysis results.
9. FastAPI and Streamlit present the result.

## Execution Modes
- LIVE DATA: queries GitHub and OSV APIs.
- DEMO FIXTURE: deterministic offline fixture mode for repeatable demonstrations.

## Main Components
- FastAPI backend
- GitHub collector
- OSV collector
- Feature extractor and normalizer
- Risk scoring engine
- SQLite persistence
- Streamlit dashboard

## CP1 Boundary
The current milestone targets O1 and O2. Historical validation, comparative evaluation, deeper lockfile parsing, and operational impact assessment are planned for later phases.


## Verification
The architecture is designed so collection, feature extraction, scoring, persistence, and presentation remain separately testable components.

# Prototype API Contract

## Health Check
`GET /api/v1/health`

## Analyze Repository
`POST /api/v1/analyze`

Example request:
```json
{"repository_url":"https://github.com/psf/requests","use_demo_fixture":false}
```

Response fields include `analysis_id`, `repository`, `risk_score`, `risk_level`, `explanation`, `scoring_version`, `feature_version`, and `is_demo_fixture`.

The API separates signal collection from assessment so live data and deterministic fixtures can feed the same scoring pipeline.

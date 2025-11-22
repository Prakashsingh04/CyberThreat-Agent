# API Specification — Cybersecurity AI Detection System

This document provides a complete reference for the public HTTP API exposed by this project: endpoints, request/response schemas, query parameters, error handling, and examples. For interactive documentation, see /docs when the server is running.

- Base URL: http://127.0.0.1:8000
- API Prefix: /api/v1
- Docs: /docs (Swagger UI), /redoc, /openapi.json
- Dashboard: /web/dashboard
- Health: /health, Info: /info
- Auth: None (lab/demo). For production, add JWT/OAuth and RBAC.

---
## 1. Conventions

- Content type: application/json
- Time format: ISO 8601 strings
- IDs: strings (UUID-like) in threat store
- Status codes: 2xx success, 4xx client error, 5xx server error
- Pagination: limit (default 100), offset (default 0) on list endpoints

---
## 2. Data Models (Pydantic)

### 2.1 InputData
```
POST bodies that include feature vectors
{
  features: number[70..79]   # 70, 75, or 79 numeric values
}
```
Validation:
- length in {70, 75, 79}
- all items numeric (float|int)

### 2.2 PredictionResponse
```
{
  prediction: string,          # e.g., "ATTACK" or "BENIGN"
  confidence: number|null,     # reserved (may be null)
  model_used: string,          # e.g., "Autoencoder Neural Network"
  processing_time: number,     # seconds
  status: "success"
}
```

### 2.3 PipelineResponse
```
{
  detection: {
    label: string|null,        # reserved for classification (null for anomaly)
    confidence: number|null,   # reserved
    model_used: "autoencoder",
    anomaly: "ATTACK"|"BENIGN",
    source_ip: string|null,
    endpoint: string|null
  },
  simulation: {
    simulation_id: string,
    entry_point: string,
    attack_type: string,
    possible_paths: [
      {
        path: string[],
        probability: number,
        techniques: string[],
        estimated_time: string,
        risk_score: number
      }
    ],
    critical_assets_at_risk: string[],
    recommended_defenses: string[],
    timestamp: string
  }|null,
  actions: [ { action: string, targets?: any, priority?: string } ],
  enforcement: { executed: any[] } | {},
  feedback_recorded: boolean
}
```

### 2.4 InjectThreatRequest
```
{
  entry_point?: string,
  attack_type: string,         # e.g., "DDoS", "PortScan"
  severity?: "low"|"medium"|"high"|"critical",
  notes?: string,
  source_ip?: string,
  endpoint?: string,
  auto_remediate?: boolean     # default true
}
```

### 2.5 ThreatOut / ThreatListOut
```
ThreatOut = {
  id: string,
  timestamp: string,             # ISO time
  status: "active"|"remediated",
  type: string,                  # e.g., "Anomaly", "Simulation:DDoS"
  severity: "low"|"medium"|"high"|"critical",
  source_ip?: string,
  endpoint?: string,
  model?: string,
  details: object,
  actions: object[]              # action history
}

ThreatListOut = { items: ThreatOut[], total: number }
```

---
## 3. Threat Detection API

Prefix: /api/v1

### 3.1 GET /
- Purpose: API home metadata
- Response: summary of status and available models/classes

### 3.2 POST /predict/anomaly/autoencoder
- Purpose: Run autoencoder anomaly detection on a feature vector
- Request: InputData
- Success 200 Response: PredictionResponse
- Errors:
  - 400 invalid features
  - 503 model or scaler unavailable

Example (PowerShell):
```powershell
$body = @{ features = @(0,0,0,0,0,0,0,0) + (1..62 | ForEach-Object { 0 }) }
Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/predict/anomaly/autoencoder" `
  -ContentType 'application/json' `
  -Body ($body | ConvertTo-Json)
```

### 3.3 GET /models/status
- Purpose: Check which models and preprocessors are loaded
- Response: { models: {...}, preprocessing: {...} }

### 3.4 GET /info/classes
- Purpose: List supported classes (if label encoder is loaded)
- Errors: 503 if label encoder not loaded

### 3.5 POST /pipeline/process
- Purpose: Orchestrate end-to-end pipeline (validate → preprocess → detect → (simulate) → decide → respond → feedback)
- Query params: entry_point (default web_server), max_steps (default 3), source_ip?, endpoint_name?
- Request: InputData
- Response: PipelineResponse

---
## 4. Simulation API

Prefix: /api/v1/simulation

### 4.1 GET /
- Purpose: Simulation API home metadata

### 4.2 POST /simulate-attack
- Request: AttackSimulationRequest
- Response: SimulationResponse
- Errors:
  - 400 unsupported attack type
  - 500 simulation failed

### 4.3 POST /mitre-mapping
- Request: MITREMappingRequest
- Response: MITREResponse
- Errors:
  - 404 mapping not found

### 4.4 POST /analyze-network
- Request: NetworkAnalysisRequest
- Response: NetworkAnalysisResponse

### 4.5 GET /attack-paths/{entry_point}
- Query: max_depth (default 3)
- Response: paths and metrics
- Errors:
  - 400 unknown entry point

### 4.6 GET /techniques
- Response: all techniques with associated tactics

### 4.7 GET /assets
- Response: asset inventory and categories

---
## 5. Threat Management API

Prefix: /api/v1

### 5.1 GET /threats
- Query: status?, severity?, q?, limit=100, offset=0
- Response: ThreatListOut

### 5.2 GET /threats/{threat_id}
- Response: ThreatOut
- Errors:
  - 404 if not found

### 5.3 POST /threats/{threat_id}/remediate
- Body: { notes?: string }
- Response: { status: "remediated", id }
- Errors: 404 if not found

### 5.4 POST /threats/{threat_id}/label
- Body: { label: "tp"|"fp" }
- Response: { status: "labeled", id, label }
- Errors: 400 invalid label | 404 not found

### 5.5 POST /threats/{threat_id}/outcome
- Body: { outcome: "contained"|"recurring" }
- Response: { status: "updated", id, outcome }
- Errors: 400 invalid outcome | 404 not found

### 5.6 POST /threats/quick/network-scan
- Response: stubbed scan results (demo)

### 5.7 POST /threats/quick/log-analysis
- Response: basic analysis of logs/monitor.log

### 5.8 GET /statistics/threats
- Response: counts (from threats_service.stats)

### 5.9 GET /analytics/threats
- Response: totals, severity distribution, MTTR, daily trend

### 5.10 GET /logs/security
- Query: limit=200
- Response: newest-first tail of logs/monitor.log

---
## 6. Dashboard & Utility API

Prefix: /web

### 6.1 GET /dashboard
- Purpose: Render dashboard HTML

### 6.2 GET /dashboard/api/stats
- Purpose: Combined stats for UI (models, requests, security, system monitor snapshot)

### 6.3 POST /dashboard/api/monitor/start
- Query: source = "system" (default) | "log"
- Response: start status and mode

### 6.4 POST /dashboard/api/monitor/stop
- Response: stop status

### 6.5 POST /dashboard/api/log-activity
- Body: arbitrary activity object; increments counters

### 6.6 GET /dashboard/* (detection|simulation|analytics|models|settings)
- Purpose: Render feature-specific pages

### 6.7 GET /dashboard/api/model-status
- Purpose: Detailed model inventory and online/offline status

### 6.8 GET /dashboard/api/attack-types
- Purpose: Attack taxonomy for UI

### 6.9 GET /dashboard/api/system-info
- Purpose: System metrics (CPU/mem/disk); degrades if psutil missing

Other utility (no prefix):
- GET /health — comprehensive health
- GET /info — API capabilities and examples

---
## 7. Errors & Status Codes

| Case | Status | Example |
|------|--------|---------|
| Invalid feature vector | 400 | { "detail": "Expected 70, 75, or 79 features" }
| Missing model/scaler | 503 | { "detail": "Autoencoder model or scaler unavailable" }
| Resource not found | 404 | { "detail": "Threat not found" }
| Simulation/mapping error | 500/404 | { "detail": "Simulation failed: ..." }

---
## 8. Filtering & Pagination

- /threats supports: status, severity, q (free-text search), limit, offset
- Default limit 100; offset 0

---
## 9. Usage Examples (PowerShell)

### 9.1 Detect anomaly via autoencoder
```powershell
$features = 0..69 | ForEach-Object { 0 }
$body = @{ features = $features }
Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/predict/anomaly/autoencoder" `
  -ContentType 'application/json' `
  -Body ($body | ConvertTo-Json)
```

### 9.2 Run full pipeline
```powershell
$features = 0..69 | ForEach-Object { 0 }
$body = @{ features = $features }
Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/pipeline/process?entry_point=web_server&max_steps=3" `
  -ContentType 'application/json' `
  -Body ($body | ConvertTo-Json)
```

### 9.3 Simulate a DDoS attack
```powershell
$body = @{ entry_point = 'web_server'; attack_type = 'DDoS'; max_steps = 3 }
Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/simulation/simulate-attack" `
  -ContentType 'application/json' `
  -Body ($body | ConvertTo-Json)
```

### 9.4 List threats (active, high severity)
```powershell
Invoke-RestMethod -Method Get `
  -Uri "http://127.0.0.1:8000/api/v1/threats?status=active&severity=high&limit=50&offset=0"
```

---
## 10. Versioning & Compatibility

- Current API version: v1 (prefix /api/v1)
- Backward-compatible additions: new fields added as optional; clients should ignore unknown fields

---
## 11. Security Notes (Important for Production)

- Add authentication (JWT/OAuth) and role-based access (analyst, admin)
- Enforce HTTPS/TLS in production
- Rate limit sensitive endpoints
- Validate and sanitize inputs rigorously (avoid extreme floats, NaN/Inf)
- Consider switching threat persistence from JSON to a database for integrity

---
## 12. Changelog

- 2025-11-09: Initial API specification document created

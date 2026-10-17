# Data Directory

Contains datasets and the runtime threat store used by the Cybersecurity AI Detection System.

## Layout

```
data/
├── raw/                  # Original downloaded datasets (e.g., CICIDS2017 CSVs) — gitignored
├── processed/            # Cleaned, feature-engineered data — gitignored
│   └── threats.json      # Runtime threat store (created/maintained by the app)
└── mitre_mappings.json   # Attack-class → MITRE ATT&CK technique mapping (optional)
```

> ⚠️ `data/processed/` is gitignored. Only `data/README.md` is tracked. The runtime file `processed/threats.json` is created and managed by the application at runtime.

## Threat store maintenance

Threat records are persisted to `data/processed/threats.json`. Administrative cleanup endpoints (require `confirm=true`):

| Endpoint | Body | Description |
|----------|------|-------------|
| `POST /api/v1/admin/purge` | `{ "confirm": true }` | Delete all threat records |
| `POST /api/v1/admin/purge-oldest` | `{ "count": 300, "confirm": true }` | Remove the oldest N threat records |
| `POST /api/v1/admin/clear-logs` | `{ "confirm": true }` | Clear `logs/monitor.log` and `logs/feedback.jsonl` |

### PowerShell examples

```powershell
# Remove oldest 300 threat records
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/admin/purge-oldest `
  -Body (@{count=300;confirm=$true} | ConvertTo-Json) -ContentType 'application/json'

# Remove all threat records
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/admin/purge `
  -Body (@{confirm=$true} | ConvertTo-Json) -ContentType 'application/json'

# Clear monitor + feedback logs
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/admin/clear-logs `
  -Body (@{confirm=$true} | ConvertTo-Json) -ContentType 'application/json'
```

All endpoints require `confirm=true` to prevent accidental mass deletion.

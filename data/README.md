 
# Data Directory

Contains the datasets used in the project.

- `raw/`: Original downloaded datasets (e.g., CICIDS2017 CSV files).
- `processed/`: Cleaned and feature-engineered datasets ready for model training or inference.
- `mitre_mappings.json`: Mapping of attack classes to MITRE ATT&CK framework techniques.

## Threat Store Maintenance

Runtime threat records are persisted to `processed/threats.json`.
Administrative cleanup endpoints:

- Purge ALL threats: `POST /api/v1/admin/purge` body `{ "confirm": true }`
- Purge OLDEST N threats (e.g. bottom 300): `POST /api/v1/admin/purge-oldest` body `{ "count": 300, "confirm": true }`
- Clear logs (`monitor.log`, `feedback.jsonl`): `POST /api/v1/admin/clear-logs` body `{ "confirm": true }`

### PowerShell Examples

```powershell
# Remove oldest 300 threat records
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/admin/purge-oldest -Body (@{count=300;confirm=$true} | ConvertTo-Json) -ContentType 'application/json'

# Remove all threat records
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/admin/purge -Body (@{confirm=$true} | ConvertTo-Json) -ContentType 'application/json'

# Clear monitor + feedback logs
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/admin/clear-logs -Body (@{confirm=$true} | ConvertTo-Json) -ContentType 'application/json'
```

All endpoints require `confirm=true` to prevent accidental mass deletion.

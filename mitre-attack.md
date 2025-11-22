# MITRE ATT&CK — Project Coverage and Usage Guide

This document centralizes everything in the project that relates to the MITRE ATT&CK framework: what techniques/tactics we cover, where we use them, how to query them via APIs, how we map detections to ATT&CK, recommended mitigations, and how to extend coverage.

- Audience: security engineers, data scientists, SOC analysts
- Scope: simulation, detection, response alignment to ATT&CK

---
## 1) Where MITRE ATT&CK is used in this project

- Attack Simulation API (`api/simulation_api.py`)
  - Maintains a detailed `MITRE_MAPPINGS` dictionary per attack class (e.g., DDoS, PortScan, Bot).
  - Returns techniques, tactics, severity, detection methods, and next-likely steps.
  - Exposes endpoints to simulate attacks and retrieve mapping details.
- Simulator Agent (`agents/simulator_agent.py`)
  - Lightweight in-process variant; includes minimal `MITRE_MAPPINGS` for programmatic use by the pipeline.
- Pipeline Orchestrator (`api/routes.py` → `/pipeline/process`)
  - Runs simulation after an anomaly detection. The simulation response carries ATT&CK techniques and risk estimates.
- Dashboard
  - Surfaced indirectly via analytics and simulation panels (techniques and recommendations).

---
## 2) ATT&CK Coverage Summary

Tactics observed (non-exhaustive based on mappings):
- Impact (e.g., T1498/T1499 Denial of Service)
- Discovery (e.g., T1046 Network Service Scanning)
- Command and Control (e.g., T1071.001 Web Protocols)
- Exfiltration (e.g., T1041 Exfiltration Over C2)
- Credential Access (e.g., T1110.001 Password Guessing)
- Lateral Movement (e.g., T1021 Remote Services)
- Initial Access (e.g., T1190 Exploit Public-Facing Application)
- Execution (e.g., T1059.007 JavaScript)

Techniques included (highlights):
- T1498 Network Denial of Service; T1499 Endpoint Denial of Service; T1499.004 Application Exhaustion Flood
- T1046 Network Service Scanning
- T1071.001 Web Protocols (C2)
- T1041 Exfiltration Over C2 Channel
- T1110.001 Password Guessing
- T1021.{003,004} Remote Services (DCOM/SSH)
- T1190 Exploit Public-Facing Application
- T1059.007 JavaScript

Note: The authoritative, richer mapping lives in `api/simulation_api.py` under `MITRE_MAPPINGS`.

---
## 3) Canonical Mapping Source (from `api/simulation_api.py`)

For each attack class (e.g., "DDoS", "PortScan", "Bot"), `MITRE_MAPPINGS` defines:
- techniques: list of { id, name, tactic }
- severity: float in [0,1]
- tactics: list of tactic names
- detection_methods: list of practical detections/controls
- next_steps: suggested next techniques an adversary might attempt

Example (abridged):
```
"DDoS": {
  "techniques": [
    {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
    {"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"}
  ],
  "severity": 0.8,
  "tactics": ["Impact"],
  "detection_methods": ["Network traffic monitoring", "Bandwidth utilization analysis"],
  "next_steps": ["T1041", "T1071"]
}
```
Refer to the file for the complete mapping of: DDoS, DoS (Hulk/GoldenEye/Slowloris/Slowhttptest), PortScan, FTP-Patator, SSH-Patator, Web Attacks (Brute Force/XSS), Bot.

---
## 4) Using ATT&CK via APIs

- List techniques across all supported attack classes
  - GET `/api/v1/simulation/techniques`
- Fetch mapping for a specific class
  - POST `/api/v1/simulation/mitre-mapping` with `{ attack_class: "DDoS", include_chain: true }`
- Run a full attack simulation (returns techniques per path)
  - POST `/api/v1/simulation/simulate-attack` with `{ entry_point, attack_type, max_steps }`
- Quick attack paths from an entry point
  - GET `/api/v1/simulation/attack-paths/{entry_point}`

Typical response fields that carry ATT&CK details:
- `possible_paths[].techniques` (list of technique IDs used on that path)
- `recommended_defenses` (often aligned with ATT&CK mitigations)
- `mitre-mapping` outputs: `techniques`, `tactics`, `next_likely_steps`

---
## 5) Mapping detections to ATT&CK

Detection sources in this project:
- Anomaly Detection (Autoencoder): network/host features → anomaly label (ATTACK/BENIGN)
- Heuristics (SystemNetworkMonitor): SYN_SENT bursts, high unique remotes, high connection totals, etc.
- Log-based triggers (demo): keyword-driven to exercise pipeline

Mapping strategy:
- If anomaly = ATTACK, the pipeline calls the simulation engine with `attack_type="Anomaly"` (or a more specific class if available), which then attaches relevant ATT&CK techniques for context.
- Where classification is unavailable, ATT&CK context is inferred from the selected simulation class (e.g., choosing "DDoS" produces Impact techniques T1498/T1499).

Recommended enhancement:
- If a classifier is reintroduced, map each predicted class directly to ATT&CK techniques (one-to-many), and include those in the detection summary so ATT&CK context is present even without running a full simulation.

---
## 6) Recommended Mitigations (ATT&CK-aligned)

Common ATT&CK mitigation categories aligned to our recommendations:
- M1030 Network Traffic Filtering: rate-limits, blocklists, geofencing
- M1037 Filter Network Traffic / Network Segmentation: segment critical assets (db_server, domain_controller)
- M1018 User Account Management & M1036 Account Use Policies: brute-force protection, MFA
- M1042 Disable or Remove Feature or Program: reduce attack surface
- M1043 Credential Access Protection: lockouts, strong password policies
- M1047 Audit: detailed logging for authentication/network events
- M1031 Network Intrusion Prevention

Project-suggested actions (from decision/response modules):
- `isolate_assets` → network segmentation/quarantine (M1037)
- `block_ip` → IP-based filtering/rate limiting (M1030)
- `quarantine_endpoint` → endpoint containment (EDR/AV controls)
- `alert_operator` → human-in-the-loop review and escalation

---
## 7) ATT&CK Data Sources vs Our Signals

ATT&CK Data Sources (examples) and corresponding project sources:
- DS0029 Network Traffic → `psutil` rates, connection states, unique remote IPs
- DS0015 Application Logs → `logs/monitor.log` tailer (demo), threat analytics
- DS0011 Process → not directly collected (future work: process trees)
- DS0010 File → not directly collected (future: suspicious file I/O)
- DS0022 Cloud Service → not in scope in current demo

---
## 8) Coverage Matrix (Project ↔ ATT&CK)

| Project Feature | ATT&CK Tactic | Techniques (examples) | Notes |
|-----------------|----------------|-----------------------|-------|
| Port scan simulation | Discovery | T1046 | `simulate-attack(PortScan)` |
| DDoS/DoS simulation | Impact | T1498, T1499, T1499.004 | High traffic/conn anomalies |
| Brute force (FTP/SSH) | Credential Access | T1110.001 | Login failure patterns (future signals) |
| Bot/C2 | C2, Exfiltration | T1071.001, T1041 | Protocol anomalies/periodicity (future) |
| Web exploit/XSS | Initial Access, Execution | T1190, T1059.007 | Requires web/app logs (future) |

---
## 9) ATT&CK Navigator Layer (Example)

You can import this minimal layer into ATT&CK Navigator to visualize current focus techniques:

```json
{
  "version": "4.5",
  "name": "Project Focus Techniques",
  "description": "Techniques referenced by the project's simulation/mappings",
  "domain": "enterprise-attack",
  "techniques": [
    {"techniqueID": "T1498", "tactic": "impact", "score": 80},
    {"techniqueID": "T1499", "tactic": "impact", "score": 70},
    {"techniqueID": "T1499.004", "tactic": "impact", "score": 65},
    {"techniqueID": "T1046", "tactic": "discovery", "score": 60},
    {"techniqueID": "T1071.001", "tactic": "command-and-control", "score": 85},
    {"techniqueID": "T1041", "tactic": "exfiltration", "score": 50},
    {"techniqueID": "T1110.001", "tactic": "credential-access", "score": 70},
    {"techniqueID": "T1021.004", "tactic": "lateral-movement", "score": 55},
    {"techniqueID": "T1190", "tactic": "initial-access", "score": 65},
    {"techniqueID": "T1059.007", "tactic": "execution", "score": 50}
  ]
}
```

---
## 10) End-to-End Flow with ATT&CK Context

1. Ingest (system metrics/logs) → feature vector
2. Detect (Autoencoder) → `ATTACK` or `BENIGN`
3. If `ATTACK`, run simulation for contextualization
4. Simulation returns `possible_paths[].techniques` + `recommended_defenses`
5. Decision agent plans actions (some align to ATT&CK mitigations)
6. Response module simulates enforcement and updates threat store
7. Dashboard and analytics reflect ATT&CK-informed results

---
## 11) How to Extend ATT&CK Coverage

- Add new attack classes to `api/simulation_api.py::MITRE_MAPPINGS`
  - Provide realistic techniques, tactics, and detection methods
- Map classifier outputs (when enabled) to technique sets
  - Maintain a `CLASS_TO_TECHNIQUES` dict (one-to-many)
- Enrich data sources to support more tactics
  - Process creation trees (DS0011), file access (DS0010), authentication logs
- Attach ATT&CK metadata to threat records
  - Extend `threats_service.add_threat` to include `techniques: []` and `tactics: []`
- Visualize in UI
  - Display techniques on threat details; show Navigator-like coverage summary

---
## 12) Quality Gates and Validation

- API endpoints validated via FastAPI/Pydantic (400/404/500 patterns)
- Simulation mapping access tested by calling `/simulation/mitre-mapping` and `/simulation/techniques`
- Recommend adding unit tests to verify:
  - Each mapped attack class returns non-empty techniques/tactics
  - Techniques are stable and valid ATT&CK IDs
  - Recommended defenses include at least one ATT&CK mitigation category

---
## 13) References

- MITRE ATT&CK (Enterprise): https://attack.mitre.org/
- ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/
- Project files:
  - `api/simulation_api.py` (authoritative mapping and endpoints)
  - `agents/simulator_agent.py` (in-process simulation)
  - `api/routes.py` (pipeline orchestration)
  - `services/threats_service.py` (threat persistence)
  - `dashboard.py` (UI endpoints)

---
## 14) Summary

The project integrates MITRE ATT&CK primarily through the simulation layer, enriching anomaly detections with tactics/techniques, risk, and defense recommendations. This enables analysts to reason about likely adversary behavior and apply ATT&CK-aligned mitigations quickly. Expanding classifier-to-technique mapping and adding richer data sources will deepen coverage across tactics beyond Impact/Discovery/C2.

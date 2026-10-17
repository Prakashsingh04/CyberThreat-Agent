# CyberThreat-Agent

**Cybersecurity AI Detection System** — an end-to-end, threat-centric console that detects anomalies with an Autoencoder, continuously monitors your system, simulates attack paths, and auto-remediates with feedback — all surfaced in a live dashboard.

[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104-009688.svg?logo=fastapi)](https://fastapi.tiangolo.com/)
[![TensorFlow](https://img.shields.io/badge/TensorFlow-2.12-FF6F00.svg?logo=tensorflow)](https://www.tensorflow.org/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.3-F7931E.svg?logo=scikit-learn)](https://scikit-learn.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 🔍 Overview

CyberThreat-Agent is a FastAPI-based cybersecurity platform for real-time threat detection, analysis, and response. It combines deep learning (TensorFlow/Keras autoencoder) with classical ML (scikit-learn) to detect anomalies from live system/network events and log streams, then orchestrates a **detect → simulate → decide → respond → feedback** pipeline surfaced through a live Bootstrap dashboard.

## ✨ Features

- **Anomaly detection** — Autoencoder-based binary verdict (BENIGN vs ATTACK) with reconstruction-error scoring
- **Multi-class classification support** — MLP and LSTM model endpoints (12 CICIDS2017 attack classes)
- **Continuous monitoring** — psutil-based system/network sampler plus a log tailer watching `logs/monitor.log`
- **Attack simulation** — Plausible attack paths, techniques, and assets-at-risk generation with MITRE ATT&CK alignment
- **Automated response** — Planned enforcement actions (block IP, rate-limit, isolate endpoint) executed in safe mode by default
- **Threat management** — Persistent JSON threat store with CRUD, remediation, labeling, outcomes, and quick actions
- **Live dashboard** — Overview, live monitor stream, threat table, security logs, simulation tab, and analytics (status/severity charts, MTTR, daily trends)
- **REST API** — Full OpenAPI/Swagger documentation at `/docs`

## 🛠 Tech stack

| Layer | Technology |
|-------|------------|
| Backend | FastAPI, Uvicorn, Python 3.9+ |
| ML/DL | TensorFlow/Keras 2.12, scikit-learn 1.3, joblib |
| Monitoring | psutil |
| Frontend | Bootstrap 5, vanilla JavaScript, Chart.js, Jinja2 |
| Persistence | JSON threat store (`data/processed/threats.json`) |
| Dataset | CICIDS2017 |

## 📁 Project structure

```
CyberThreat-Agent/
├── main.py                     # FastAPI app entry point (lifespan, health, info, error handlers)
├── dashboard.py                # Web UI routes + monitor start/stop API
├── requirements.txt            # Python dependencies
├── config/
│   ├── settings.py             # Runtime config (safe mode, thresholds, env overrides)
│   └── logging.conf
├── api/
│   ├── routes.py               # Detection, anomaly, pipeline, inject-threat endpoints
│   ├── simulation_api.py       # Attack simulation endpoints
│   ├── threats_api.py          # Threat CRUD, analytics, security logs, admin maintenance
│   └── utils.py                # Model-file checks, prediction helpers, logging setup
├── agents/
│   ├── preprocessor.py         # Feature scaling with scaler.pkl
│   ├── detection_agent.py      # Autoencoder anomaly detection
│   ├── simulator_agent.py      # Attack-path simulation
│   ├── decision_agent.py       # Response-action planning
│   ├── response_module.py      # Simulated enforcement
│   ├── feedback.py             # Feedback logging to logs/feedback.jsonl
│   └── model_manager.py        # Model loading/caching (autoencoder, MLP, LSTM, Isolation Forest)
├── services/
│   ├── system_monitor.py       # psutil-based live sampler
│   └── threats_service.py      # JSON-backed threat store + stats
├── models/                     # Trained models & preprocessing objects (gitignored, see below)
├── data/
│   └── processed/threats.json  # Runtime threat store (gitignored)
├── logs/                       # monitor.log, feedback.jsonl, api.log (gitignored)
├── static/                     # CSS, JS for the dashboard
├── templates/                  # Jinja2 HTML templates
├── tests/                      # pytest suite
├── notebooks/                  # Jupyter exploration notebooks
├── scripts/                    # Helper/monitor scripts
├── .env                        # Local environment overrides (gitignored)
├── .gitignore
├── README.md
├── LICENSE
└── api-specs.md, mitre-attack.md, snippet.md
```

## ⚙️ Configuration

Runtime behavior is controlled by `config/settings.py` and overridable via environment variables:

| Variable | Default | Meaning |
|----------|---------|---------|
| `CYBERSEC_SAFE_MODE` | `1` | When `1`, response actions only log and update state (no real system changes) |
| `CYBERSEC_ENABLE_ENFORCEMENT` | `0` | Attempt actual system enforcement on Windows (ignored when safe mode is on) |
| `CYBERSEC_FW_RULE_PREFIX` | `CyberSecBlock` | Firewall rule name prefix for `block_ip` actions |
| `CYBERSEC_AUTO_REMEDIATE_SIM` | `1` | Auto-remediate threats created by the simulation endpoint |
| `CYBERSEC_MONITOR_SENSITIVITY` | `medium` | System monitor sensitivity: `low` \| `medium` \| `high` |
| `CYBERSEC_MONITOR_CONN_TOTAL` | `2500` | Total connections threshold |
| `CYBERSEC_MONITOR_UNIQUE_REMOTES` | `25` | Unique remote hosts threshold |
| `CYBERSEC_MONITOR_BYTES_SENT_MBPS` | `15.0` | Bytes-sent MB/s threshold |
| `CYBERSEC_MONITOR_COOLDOWN` | `30` | Cooldown seconds between repeat pipeline postings |

## 🧠 Models

The following models and preprocessing objects are expected in `models/`:

| File | Purpose |
|------|---------|
| `autoencoder_model.h5` | Keras autoencoder for anomaly detection (primary detector) |
| `isolation_forest.pkl` | scikit-learn Isolation Forest anomaly detector |
| `mlp_model.h5` | Multi-Layer Perceptron multi-class classifier |
| `lstm_model.h5` | LSTM sequential classifier |
| `scaler.pkl` | StandardScaler for feature normalization |
| `label_encoder.pkl` | LabelEncoder for class-name ↔ label conversion |

> ⚠️ **Model binaries are not tracked in Git.** `models/*.h5` and `models/*.pkl` are in `.gitignore`. You must place your own trained files in `models/` before running detection/anomaly endpoints; otherwise those endpoints return `503`. See `models/README.md` for details.

Supported attack classes (12): `BENIGN`, `Bot`, `DDoS`, `DoS GoldenEye`, `DoS Hulk`, `DoS Slowhttptest`, `DoS slowloris`, `FTP-Patator`, `PortScan`, `SSH-Patator`, `Web Attack - Brute Force`, `Web Attack - XSS`.

Input feature length: `70`, `75`, or `79` numerical features (automatic preprocessing handles scaling).

## 🚀 Quick start

### 1) Clone and create a virtual environment

```powershell
# Windows PowerShell
git clone https://github.com/Prakashsingh04/CyberThreat-Agent.git
cd CyberThreat-Agent
python -m venv venv
./venv/Scripts/Activate
```

```bash
# Linux / macOS
git clone https://github.com/Prakashsingh04/CyberThreat-Agent.git
cd CyberThreat-Agent
python3 -m venv venv
source venv/bin/activate
```

### 2) Install dependencies

```powershell
pip install -r requirements.txt
```

### 3) Add trained models

Place your model files in `models/`:
- `autoencoder_model.h5`, `scaler.pkl`, `label_encoder.pkl` (minimum for anomaly detection)
- `mlp_model.h5`, `lstm_model.h5`, `isolation_forest.pkl` (optional classification models)

### 4) Run the app

```powershell
python .\main.py
```

The app starts on `http://127.0.0.1:8000`:
- 🖥 Dashboard: `http://127.0.0.1:8000/web/dashboard`
- 📖 API docs: `http://127.0.0.1:8000/docs`
- ❤ Health: `http://127.0.0.1:8000/health`

> Alternatively: `uvicorn main:app --reload`

## 🖥 Using the dashboard

1. **Live Monitor** — Click "Start Monitor". This starts both the system sampler (psutil) and the log tailer. Safe periods emit heartbeats; spikes appear as red alerts.
2. **Threat Management** — Filter by status/severity, open details, and remediate from the UI. Quick actions: stubbed network scan and log analysis.
3. **Security Logs** — Shows the newest-first lines from `logs/monitor.log`.
4. **Attack Simulation** — Run a scenario (entry point, attack type, steps) and use "Create Test Threat" to inject a synthetic threat record.
5. **Analytics** — Status split, severity distribution, daily trends, MTTR; export analytics JSON.

## 📚 API highlights

Base path: `/api/v1`

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/predict/anomaly/autoencoder` | POST | Autoencoder anomaly verdict (70/75/79 features) |
| `/pipeline/process` | POST | Full detect → simulate → decide → respond → feedback orchestration |
| `/simulation/simulate-attack` | POST | Generate plausible attack paths and defenses |
| `/simulation/inject-threat` | POST | Create a test threat from a simulation scenario |
| `/threats` | GET | List threats with status/severity/search filters |
| `/threats/{id}` | GET | Threat detail |
| `/threats/{id}/remediate` | POST | Mark a threat as remediated |
| `/analytics/threats` | GET | Totals, severity, MTTR, daily trend |
| `/logs/security` | GET | Last N monitor-log lines (newest first) |
| `/dashboard/api/monitor/start\|stop` | POST | Start/stop system + log monitors |
| `/dashboard/api/stats` | GET | Dashboard summary stats |
| `/health` \| `/info` | GET | System health and API metadata |

OpenAPI/Swagger UI: `http://127.0.0.1:8000/docs`

## 🔄 Architecture & data flow

```
Ingest → Preprocess → Detect → Simulate → Decide → Respond → Feedback
```

1. **Ingest** — `SystemNetworkMonitor` (psutil) samples connections/IO, or the log tailer watches `logs/monitor.log` for `MALICIOUS` lines → produces a 70-dim feature vector
2. **Preprocess** — `agents.preprocessor.prepare(...)` loads `scaler.pkl` and normalizes features
3. **Detect** — `agents.detection_agent.detect_anomaly(..., method='autoencoder')` returns BENIGN vs ATTACK
4. **Simulate** — On ATTACK, `agents.simulator_agent.simulate_attack(...)` generates attack paths, techniques, assets-at-risk
5. **Decide** — `agents.decision_agent.plan_actions(...)` proposes controls (block IP, rate-limit, isolate endpoint)
6. **Respond** — `agents.response_module.enforce(...)` performs simulated enforcement and updates threat actions
7. **Feedback** — `agents.feedback.record(...)` appends a JSON line to `logs/feedback.jsonl`

Storage:
- Models: `models/` (gitignored — bring your own)
- Threat store: `data/processed/threats.json` (gitignored, created at runtime)
- Monitor log: `logs/monitor.log` (gitignored)
- Feedback: `logs/feedback.jsonl` (gitignored)

## 🧪 Testing

```powershell
pip install -r requirements.txt
pytest
```

## 🗺 Roadmap & contributing

Low-risk enhancements welcome:
- Monitor source toggle (system-only / log-only / both) + network health chip
- Persist simulation history and allow replay
- MITRE ATT&CK overlay per path in the Simulation tab
- Tests for analytics and simulation threat-injection endpoints

Contributions are welcome. Open an issue or PR with a concise proposal and scope. Please keep enforcement-related changes in safe mode by default.

## ⚠️ Security notice

Response/enforcement actions are **disabled by default** (`CYBERSEC_SAFE_MODE=1`). When safe mode is on, actions only log and update state — no firewall rules, process kills, or network changes are made. Enable real enforcement only if you understand the risks and are running in an isolated environment.

## 📄 License

MIT License. See `LICENSE`.

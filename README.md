# Cybersecurity AI Detection System

End-to-end, threat-centric console that detects anomalies with an Autoencoder, continuously monitors your system, simulates attack paths, and auto-remediates with feedback — all surfaced in a live dashboard.

• Backend: FastAPI, Python
• ML/DL: TensorFlow/Keras Autoencoder, scikit-learn StandardScaler
• Monitoring: psutil-based SystemNetworkMonitor + log tailer
• UI: Bootstrap + vanilla JS, Chart.js



- Autoencoder anomaly detection pipeline with end-to-end orchestration:
	ingest → preprocess → detect → simulate → decide → respond → feedback

- Live Monitor that streams events from two sources:
	- SystemNetworkMonitor sampling connections and IO, posting suspicious spikes
	- Log tailer that watches `logs/monitor.log` for malicious entries

- Threat Management with persistent JSON store: list, view, remediate, quick actions

- Security Logs for situational awareness

- Attack Simulation with “Create Test Threat” to exercise the full lifecycle

- Analytics with severity/status charts, MTTR.


## Architecture and flow

1. Event Ingest
	 - SystemNetworkMonitor (psutil) or log tailer generates a 70-dim feature vector.
2. Preprocess
	 - `agents.preprocessor.prepare(...)` loads `scaler.pkl` and normalizes features.
3. Detect (Autoencoder only)
	 - `agents.detection_agent.detect_anomaly(..., method='autoencoder')` returns BENIGN vs ATTACK.
4. Simulate
	 - If ATTACK, `agents.simulator_agent.simulate_attack(...)` generates plausible paths, techniques, and assets-at-risk.
5. Decide
	 - `agents.decision_agent.plan_actions(...)` proposes controls (block IP, rate-limit, isolate endpoint).
6. Respond
	 - `agents.response_module.enforce(...)` performs a simulated enforcement and updates threat actions.
7. Feedback
	 - `agents.feedback.record(...)` appends a JSON line to `logs/feedback.jsonl` for learning.

storage
- Models: `models/autoencoder_model.h5`, `models/scaler.pkl`, `models/label_encoder.pkl`
- Threat store: `data/processed/threats.json`
- Monitor log: `logs/monitor.log`

Key services/files:
- `api/routes.py` — Pipeline, anomaly prediction, simulation-based threat injection
- `api/threats_api.py` — Threats CRUD, quick actions, statistics, analytics, security logs
- `dashboard.py` — Web UI routes and monitor control (start/stop, stats)
- `services/system_monitor.py` — psutil-based sampler posting suspicious events
- `services/threats_service.py` — Persistent JSON store helpers
- `static/js/dashboard.js` — Live Monitor, Threats UI, Analytics charts, Simulation UI




## Quick start (Windows PowerShell)

```
python -m venv venv
./venv/Scripts/Activate

# 2) Install dependencies (TensorFlow, FastAPI, psutil, etc.)
pip install -r requirements.txt

# 3) Run the app (starts FastAPI + Dashboard)
python .\main.py
```


### First run tips

- Models: Place `autoencoder_model.h5`, `scaler.pkl`, and `label_encoder.pkl` in `models/`.
	- Without them, anomaly endpoints will return 503

- Start Monitoring: In the Dashboard → Live Monitor tab, click “Start Monitor”. This starts both:
	- System sampler (psutil) for continuous safe/alert heartbeats
	- Log tailer to process lines in `logs/monitor.log`

## Dashboard tour

- Overview
	- Active/Remediated counts, system health heartbeat, last activity
- Live Monitor
	- Color-coded stream: detections, resolutions, heartbeats, backend notices
	- Clear button resets the view
- Threat Management
	- Filter by status/severity, open details, and remediate from UI
	- Quick Actions: stubbed network scan and log analysis for demos
- Security Logs
	- Reads `logs/monitor.log` and shows newest-first
- Attack Simulation
	- Run a scenario (entry point, attack type, steps)
	- “Create Test Threat” button injects a threat record
- Analytics
	- Total/Active/Remediated/MTTR, severity/status breakdown, daily trends, recent threats

## API highlights

- Detection & Pipeline
	- POST `/api/v1/pipeline/process` — Orchestrates the full flow for a single event
	- POST `/api/v1/predict/anomaly/autoencoder` — Anomaly verdict using the autoencoder
- Simulation
	- POST `/api/v1/simulation/simulate-attack` — Generate plausible attack paths and defenses
	- POST `/api/v1/simulation/inject-threat` — Create a test threat from a simulation
- Threats & Logs
	- GET `/api/v1/threats` — List with filters; GET `/api/v1/threats/{id}` — Detail
	- POST `/api/v1/threats/{id}/remediate` — Mark as remediated, append action
	- GET `/api/v1/analytics/threats` — Totals/severity/MTTR/trend
	- GET `/api/v1/logs/security` — Last N log lines (newest-first)
- Dashboard control
	- POST `/web/dashboard/api/monitor/start` — Start system+log monitors
	- POST `/web/dashboard/api/monitor/stop` — Stop monitors
	- GET  `/web/dashboard/api/stats` — Summary used by the Live Monitor




## Contributing & roadmap

- Good first issues:
	- Add a monitor source toggle (system-only, log-only, both) + small network health chip
	- Persist simulation history and allow replay
	- MITRE ATT&CK overlay for Simulation tab
	- Tests for analytics and simulation threat injection endpoints

## Architecture and workflow

High-level flow for each event (from monitors or API):

1) Ingest → 2) Preprocess → 3) Detect (Autoencoder) → 4) Simulate (on attack) → 5) Decide → 6) Respond (simulated) → 7) Feedback

- Ingestion sources
	- SystemNetworkMonitor (psutil): samples network rates and connections; posts suspicious spikes to `/api/v1/pipeline/process`.
	- Log tailer: watches `logs/monitor.log`; any line containing “MALICIOUS” generates a high-intensity feature vector and posts to the pipeline.
- Detection: Autoencoder-only anomaly decision (“BENIGN” vs “ATTACK”).
- Simulation: Run only when anomaly is detected (attack-type “Anomaly” by default).
- Decision & Response: Plans and simulates enforcement; threat is marked remediated automatically for the demo.
- Persistence & Analytics: Threats are stored as JSON; the dashboard uses this for counters, charts, MTTR, and trends.

Key modules
- `agents/`: preprocessor, detection_agent (autoencoder), simulator_agent, decision_agent, response_module, feedback, model_manager (caching).
- `services/system_monitor.py`: psutil-based live sampler with safe/alert heartbeats.
- `services/threats_service.py`: JSON-backed threat store with stats and action history.
- `api/threats_api.py`: Threats API, security logs (newest-first), analytics endpoint.
- `api/routes.py`: Autoencoder prediction, pipeline orchestrator, and simulation “inject threat”.
- `dashboard.py`: UI routes + monitor start/stop API; starts both system+log monitors by default and exposes system-monitor status in stats.


## Using the dashboard

1) Live Monitor
- Click “Start Monitor” once the app is running. This starts BOTH:
	- System monitor (psutil sampler) posting anomalies to the pipeline
	- Log tailer watching `logs/monitor.log`
- You’ll see periodic “heartbeat” entries when safe; alerts on spikes will appear in red with a bullseye icon.

2) Threat Management
- Filter by status or severity; click a row to see details and action history.
- Click “Remediate” to mark an active threat as remediated (updates store + counters).

3) Security Logs
- Shows last N lines from `logs/monitor.log`, newest-first.

4) Attack Simulation → “Create Test Threat”
- Run a simulation (entry point + attack type + steps) from the tab.
- Click “Create Test Threat” to inject a synthetic record into the Threat Management list.

5) Analytics
- Charts: status split, severity distribution, daily trend.
- Export: download the current analytics JSON.

## Roadmap and contributions

Low-risk enhancements
- UI: source toggle (system vs. log) and a compact network health chip
- Simulation history persistence and replay
- MITRE overlay per path in the Simulation tab

Contributions are welcome. Open an issue or PR with a concise proposal and scope.



## License

MIT

# Cybersecurity AI Threat Console (Autoencoder-first)

End-to-end cybersecurity threat console featuring an autoencoder-only anomaly detector, continuous monitoring, automatic remediation (simulated), and a live dashboard with analytics and threat management.

- Backend: FastAPI (Python)
- ML: TensorFlow/Keras Autoencoder + scikit-learn StandardScaler
- Monitoring: psutil-based system network sampler + log tailer (prototype)
- Persistence: JSON threat store (`data/processed/threats.json`)
- Frontend: Bootstrap + vanilla JS + Chart.js

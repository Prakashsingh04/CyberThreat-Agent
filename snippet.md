# Code Snippet Compendium

Curated essential excerpts from core modules of the Cybersecurity AI Detection System. Each snippet highlights the key logic for architecture, pipeline flow, simulation, threat management, monitoring, and response. Use these snippets in documentation, onboarding, or presentations without needing to open every source file.

> Note: Non-critical boilerplate (imports, trivial getters) trimmed where safe. Retain full files for production reference.

---
## 1. Application Bootstrap (`main.py`)
```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    startup_time = datetime.datetime.now()
    # Create directories, check model files, preload models
    model_availability = check_model_files()
    load_models_at_startup()
    yield
    # Shutdown + uptime logging
```
```python
app = FastAPI(title="Cybersecurity AI Detection System", version="2.0.0", lifespan=lifespan)
app.include_router(detection_router, prefix="/api/v1")
app.include_router(simulation_router, prefix="/api/v1")
app.include_router(threats_router,    prefix="/api/v1")
app.include_router(dashboard.router,  prefix="/web")
```
```python
@app.get("/health")
async def health_check():
    return {"status": "healthy", "models": model_availability, "uptime": uptime_str}
```

---
## 2. Core Pipeline Orchestrator (`api/routes.py`)
```python
class InputData(BaseModel):
    features: List[float] = Field(..., min_length=70, max_length=79)
    @field_validator('features')
    def check_feature_length(cls, v):
        if len(v) not in [70,75,79]: raise ValueError("Expected 70, 75, or 79 features")
        if any(not isinstance(x,(float,int)) for x in v): raise ValueError("All features must be numerical")
        return v
```
```python
@router.post("/pipeline/process")
async def process_pipeline(data: InputData, entry_point: str = "web_server", max_steps: int = 3, source_ip: Optional[str] = None):
    ok,msg = validate_features(data.features)
    if not ok: raise HTTPException(400, msg)
    _, scaler, label_encoder = agent_preproc.prepare(data.features)
    anomaly = agent_detect.detect_anomaly(data.features, method='autoencoder')
    detection_summary = {"label": None, "anomaly": anomaly, "model_used": "autoencoder", "source_ip": source_ip}
    # Threat record + simulation only if anomaly detected
    if anomaly == "ATTACK":
        threat_record = threats.add_threat(th_type="Anomaly", severity="high", source_ip=source_ip, model="autoencoder")
        simulation_result = agent_sim.simulate_attack(entry_point=entry_point, attack_type="Anomaly", max_steps=max_steps)
    else:
        threat_record = None; simulation_result = None
    actions = agent_decide.plan_actions(detection_summary, simulation_result)
    enforcement = agent_response.enforce(actions, threat_id=threat_record['id'] if threat_record else None)
    agent_feedback.record({"detection": detection_summary, "simulation_id": simulation_result.get("simulation_id") if simulation_result else None, "actions": actions, "enforcement_summary": enforcement})
    return {"detection": detection_summary, "simulation": simulation_result, "actions": actions, "enforcement": enforcement, "feedback_recorded": True}
```

---
## 3. Preprocessing Utilities (`api/utils.py`)
```python
def preprocess_features(features: List[float]) -> np.ndarray:
    arr = np.array(features, dtype=np.float32)
    if len(arr) in (79,75): arr = arr[:70]
    elif len(arr) != 70: raise ValueError("Expected 70, 75, or 79 features")
    return arr.reshape(1,-1)
```
```python
def _align_and_scale(processed_features: np.ndarray, scaler) -> np.ndarray:
    if hasattr(scaler, 'feature_names_in_'):
        # Map required columns, pad missing with 0
        row = {col: float(processed_features[0,i]) if i < processed_features.shape[1] else 0.0 for i,col in enumerate(scaler.feature_names_in_)}
        df = pd.DataFrame([row], columns=list(scaler.feature_names_in_))
        return scaler.transform(df)
    # Fallback: pad/truncate to scaler.n_features_in_
```
```python
def predict_anomaly(model, features, scaler, method='autoencoder') -> str:
    processed = preprocess_features(features)
    scaled = _align_and_scale(processed, scaler) if scaler else processed
    if scaled.shape[1] < 70: scaled = np.pad(scaled, ((0,0),(0,70 - scaled.shape[1])))
    scaled = scaled[:, :70]
    if method == 'isolation_forest': return 'BENIGN' if model.predict(scaled)[0] == 1 else 'ATTACK'
    reconstructed = model.predict(scaled, verbose=0)
    mse = np.mean((scaled - reconstructed)**2)
    return 'BENIGN' if mse <= 0.28821281545585886 else 'ATTACK'
```

---
## 4. Detection Agent Fallback (`agents/detection_agent.py`)
```python
def detect_anomaly(features: List[float], method: str = 'autoencoder') -> str:
    scaler = get_scaler(); model = get_model('autoencoder')
    try:
        if model and method == 'autoencoder': return predict_anomaly(model, features, scaler, 'autoencoder')
    except Exception: pass
    mean_val = sum(features)/len(features); variance = sum((x-mean_val)**2 for x in features)/len(features)
    return 'ATTACK' if variance > 1.0 else 'BENIGN'
```

---
## 5. Simulation Agent (`agents/simulator_agent.py`)
```python
MITRE_MAPPINGS = {
    'DDoS': {'severity': 0.8, 'techniques': ['T1498']},
    'Bot':  {'severity': 0.9, 'techniques': ['T1071.001']},
}
```
```python
def simulate_attack(entry_point: str, attack_type: str, max_steps: int = 3) -> Dict[str, Any]:
    if entry_point not in NETWORK_ASSETS: entry_point = random.choice(NETWORK_ASSETS)
    mitre_data = MITRE_MAPPINGS.get(attack_type, {'severity':0.5,'techniques':[]})
    possible_paths = []
    for _ in range(min(3, max_steps)):
        path = [entry_point]; current = entry_point
        for _ in range(min(max_steps - 1, 4)):
            candidates = [a for a in NETWORK_ASSETS if a != current and a not in path]
            if not candidates: break
            if attack_type in ['Bot','DDoS']:
                server_candidates = [a for a in candidates if 'server' in a]
                next_asset = random.choice(server_candidates or candidates)
            else:
                next_asset = random.choice(candidates)
            path.append(next_asset); current = next_asset
        probability = round(random.uniform(0.3,0.9),2) if attack_type != 'BENIGN' else 0.05
        risk_score = round(mitre_data['severity'] * probability,2)
        possible_paths.append({'path': path,'probability': probability,'techniques': mitre_data['techniques'],'estimated_time': f"{random.randint(5,120)} minutes",'risk_score': risk_score})
    critical = [a for p in possible_paths for a in p['path'] if any(k in a for k in ['server','domain'])]
    return {'simulation_id': f"sim_{datetime.now().strftime('%Y%m%d_%H%M%S')}", 'entry_point': entry_point,'attack_type': attack_type,'possible_paths': possible_paths,'critical_assets_at_risk': list(set(critical)),'recommended_defenses': ['Implement network segmentation','Enable MFA','Deploy EDR','Rate-limit traffic','Harden exposed services'],'timestamp': datetime.now().isoformat()}
```

---
## 6. Decision Agent (`agents/decision_agent.py`)
```python
def plan_actions(detection: Dict[str,Any], simulation: Dict[str,Any]) -> List[Dict[str,Any]]:
    label = detection.get('label','UNKNOWN'); anomaly = detection.get('anomaly','BENIGN')
    risk_multiplier = 1.0 + (0.5 if anomaly=='ATTACK' else 0) + (0.5 if label not in ['BENIGN','UNKNOWN'] else 0)
    critical = simulation.get('critical_assets_at_risk',[]) if simulation else []
    actions = []
    if critical: actions.append({'action':'isolate_assets','targets':critical,'priority':'high'})
    actions.append({'action':'block_ip','targets':[detection.get('source_ip','unknown')],'priority':'medium'})
    if label not in ['BENIGN','UNKNOWN']: actions.append({'action':'quarantine_endpoint','targets':[detection.get('endpoint','unknown')],'priority':'high'})
    actions.append({'action':'alert_operator','message':f"Detected {label} (anomaly={anomaly})",'priority':'high' if risk_multiplier>1.5 else 'medium'})
    return actions
```

---
## 7. Response Module (`agents/response_module.py`)
```python
def enforce(actions: List[Dict[str,Any]], threat_id: Optional[str] = None) -> Dict[str,Any]:
    executed = [{"action": a['action'], "targets": a.get('targets'), "status": "enforced", "details": f"(simulated) executed {a['action']}"} for a in actions]
    mark_resolved({"actions_count": len(actions)})
    if threat_id:
        threats.update_status(threat_id,'remediated')
        threats.add_action(threat_id, action='auto-remediate', result='success', notes='Enforcement simulated')
    return {"executed_count": len(executed), "executed": executed, "summary": "All actions simulated as enforced"}
```

---
## 8. Feedback Logger (`agents/feedback.py`)
```python
def record(outcome: Dict[str,Any]) -> None:
    os.makedirs(os.path.dirname(FEEDBACK_PATH), exist_ok=True)
    with open(FEEDBACK_PATH,'a',encoding='utf-8') as fh: fh.write(json.dumps(outcome) + '\n')
```

---
## 9. Model Manager (`agents/model_manager.py`)
```python
def load_all():
    availability = check_model_files()
    scaler, label_encoder = load_preprocessing_objects()
    if availability.get('mlp_model.h5'): models['mlp'] = load_keras_model('models/mlp_model.h5')
    if availability.get('lstm_model.h5'): models['lstm'] = load_keras_model('models/lstm_model.h5')
    if availability.get('autoencoder_model.h5'): models['autoencoder'] = load_keras_model('models/autoencoder_model.h5')
    if availability.get('isolation_forest.pkl'): models['isolation_forest'] = load_sklearn_model('models/isolation_forest.pkl')
```
```python
def get_model(name: str): return models.get(name)
```

---
## 10. Threat Persistence (`services/threats_service.py`)
```python
def add_threat(th_type: str, severity: str='medium', source_ip: Optional[str]=None, endpoint: Optional[str]=None, model: Optional[str]=None, details: Optional[Dict[str,Any]]=None, status: str='active') -> Dict[str,Any]:
    rec = { 'id': str(uuid.uuid4()), 'timestamp': datetime.utcnow().isoformat(), 'status': status, 'type': th_type, 'severity': severity, 'source_ip': source_ip, 'endpoint': endpoint, 'model': model, 'details': details or {}, 'actions': [], 'label': None, 'outcome': None }
    with _lock: data = _load(); data['threats'].append(rec); _save(data)
    return rec
```
```python
def add_action(threat_id: str, action: str, result: str='success', notes: Optional[str]=None) -> bool:
    with _lock: data = _load();
    for t in data.get('threats', []):
        if t['id'] == threat_id:
            t.setdefault('actions', []).insert(0,{ 'timestamp': datetime.utcnow().isoformat(), 'action': action, 'result': result, 'notes': notes or '' })
            _save(data); return True
    return False
```

---
## 11. System Network Monitor (`services/system_monitor.py`)
```python
def _is_suspicious(m):
    if m['conn_syn_sent'] > 20 and m['unique_remotes'] > 30: return True
    if m['bytes_sent_rate'] > 5_000_000 and m['conn_established'] > 200: return True
    if m['unique_remotes'] > 200: return True
    if m['conn_total'] > 1000: return True
    if m['conn_time_wait'] > 300: return True
    return False
```
```python
def _features_from_metrics(m):
    vec = [0.0]*70
    vec[0] = m['bytes_sent_rate']/1_000_000.0
    vec[1] = m['bytes_recv_rate']/1_000_000.0
    vec[2] = m['conn_total']; vec[3] = m['conn_established']; vec[4] = m['conn_syn_sent']
    vec[5] = m['conn_time_wait']; vec[6] = m['conn_close_wait']; vec[7] = m['unique_remotes']
    return vec
```

---
## 12. Dashboard Log Tailer (`dashboard.py` excerpt)
```python
def _monitor_tail_loop(stop_event: threading.Event):
    with open(LOG_PATH,'r',encoding='utf-8') as fh:
        fh.seek(0, os.SEEK_END)
        while not stop_event.is_set():
            pos = fh.tell(); line = fh.readline()
            if not line: time.sleep(0.5); fh.seek(pos); continue
            line = line.strip();
            features = [100.0]*70 if 'MALICIOUS' in line.upper() else [0.0]*70
            requests.post(PIPELINE_ENDPOINT, params={'entry_point': 'web_server','max_steps':3}, json={'features': features}, timeout=5)
```

---
## 13. Monitor Script (`scripts/monitor.py`)
```python
def create_features_from_line(line: str):
    return [100.0]*70 if 'MALICIOUS' in line.upper() else [0.0]*70
```
```python
def tail_and_post():
    with open(LOG_PATH,'r',encoding='utf-8') as fh:
        fh.seek(0, os.SEEK_END)
        while True:
            line = fh.readline();
            if not line: time.sleep(0.5); continue
            line = line.strip();
            features = create_features_from_line(line)
            requests.post(ENDPOINT, params={'entry_point':'web_server','max_steps':3}, json={'features': features}, timeout=5)
```

---
## 14. Harmful Event Generator (`scripts/harmful_script.py`)
```python
def emit_malicious_events(count: int = 2, interval: float = 1.0):
    with open(LOG_PATH,'a',encoding='utf-8') as fh:
        for i in range(count):
            fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - MALICIOUS - simulated attack event {i+1}\n")
            fh.flush(); time.sleep(interval)
```

---
## 15. Threat Analytics (`api/threats_api.py` excerpt)
```python
def analytics_threats():
    items,_ = svc.list_threats(limit=10_000)
    active = sum(1 for t in items if t['status']=='active')
    remediated = sum(1 for t in items if t['status']=='remediated')
    sev_counts = defaultdict(int)
    for t in items: sev_counts[(t.get('severity') or 'unknown').lower()] += 1
    # MTTR calculation + trend by day omitted for brevity
    return { 'totals': {'total': len(items), 'active': active, 'remediated': remediated}, 'severity': sev_counts }
```

---
## 16. Attack Simulation API (`api/simulation_api.py` excerpt)
```python
MITRE_MAPPINGS = { 'DDoS': { 'techniques': [{ 'id':'T1498','name':'Network Denial of Service','tactic':'Impact'}], 'severity':0.8, 'tactics':['Impact'], 'detection_methods':['Network traffic monitoring'], 'next_steps':['T1041','T1071'] }, ... }
```
```python
@router.post('/simulate-attack')
async def simulate_attack(request: AttackSimulationRequest):
    if request.attack_type not in SUPPORTED_ATTACKS: raise HTTPException(400, 'Unsupported attack type')
    simulation_id = f"sim_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{random.randint(1000,9999)}"
    # Build possible_paths with probability, techniques, risk_score
    return SimulationResponse(...)
```

---
## 17. Model Status Endpoint Snippet (`dashboard.py`)
```python
@router.get('/dashboard/api/model-status')
async def get_model_status():
    model_availability = check_model_files()
    model_details = { 'autoencoder_model.h5': { 'name': 'Autoencoder Neural Network', 'status': 'online' if model_availability.get('autoencoder_model.h5') else 'offline', 'expected_input': '70 features', 'output': 'Binary (BENIGN/ATTACK)' }, ... }
    return { 'models': model_details, 'summary': {...} }
```

---
## 18. Health Check Pattern (`main.py`) 
```python
@app.get('/health')
async def health_check():
    availability = check_model_files(); uptime_str = str(datetime.datetime.now() - startup_time).split('.')[0]
    return { 'status': 'healthy', 'models': { 'available': sum(1 for a in availability.values() if a) }, 'uptime': uptime_str }
```

---
## 19. Feedback Log Format Example
```json
{"detection": {"anomaly": "ATTACK", "model_used": "autoencoder"}, "simulation_id": "sim_20251110_120102_1234", "actions": [{"action":"block_ip"}], "enforcement_summary": {"executed_count":1}}
```

---
## 20. Quick Reference: Pipeline Step Functions
| Step | Function | File |
|------|----------|------|
| Preprocess | `prepare()` | `agents/preprocessor.py` |
| Detect | `detect_anomaly()` | `agents/detection_agent.py` |
| Simulate | `simulate_attack()` | `agents/simulator_agent.py` |
| Decide | `plan_actions()` | `agents/decision_agent.py` |
| Respond | `enforce()` | `agents/response_module.py` |
| Feedback | `record()` | `agents/feedback.py` |

---
## 21. Extending Snippets
Add new excerpts by copying minimal, context-rich blocks (function signature + core logic), omitting trivial error handling or repeated patterns. Keep each block under ~40 lines for readability; link back to full file for details.

---
## 22. License Reminder
Original code under MIT License (see `main.py` license_info). Snippets inherit same license usage policies.

---
End of snippet compendium.

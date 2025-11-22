import json
import os
import threading
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

STORE_PATH = os.path.join('data', 'processed', 'threats.json')
_lock = threading.Lock()

ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}

def _severity_from_type(th_type: Optional[str]) -> str:
    t = (th_type or "").lower()
    if any(k in t for k in ["bot", "ddos"]):
        return "critical"
    if any(k in t for k in ["goldeneye", "hulk", "patator", "brute"]):
        return "high"
    if any(k in t for k in ["portscan", "xss", "slowloris", "slowhttp"]):
        return "medium"
    return "low"

def _normalize_severity(value: Any, th_type: Optional[str] = None) -> str:
    """Normalize severity into one of: low|medium|high|critical.

    Accepts existing labels, numeric (0..1), or falls back based on type.
    """
    # If it's already valid string label
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ALLOWED_SEVERITIES:
            return v
        # Try to coerce numeric strings
        try:
            f = float(v)
            if 0.0 <= f <= 1.0:
                pass
            else:
                return _severity_from_type(th_type)
        except Exception:
            return _severity_from_type(th_type)
    # If it's numeric, map ranges
    try:
        f = float(value)
        if f < 0.25:
            return "low"
        if f < 0.5:
            return "medium"
        if f < 0.75:
            return "high"
        return "critical"
    except Exception:
        return _severity_from_type(th_type)

def _ensure_store():
    os.makedirs(os.path.dirname(STORE_PATH), exist_ok=True)
    if not os.path.exists(STORE_PATH):
        with open(STORE_PATH, 'w', encoding='utf-8') as f:
            json.dump({'threats': []}, f)

def _load() -> Dict[str, Any]:
    _ensure_store()
    with open(STORE_PATH, 'r', encoding='utf-8') as f:
        return json.load(f)

def _save(data: Dict[str, Any]) -> None:
    with open(STORE_PATH, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

# Threat schema (JSON)
# id: str
# timestamp: iso str
# status: 'active' | 'remediated'
# type: str (e.g., 'Anomaly', 'DDoS')
# severity: 'low'|'medium'|'high'|'critical'
# source_ip: Optional[str]
# endpoint: Optional[str]
# model: Optional[str]
# details: Dict[str, Any]
# actions: List[{timestamp, action, result, notes}]

def add_threat(th_type: str, severity: str = 'medium', source_ip: Optional[str] = None, endpoint: Optional[str] = None, model: Optional[str] = None, details: Optional[Dict[str, Any]] = None, status: str = 'active') -> Dict[str, Any]:
    sev = _normalize_severity(severity, th_type=th_type)
    rec = {
        'id': str(uuid.uuid4()),
        'timestamp': datetime.utcnow().isoformat(),
        'status': status,
        'type': th_type,
        'severity': sev,
        'source_ip': source_ip,
        'endpoint': endpoint,
        'model': model,
        'details': details or {},
        'actions': [],
        'label': None,     # 'tp' | 'fp' | None
        'outcome': None    # 'contained' | 'recurring' | None
    }
    with _lock:
        data = _load()
        data['threats'].append(rec)
        _save(data)
    return rec

def list_threats(status: Optional[str] = None, severity: Optional[str] = None, q: Optional[str] = None, limit: int = 100, offset: int = 0) -> Tuple[List[Dict[str, Any]], int]:
    with _lock:
        data = _load()
    items = data.get('threats', [])
    if status:
        items = [t for t in items if t.get('status') == status]
    if severity:
        items = [t for t in items if t.get('severity') == severity]
    if q:
        qa = q.lower()
        def _match(t):
            blob = json.dumps(t, ensure_ascii=False).lower()
            return qa in blob
        items = [t for t in items if _match(t)]
    # Sort by timestamp descending so newest threats appear first in consumers
    try:
        items = sorted(items, key=lambda t: t.get('timestamp') or '', reverse=True)
    except Exception:
        pass
    total = len(items)
    return items[offset:offset+limit], total

def get_threat(threat_id: str) -> Optional[Dict[str, Any]]:
    with _lock:
        data = _load()
    for t in data.get('threats', []):
        if t.get('id') == threat_id:
            return t
    return None

def update_status(threat_id: str, status: str) -> bool:
    with _lock:
        data = _load()
        changed = False
        for t in data.get('threats', []):
            if t.get('id') == threat_id:
                t['status'] = status
                changed = True
                break
        if changed:
            _save(data)
        return changed

def add_action(threat_id: str, action: str, result: str = 'success', notes: Optional[str] = None) -> bool:
    with _lock:
        data = _load()
        changed = False
        for t in data.get('threats', []):
            if t.get('id') == threat_id:
                t.setdefault('actions', []).insert(0, {
                    'timestamp': datetime.utcnow().isoformat(),
                    'action': action,
                    'result': result,
                    'notes': notes or ''
                })
                changed = True
                break
        if changed:
            _save(data)
        return changed

def stats() -> Dict[str, int]:
    with _lock:
        data = _load()
    items = data.get('threats', [])
    total = len(items)
    active = sum(1 for t in items if t.get('status') == 'active')
    remediated = sum(1 for t in items if t.get('status') == 'remediated')
    return {'total': total, 'active': active, 'remediated': remediated}

def set_label(threat_id: str, label: str) -> bool:
    label = (label or '').lower()
    if label not in ('tp', 'fp'):
        return False
    with _lock:
        data = _load()
        changed = False
        for t in data.get('threats', []):
            if t.get('id') == threat_id:
                t['label'] = label
                changed = True
                break
        if changed:
            _save(data)
        return changed

def sanitize_store() -> int:
    """Ensure all stored records have normalized severities. Returns count changed."""
    with _lock:
        data = _load()
        threats = data.get('threats', [])
        changed = 0
        for t in threats:
            old = t.get('severity')
            norm = _normalize_severity(old, th_type=t.get('type'))
            if norm != old:
                t['severity'] = norm
                changed += 1
        if changed:
            _save(data)
        return changed

def purge_simulation_string() -> int:
    """Remove any threats where type is exactly 'Simulation:string'.

    Returns the number of records removed.
    """
    with _lock:
        data = _load()
        items = data.get('threats', [])
        before = len(items)
        items = [t for t in items if (t.get('type') or '').strip() != 'Simulation:string']
        removed = before - len(items)
        if removed:
            data['threats'] = items
            _save(data)
        return removed

def clear_store() -> int:
    """Remove all threats from the store. Returns number removed."""
    with _lock:
        data = _load()
        count = len(data.get('threats', []))
        data['threats'] = []
        _save(data)
        return count

def create_from_log_event(message: str, source: str = 'log') -> Optional[Dict[str, Any]]:
    """Create a threat record from a raw log line.

    Heuristics:
    - 'MALICIOUS' -> high severity
    - 'SUSPICIOUS' -> medium severity
    Returns None if no indicators matched.
    """
    text = message.lower()
    if 'malicious' in text:
        severity = 'high'
        th_type = 'LogEvent-Malicious'
    elif 'suspicious' in text:
        severity = 'medium'
        th_type = 'LogEvent-Suspicious'
    else:
        return None
    details = {'raw': message, 'source': source}
    return add_threat(th_type=th_type, severity=severity, details=details)

def purge_oldest(count: int) -> int:
    """Remove the oldest `count` threats by timestamp. Returns number removed.

    If fewer than `count` exist, removes all. Ignores malformed timestamps by
    treating them as very old.
    """
    if count <= 0:
        return 0
    with _lock:
        data = _load()
        items = data.get('threats', [])
        if not items:
            return 0
        from datetime import timezone
        def _ts(t):
            try:
                raw = t.get('timestamp') or ''
                dt = datetime.fromisoformat(raw)
                # Normalize: convert aware to UTC then make naive for consistent comparison
                if dt.tzinfo:
                    dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
                return dt.timestamp()
            except Exception:
                return 0.0  # treat malformed as very old
        # Sort ascending by numeric timestamp (oldest first)
        items_sorted = sorted(items, key=_ts)
        to_remove_ids = set(x['id'] for x in items_sorted[:count])
        remaining = [x for x in items if x['id'] not in to_remove_ids]
        removed = len(items) - len(remaining)
        if removed:
            data['threats'] = remaining
            _save(data)
        return removed

def set_outcome(threat_id: str, outcome: str) -> bool:
    outcome = (outcome or '').lower()
    if outcome not in ('contained', 'recurring'):
        return False
    with _lock:
        data = _load()
        changed = False
        for t in data.get('threats', []):
            if t.get('id') == threat_id:
                t['outcome'] = outcome
                changed = True
                break
        if changed:
            _save(data)
        return changed

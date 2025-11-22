from fastapi import APIRouter, HTTPException, Query
from typing import Optional
from pydantic import BaseModel, Field
from services import threats_service as svc
import agents.decision_agent as agent_decide
import agents.response_module as agent_response
import agents.feedback as agent_feedback
import os
from fastapi import Body
import os
from datetime import datetime
from collections import defaultdict

router = APIRouter()

class ThreatOut(BaseModel):
    id: str
    timestamp: str
    status: str
    type: str
    severity: str
    source_ip: Optional[str] = None
    endpoint: Optional[str] = None
    model: Optional[str] = None
    details: dict
    actions: list

class ThreatListOut(BaseModel):
    items: list[ThreatOut]
    total: int

class RemediateIn(BaseModel):
    notes: Optional[str] = Field(default=None)

class LabelIn(BaseModel):
    label: str = Field(..., description="tp|fp")

class OutcomeIn(BaseModel):
    outcome: str = Field(..., description="contained|recurring")

class LogLineIn(BaseModel):
    line: str = Field(..., description="Raw log line to convert into threat if it contains indicators")

class PurgeOldestIn(BaseModel):
    count: int = Field(..., gt=0, le=10000, description="Number of oldest threats to remove")
    confirm: bool = Field(False, description="Safety flag must be true to execute purge")

@router.get('/threats', response_model=ThreatListOut)
async def list_threats(status: Optional[str] = Query(default=None), severity: Optional[str] = Query(default=None), q: Optional[str] = Query(default=None), limit: int = 100, offset: int = 0):
    items, total = svc.list_threats(status=status, severity=severity, q=q, limit=limit, offset=offset)
    return {'items': items, 'total': total}

@router.get('/threats/{threat_id}', response_model=ThreatOut)
async def get_threat(threat_id: str):
    t = svc.get_threat(threat_id)
    if not t:
        raise HTTPException(404, 'Threat not found')
    return t

@router.post('/threats/{threat_id}/remediate')
async def remediate_threat(threat_id: str, payload: RemediateIn):
    t = svc.get_threat(threat_id)
    if not t:
        raise HTTPException(404, 'Threat not found')
    # Plan minimal response based on available metadata
    actions = agent_decide.plan_actions(
        {
            'label': t.get('type') or 'Unknown',
            'anomaly': 'ATTACK' if t.get('status') == 'active' else 'BENIGN',
            'source_ip': t.get('source_ip'),
            'endpoint': t.get('endpoint'),
        },
        None
    )
    # Enforce and log feedback
    enforcement = agent_response.enforce(actions, threat_id=threat_id)
    svc.add_action(threat_id, action='remediate', result='success', notes=payload.notes)
    agent_feedback.record({
        'source': 'manual_remediate',
        'actions': actions,
        'enforcement': enforcement,
        'notes': payload.notes,
    }, threat_id=threat_id, severity=t.get('severity'))
    return {'status': 'remediated', 'id': threat_id}

@router.post('/threats/{threat_id}/label')
async def label_threat(threat_id: str, payload: LabelIn):
    if payload.label.lower() not in ('tp', 'fp'):
        raise HTTPException(400, 'label must be tp|fp')
    ok = svc.set_label(threat_id, payload.label)
    if not ok:
        raise HTTPException(404, 'Threat not found or invalid label')
    svc.add_action(threat_id, action='label', result='success', notes=f"{payload.label}")
    return {'status': 'labeled', 'id': threat_id, 'label': payload.label}

@router.post('/threats/{threat_id}/outcome')
async def set_threat_outcome(threat_id: str, payload: OutcomeIn):
    if payload.outcome.lower() not in ('contained', 'recurring'):
        raise HTTPException(400, 'outcome must be contained|recurring')
    ok = svc.set_outcome(threat_id, payload.outcome)
    if not ok:
        raise HTTPException(404, 'Threat not found or invalid outcome')
    svc.add_action(threat_id, action='outcome', result='success', notes=f"{payload.outcome}")
    return {'status': 'updated', 'id': threat_id, 'outcome': payload.outcome}

@router.post('/threats/quick/network-scan')
async def quick_network_scan():
    # Placeholder: In a real system, integrate nmap or similar scanner with safe parameters
    # Here we just return a stub
    return {
        'status': 'completed',
        'summary': 'Network scan simulation completed.',
        'findings': [
            {'host': '127.0.0.1', 'ports_open': [80, 443], 'note': 'Local demo'},
        ]
    }

@router.post('/threats/quick/log-analysis')
async def quick_log_analysis():
    # Analyze recent monitor log lines (tail)
    log_path = os.path.join('logs', 'monitor.log')
    lines = []
    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()[-100:]
    except Exception:
        pass
    malicious = [ln.strip() for ln in lines if 'MALICIOUS' in ln.upper()]
    return {
        'status': 'completed',
        'log_path': log_path,
        'lines_analyzed': len(lines),
        'malicious_hits': len(malicious),
        'examples': malicious[-5:]
    }

@router.post('/threats/log-event')
async def ingest_log_event(payload: LogLineIn):
    rec = svc.create_from_log_event(payload.line)
    if not rec:
        return {'status': 'ignored'}
    return {'status': 'created', 'threat': rec}

@router.get('/statistics/threats')
async def threat_statistics():
    return svc.stats()

@router.get('/logs/security')
async def security_logs(limit: int = 200):
    path = os.path.join('logs', 'monitor.log')
    payload = []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            # Get last N lines and return in descending order (most recent first)
            payload = [ln.rstrip('\n') for ln in f.readlines()[-limit:]][::-1]
    except Exception:
        pass
    return {'path': path, 'count': len(payload), 'lines': payload}


@router.get('/analytics/threats')
async def analytics_threats():
    """Return threat-centric analytics for the dashboard.

    Includes: totals, status distribution, severity distribution, MTTR, and daily trend.
    """
    items, _ = svc.list_threats(limit=10_000)
    total = len(items)
    active = sum(1 for t in items if t.get('status') == 'active')
    remediated = sum(1 for t in items if t.get('status') == 'remediated')

    # Severity distribution
    sev_counts = defaultdict(int)
    for t in items:
        sev_counts[(t.get('severity') or 'unknown').lower()] += 1

    # MTTR (seconds): time from threat timestamp to first remediation action
    mttr_values = []
    for t in items:
        if t.get('status') != 'remediated':
            continue
        try:
            created = datetime.fromisoformat(t.get('timestamp'))
            actions = t.get('actions') or []
            rem_action = None
            for a in reversed(actions):
                # Since we insert actions at index 0, oldest is at end
                if 'remediate' in (a.get('action') or ''):
                    rem_action = a
                    break
            if not rem_action and actions:
                # Fallback to most recent action
                rem_action = actions[0]
            if rem_action:
                finished = datetime.fromisoformat(rem_action.get('timestamp'))
                mttr_values.append((finished - created).total_seconds())
        except Exception:
            continue
    mttr_seconds = sum(mttr_values) / len(mttr_values) if mttr_values else 0.0

    # Trend by day
    by_day = defaultdict(lambda: {'total': 0, 'active': 0, 'remediated': 0})
    for t in items:
        try:
            day = datetime.fromisoformat(t.get('timestamp')).date().isoformat()
        except Exception:
            day = 'unknown'
        by_day[day]['total'] += 1
        if t.get('status') == 'active':
            by_day[day]['active'] += 1
        elif t.get('status') == 'remediated':
            by_day[day]['remediated'] += 1

    trend = [
        { 'date': k, **v }
        for k, v in sorted(by_day.items(), key=lambda kv: kv[0])
    ]

    return {
        'totals': {
            'total': total,
            'active': active,
            'remediated': remediated,
        },
        'severity': sev_counts,
        'mttr_seconds': round(mttr_seconds, 2),
        'trend': trend,
    }

# --- Maintenance / Admin endpoints ---

@router.post('/admin/purge', summary='Delete all threat records')
async def purge_all_threats(confirm: bool = Body(False, embed=True)):
    if not confirm:
        raise HTTPException(400, 'Set confirm=true to purge all threats')
    removed = svc.clear_store()
    return {'status': 'purged', 'removed': removed}

@router.post('/admin/clear-logs', summary='Clear monitor.log and feedback.jsonl')
async def clear_logs(confirm: bool = Body(False, embed=True)):
    if not confirm:
        raise HTTPException(400, 'Set confirm=true to clear logs')
    monitor_path = os.path.join('logs', 'monitor.log')
    feedback_path = os.path.join('logs', 'feedback.jsonl')
    cleared = []
    for p in [monitor_path, feedback_path]:
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, 'w', encoding='utf-8').close()
            cleared.append(p)
        except Exception:
            pass
    return {'status': 'cleared', 'paths': cleared}

@router.post('/admin/purge-oldest', summary='Remove oldest N threat records')
async def purge_oldest(payload: PurgeOldestIn):
    if not payload.confirm:
        raise HTTPException(400, 'Set confirm=true to purge records')
    removed = svc.purge_oldest(payload.count)
    return {'status': 'purged_oldest', 'removed': removed, 'requested': payload.count}

import pytest
from fastapi.testclient import TestClient
from main import app
import dashboard as dash

client = TestClient(app)


def test_mark_detected_and_resolved_reflected_in_stats(monkeypatch):
    # Force stats endpoint to fall back to in-memory dashboard stats
    def raise_stats():
        raise Exception("no store for test")
    monkeypatch.setattr(dash.threats, 'stats', raise_stats, raising=True)

    # Reset dashboard stats via API to ensure clean slate
    r = client.post('/web/dashboard/api/reset-stats')
    assert r.status_code == 200

    # Sanity check initial
    s = client.get('/web/dashboard/api/stats')
    assert s.status_code == 200
    data = s.json()
    assert data['security']['threats_detected'] == 0
    assert data['security']['resolved_threats'] == 0

    # Mark events
    dash.mark_detected({"test": True})
    dash.mark_detected({"test": True})
    dash.mark_resolved({"test": True})

    s2 = client.get('/web/dashboard/api/stats')
    assert s2.status_code == 200
    data2 = s2.json()
    assert data2['security']['threats_detected'] == 2
    assert data2['security']['resolved_threats'] == 1

from services import threats_service as svc

def test_add_and_list_threats(tmp_path, monkeypatch):
    # Redirect store path to temp file for test isolation
    monkeypatch.setattr(svc, 'STORE_PATH', str(tmp_path / 'threats.json'), raising=False)
    # Add a few
    t1 = svc.add_threat('Anomaly', severity='high', source_ip='1.1.1.1', endpoint='web')
    t2 = svc.add_threat('Anomaly', severity='low', source_ip='2.2.2.2', endpoint='db', status='remediated')
    # List all
    items, total = svc.list_threats()
    assert total == 2
    assert any(x['id'] == t1['id'] for x in items)
    # Filter
    active, n = svc.list_threats(status='active')
    assert n == 1
    # Update
    ok = svc.update_status(t1['id'], 'remediated')
    assert ok
    svc.add_action(t1['id'], 'auto-remediate', 'success', 'done')
    st = svc.stats()
    assert st['total'] == 2
    assert st['remediated'] == 2

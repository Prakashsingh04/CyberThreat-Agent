from fastapi.testclient import TestClient
from main import app


def test_pipeline_happy_path():
    client = TestClient(app)
    # Simple payload with 70 zero features (valid size)
    payload = {"features": [0.0] * 70}
    resp = client.post("/api/v1/pipeline/process", json=payload)
    assert resp.status_code == 200, resp.text
    j = resp.json()
    assert "detection" in j
    assert "actions" in j
    assert isinstance(j["actions"], list)

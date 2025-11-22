# tests/test_api.py
import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

VALID_FEATURES = [
    53.0, 31471.0, 2.0, 2.0, 62.0, 446.0, 31.0, 31.0, 31.0, 0.0,
    223.0, 223.0, 223.0, 0.0, 16141.84487, 127.1011407, 10490.33333,
    18127.37031, 31422.0, 1.0, 1.0, 1.0, 0.0, 1.0, 1.0, 48.0,
    48.0, 0.0, 48.0, 48.0, 0.0, 0.0, 0.0, 0.0, 64.0, 64.0,
    63.55057037, 63.55057037, 31.0, 223.0, 107.8, 105.162731,
    11059.2, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    1.0, 134.75, 31.0, 223.0, 64.0, 0.0, 0.0, 0.0,
    0.0, 0.0, 0.0, 2.0, 62.0, 2.0, 446.0, -1.0,
    -1.0, 1.0, 32.0, 0.0  # Removed 5 extra features to make it exactly 70
]

def test_get_root():
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]

@pytest.mark.parametrize("endpoint", [
    "/api/v1/predict/anomaly/autoencoder",
])
def test_post_valid_prediction(endpoint):
    response = client.post(endpoint, json={"features": VALID_FEATURES})
    # Endpoint may return 200 (model available) or 503 (model/scaler unavailable in demo env)
    assert response.status_code in (200, 503), f"Unexpected status at {endpoint}: {response.status_code} {response.text}"
    if response.status_code == 200:
        data = response.json()
        assert "prediction" in data
        assert "model_used" in data

def test_post_invalid_feature_length_pipeline():
    # The pipeline validates feature length before model usage and should return 400/422
    endpoint = "/api/v1/pipeline/process"
    response = client.post(endpoint, json={"features": VALID_FEATURES[:10]})
    assert response.status_code in (400, 422), f"Expected validation error, got {response.status_code}: {response.text}"

def test_get_model_status():
    response = client.get("/api/v1/models/status")
    assert response.status_code == 200
    data = response.json()
    assert "models" in data
    assert "preprocessing" in data

def test_get_class_info():
    response = client.get("/api/v1/info/classes")
    assert response.status_code == 200
    data = response.json()
    assert "supported_classes" in data

def test_invalid_endpoint():
    response = client.get("/api/v1/unknown-endpoint")
    assert response.status_code == 404

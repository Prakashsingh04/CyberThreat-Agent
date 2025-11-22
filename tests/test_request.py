# test_requests.py
import requests
import json

# Test data
test_features = [
    53.0, 31471.0, 2.0, 2.0, 62.0, 446.0, 31.0, 31.0, 31.0, 0.0,
    223.0, 223.0, 223.0, 0.0, 16141.84487, 127.1011407, 10490.33333,
    18127.37031, 31422.0, 1.0, 1.0, 1.0, 0.0, 1.0, 1.0, 48.0,
    48.0, 0.0, 48.0, 48.0, 0.0, 0.0, 0.0, 0.0, 64.0, 64.0,
    63.55057037, 63.55057037, 31.0, 223.0, 107.8, 105.162731,
    11059.2, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    1.0, 134.75, 31.0, 223.0, 64.0, 0.0, 0.0, 0.0,
    0.0, 0.0, 0.0, 2.0, 62.0, 2.0, 446.0, -1.0,
    -1.0, 1.0, 32.0, 0.0, 0.0, 0.0, 0.0, 0.0
]

def test_all_endpoints():
    base_url = "http://127.0.0.1:8000/api/v1"
    
    endpoints_to_test = [
        "/predict/classification/mlp",
        "/predict/anomaly/isolation_forest", 
        "/predict/anomaly/autoencoder"
    ]
    
    for endpoint in endpoints_to_test:
        print(f"\n🔍 Testing {endpoint}")
        try:
            response = requests.post(
                f"{base_url}{endpoint}",
                json={"features": test_features},
                headers={"Content-Type": "application/json"}
            )
            
            print(f"Status Code: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ Success!")
                print(f"   Prediction: {result['prediction']}")
                print(f"   Model: {result['model_used']}")
                print(f"   Time: {result['processing_time']}s")
            else:
                print(f"❌ Error: {response.text}")
                
        except Exception as e:
            print(f"❌ Exception: {e}")

def test_api_info():
    print("\n📊 Testing API Info Endpoints")
    
    info_endpoints = [
        "/",
        "/models/status", 
        "/info/classes"
    ]
    
    for endpoint in info_endpoints:
        try:
            response = requests.get(f"http://127.0.0.1:8000/api/v1{endpoint}")
            print(f"\n{endpoint}: Status {response.status_code}")
            if response.status_code == 200:
                if endpoint == "/":
                    print("   API Home: ✅")
                else:
                    print(f"   Response: {response.json()}")
        except Exception as e:
            print(f"❌ {endpoint}: {e}")

if __name__ == "__main__":
    print("🚀 Testing Cybersecurity AI API")
    print(f"📊 Test features count: {len(test_features)}")
    
    # Test info endpoints first
    test_api_info()
    
    # Test prediction endpoints
    test_all_endpoints()

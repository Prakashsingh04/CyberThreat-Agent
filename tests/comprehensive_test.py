# comprehensive_test.py
import requests
import json

def test_comprehensive():
    base_url = "http://127.0.0.1:8000/api/v1"
    
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
    
    endpoints = [
        ("🧠 MLP Classification", "/predict/classification/mlp"),
        ("🔍 LSTM Classification", "/predict/classification/lstm"), 
        ("🚨 Isolation Forest", "/predict/anomaly/isolation_forest"),
        ("🤖 Autoencoder", "/predict/anomaly/autoencoder")
    ]
    
    print("🎯 Testing All Prediction Endpoints\n")
    
    for name, endpoint in endpoints:
        try:
            response = requests.post(
                f"{base_url}{endpoint}",
                json={"features": test_features}
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ {name}")
                print(f"   Prediction: {result['prediction']}")
                print(f"   Model: {result['model_used']}")
                print(f"   Time: {result['processing_time']:.4f}s\n")
            else:
                print(f"❌ {name}: {response.status_code} - {response.text}\n")
                
        except Exception as e:
            print(f"❌ {name}: Error - {e}\n")
    
    # Test simulation
    print("⚔️ Testing Attack Simulation")
    try:
        sim_response = requests.post(
            f"{base_url}/simulation/simulate-attack",
            json={
                "entry_point": "web_server",
                "attack_type": "DDoS",
                "max_steps": 3
            }
        )
        
        if sim_response.status_code == 200:
            sim_result = sim_response.json()
            print(f"✅ Attack Simulation")
            print(f"   Simulation ID: {sim_result['simulation_id']}")
            print(f"   Attack Paths: {len(sim_result['possible_paths'])}")
            print(f"   Critical Assets: {len(sim_result['critical_assets_at_risk'])}")
        else:
            print(f"❌ Attack Simulation: {sim_response.status_code}")
            
    except Exception as e:
        print(f"❌ Attack Simulation: {e}")

if __name__ == "__main__":
    test_comprehensive()

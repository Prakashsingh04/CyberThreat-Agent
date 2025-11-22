# test_simulation.py
import requests

def test_simulation():
    base_url = "http://127.0.0.1:8000/api/v1/simulation"
    
    # Test attack simulation
    attack_data = {
        "entry_point": "web_server",
        "attack_type": "DDoS",
        "max_steps": 3
    }
    
    response = requests.post(f"{base_url}/simulate-attack", json=attack_data)
    print(f"Attack Simulation: {response.status_code}")
    if response.status_code == 200:
        result = response.json()
        print(f"✅ Simulation ID: {result['simulation_id']}")
        print(f"   Paths found: {len(result['possible_paths'])}")

if __name__ == "__main__":
    test_simulation()

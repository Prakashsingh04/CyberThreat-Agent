
from typing import List, Dict, Any
import random
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# Keep a small set of assets consistent with the rest of the repo
NETWORK_ASSETS = [
    "web_server", "db_server", "domain_controller", "file_server",
    "workstation_1", "workstation_2", "firewall", "router",
    "email_server", "backup_server", "dns_server", "proxy_server"
]

MITRE_MAPPINGS = {
    # Minimal mapping (the detailed mapping lives in api/simulation_api.py)
    "DDoS": {"severity": 0.8, "techniques": ["T1498"]},
    "Bot": {"severity": 0.9, "techniques": ["T1071.001"]},
}


def simulate_attack(entry_point: str, attack_type: str, max_steps: int = 3) -> Dict[str, Any]:
    """Return a structured simulation result.

    The result includes possible paths, per-path probability and risk score.
    """
    if entry_point not in NETWORK_ASSETS:
        entry_point = random.choice(NETWORK_ASSETS)

    possible_paths = []
    mitre_data = MITRE_MAPPINGS.get(attack_type, {"severity": 0.5, "techniques": []})

    for i in range(min(3, max_steps)):
        path = [entry_point]
        current = entry_point
        for _ in range(min(max_steps - 1, 4)):
            candidates = [a for a in NETWORK_ASSETS if a != current and a not in path]
            if not candidates:
                break
            if attack_type in ["Bot", "DDoS"]:
                critical = [a for a in candidates if "server" in a]
                next_asset = random.choice(critical if critical else candidates)
            else:
                next_asset = random.choice(candidates)
            path.append(next_asset)
            current = next_asset

        probability = round(random.uniform(0.3, 0.9), 2) if attack_type != "BENIGN" else 0.05
        risk_score = round(mitre_data.get("severity", 0.5) * probability, 2)

        possible_paths.append({
            "path": path,
            "probability": probability,
            "techniques": mitre_data.get("techniques", []),
            "estimated_time": f"{random.randint(5,120)} minutes",
            "risk_score": risk_score,
        })

    critical_assets = [a for p in possible_paths for a in p["path"] if any(k in a for k in ["server", "domain"])]

    return {
        "simulation_id": f"sim_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{random.randint(1000,9999)}",
        "entry_point": entry_point,
        "attack_type": attack_type,
        "possible_paths": possible_paths,
        "critical_assets_at_risk": list(set(critical_assets)),
        "recommended_defenses": [
            "Implement network segmentation",
            "Enable MFA",
            "Deploy EDR",
            "Rate-limit traffic",
            "Harden exposed services"
        ],
        "timestamp": datetime.now().isoformat()
    }

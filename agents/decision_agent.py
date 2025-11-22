
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)


def plan_actions(detection: Dict[str, Any], simulation: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return a list of actions with priority.

    Input `detection` is expected to include keys like 'label' and 'anomaly'.
    """
    actions = []
    label = detection.get("label", "UNKNOWN")
    anomaly = detection.get("anomaly", "BENIGN")

    risk_multiplier = 1.0
    if anomaly == "ATTACK":
        risk_multiplier += 0.5
    if label != "BENIGN" and label != "UNKNOWN":
        risk_multiplier += 0.5

    # If simulation highlights critical assets, prioritize isolation
    critical = simulation.get("critical_assets_at_risk", []) if simulation else []

    if critical:
        actions.append({"action": "isolate_assets", "targets": critical, "priority": "high"})

    # Block suspicious behavior (mocked as an action)
    actions.append({"action": "block_ip", "targets": [detection.get("source_ip", "unknown")], "priority": "medium"})

    # Quarantine files if classification suggests malware
    if label not in ["BENIGN", "UNKNOWN"]:
        actions.append({"action": "quarantine_endpoint", "targets": [detection.get("endpoint", "unknown")], "priority": "high"})

    # Alert human operator for review
    actions.append({"action": "alert_operator", "message": f"Detected {label} (anomaly={anomaly})", "priority": "high" if risk_multiplier>1.5 else "medium"})

    return actions

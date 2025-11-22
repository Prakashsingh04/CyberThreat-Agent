"""Detection agent wrappers.

This module exposes two main functions used by the orchestrator:
 - classify(features): returns predicted class label and confidence (if available)
 - detect_anomaly(features): returns 'BENIGN' or 'ATTACK'

Under the hood it uses the project's existing prediction helpers where possible
but falls back to simple heuristics if models aren't present.
"""
from typing import List, Tuple, Optional
import logging

from api.utils import predict_anomaly
from .model_manager import get_model, get_scaler, get_label_encoder

logger = logging.getLogger(__name__)


# Classification removed: this deployment focuses on autoencoder anomaly detection


def detect_anomaly(features: List[float], method: str = "autoencoder") -> str:
    """Run anomaly detection (isolation_forest or autoencoder) or fallback.
    Returns 'BENIGN' or 'ATTACK'.
    """
    scaler = get_scaler()
    try:
        model = get_model('autoencoder')
        if model is not None and method == "autoencoder":
            return predict_anomaly(model, features, scaler, method="autoencoder")
    except Exception as e:
        logger.debug(f"Model-based anomaly detection failed: {e}")

    # Fallback: if variance is high, flag as attack
    try:
        mean_val = sum(features) / len(features)
        variance = sum((x - mean_val) ** 2 for x in features) / len(features)
        return "ATTACK" if variance > 1.0 else "BENIGN"
    except Exception as e:
        logger.error(f"Anomaly fallback failed: {e}")
        return "BENIGN"

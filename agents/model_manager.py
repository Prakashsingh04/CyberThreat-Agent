
from typing import Dict, Optional, Any
import logging
import os

from api.utils import load_keras_model, load_sklearn_model, load_preprocessing_objects, check_model_files

logger = logging.getLogger(__name__)

# Cached objects
models: Dict[str, Any] = {}
scaler = None
label_encoder = None


def load_all():
    """Load all known models and preprocessing objects if available."""
    global models, scaler, label_encoder
    availability = check_model_files()
    logger.info(f"Model files availability: {availability}")

    try:
        scaler, label_encoder = load_preprocessing_objects()
    except Exception as e:
        logger.warning(f"Preprocessing objects not loaded: {e}")

    # Try loading models if files exist
    try:
        if availability.get('mlp_model.h5'):
            models['mlp'] = load_keras_model('models/mlp_model.h5')
    except Exception as e:
        logger.warning(f"Failed to load MLP: {e}")

    try:
        if availability.get('lstm_model.h5'):
            models['lstm'] = load_keras_model('models/lstm_model.h5')
    except Exception as e:
        logger.warning(f"Failed to load LSTM: {e}")

    try:
        if availability.get('autoencoder_model.h5'):
            models['autoencoder'] = load_keras_model('models/autoencoder_model.h5')
    except Exception as e:
        logger.warning(f"Failed to load autoencoder: {e}")

    try:
        if availability.get('isolation_forest.pkl'):
            models['isolation_forest'] = load_sklearn_model('models/isolation_forest.pkl')
    except Exception as e:
        logger.warning(f"Failed to load isolation forest: {e}")

    logger.info(f"Model manager loaded models: {list(models.keys())}")


def get_model(name: str) -> Optional[Any]:
    return models.get(name)


def get_scaler():
    return scaler


def get_label_encoder():
    return label_encoder

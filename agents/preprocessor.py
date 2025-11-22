"""Preprocessing helpers that wrap the project's preprocessing utilities.

This module intentionally keeps a thin layer over `api.utils` preprocessing so
the rest of the agents call a consistent interface.
"""
from typing import List, Tuple
import logging

from api.utils import preprocess_features, load_preprocessing_objects

logger = logging.getLogger(__name__)


def prepare(features: List[float]):
    """Return the preprocessed numpy array and preprocessing objects.

    Returns:
        (processed_array, scaler, label_encoder)
    """
    scaler = None
    label_encoder = None
    try:
        scaler, label_encoder = load_preprocessing_objects()
    except Exception as e:
        logger.debug(f"Preprocessing objects load failed: {e}")

    processed = preprocess_features(features)
    return processed, scaler, label_encoder

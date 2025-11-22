
from typing import Any, Dict, List, Tuple
import logging

logger = logging.getLogger(__name__)

def collect_from_event(event: Dict[str, Any]) -> Tuple[bool, List[float]]:
    """Extracts feature list from an incoming event dict.

    Expected shape: event["features"] -> list of numbers (70/75/79)
    Returns (ok, features)
    """
    if not isinstance(event, dict):
        logger.debug("Event must be a dictionary")
        return False, []

    features = event.get("features")
    if not features or not isinstance(features, list):
        logger.debug("Event missing 'features' list")
        return False, []

    # shallow validation
    if any(not isinstance(x, (int, float)) for x in features):
        logger.debug("One or more features are not numeric")
        return False, []

    return True, [float(x) for x in features]

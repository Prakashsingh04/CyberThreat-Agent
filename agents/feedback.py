"""Simple feedback recorder for the continuous learning loop.

This module appends JSON lines to `logs/feedback.jsonl` with outcome metadata.

"""
from typing import Dict, Any, Optional
import json
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

FEEDBACK_PATH = os.path.join("logs", "feedback.jsonl")


def record(outcome: Dict[str, Any], *, threat_id: Optional[str] = None, severity: Optional[str] = None) -> None:
    """Append a JSON object describing the outcome to the feedback log.

    Adds timestamp and optional threat metadata.
    """
    try:
        os.makedirs(os.path.dirname(FEEDBACK_PATH), exist_ok=True)
        payload = {
            "timestamp": datetime.utcnow().isoformat(),
            **outcome,
        }
        if threat_id:
            payload["threat_id"] = threat_id
        if severity:
            payload["severity"] = severity
        with open(FEEDBACK_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload) + "\n")
        logger.info("Feedback recorded")
    except Exception as e:
        logger.error(f"Failed to record feedback: {e}")

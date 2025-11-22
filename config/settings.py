 
"""Application configuration for response/enforcement behavior.

Defaults keep enforcement in safe, no-op mode. Toggle flags to enable
actual system actions (Windows PowerShell based) at your own risk.
"""

from __future__ import annotations
import os

# Global safe mode: when True, response actions only log and update state
# Environment override: CYBERSEC_SAFE_MODE=0|1
SAFE_MODE: bool = os.getenv("CYBERSEC_SAFE_MODE", "1") not in ("0", "false", "False")

# If True and running on Windows, attempt to execute system enforcement.
# Environment override: CYBERSEC_ENABLE_ENFORCEMENT=0|1 (ignored when SAFE_MODE=True)
ENABLE_SYSTEM_ENFORCEMENT: bool = os.getenv("CYBERSEC_ENABLE_ENFORCEMENT", "0") in ("1", "true", "True")

# Default firewall rule name prefix for block_ip actions
FIREWALL_RULE_PREFIX: str = os.getenv("CYBERSEC_FW_RULE_PREFIX", "CyberSecBlock")

# Path for operator/monitor log used by dashboard Security Logs
MONITOR_LOG_PATH: str = os.path.join("logs", "monitor.log")

# Auto remediate threats created by simulation endpoint
# Environment override: CYBERSEC_AUTO_REMEDIATE_SIM=0|1
AUTO_REMEDIATE_SIMULATION: bool = os.getenv("CYBERSEC_AUTO_REMEDIATE_SIM", "1") in ("1", "true", "True")

# --- System Monitor Tuning (environment overridable) ---
# Sensitivity levels adjust dynamic ratio thresholds. One of: low|medium|high
SYSTEM_MONITOR_SENSITIVITY: str = os.getenv("CYBERSEC_MONITOR_SENSITIVITY", "medium").lower()

# Absolute thresholds (these are conservative defaults to reduce false alerts on normal wifi traffic)
SYSTEM_MONITOR_CONN_TOTAL_THRESHOLD: int = int(os.getenv("CYBERSEC_MONITOR_CONN_TOTAL", "2500"))
SYSTEM_MONITOR_UNIQUE_REMOTES_THRESHOLD: int = int(os.getenv("CYBERSEC_MONITOR_UNIQUE_REMOTES", "25"))
SYSTEM_MONITOR_BYTES_SENT_MBPS_THRESHOLD: float = float(os.getenv("CYBERSEC_MONITOR_BYTES_SENT_MBPS", "15.0"))  # MB/s
SYSTEM_MONITOR_CONN_SYN_SENT_THRESHOLD: int = int(os.getenv("CYBERSEC_MONITOR_SYN_SENT", "50"))
SYSTEM_MONITOR_CONN_TIME_WAIT_THRESHOLD: int = int(os.getenv("CYBERSEC_MONITOR_TIME_WAIT", "800"))

# Dynamic ratio (an event must exceed baseline * ratio)
_sens_map = {"low": 4.0, "medium": 3.0, "high": 2.0}
SYSTEM_MONITOR_RATIO: float = _sens_map.get(SYSTEM_MONITOR_SENSITIVITY, 3.0)

# Cooldown seconds between pipeline postings for non-critical repeats
SYSTEM_MONITOR_COOLDOWN_SECONDS: int = int(os.getenv("CYBERSEC_MONITOR_COOLDOWN", "30"))

# Minimum consecutive suspicious samples required before triggering (debounce)
SYSTEM_MONITOR_CONSECUTIVE_REQUIRED: int = int(os.getenv("CYBERSEC_MONITOR_CONSEC", "2"))

def is_windows() -> bool:
	try:
		return os.name == "nt"
	except Exception:
		return False


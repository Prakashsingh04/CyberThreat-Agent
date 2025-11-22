from typing import List, Dict, Any, Optional
import logging
import subprocess
import shlex
from datetime import datetime
from dashboard import mark_resolved
from services import threats_service as threats
from config import settings
import os

logger = logging.getLogger(__name__)

def _append_monitor_log(message: str) -> None:
    try:
        os.makedirs(os.path.dirname(settings.MONITOR_LOG_PATH), exist_ok=True)
        with open(settings.MONITOR_LOG_PATH, "a", encoding="utf-8") as fh:
            ts = datetime.now().isoformat()
            fh.write(f"{ts} | {message}\n")
    except Exception as e:
        logger.debug(f"Failed writing monitor log: {e}")


def _run_powershell(cmd: str) -> Dict[str, Any]:
    """Run a PowerShell command safely and capture output."""
    try:
        # Use powershell.exe -Command with proper quoting
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=10
        )
        return {
            "rc": completed.returncode,
            "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip(),
        }
    except Exception as e:
        return {"rc": -1, "error": str(e)}


def _enforce_block_ip(targets: List[str]) -> Dict[str, Any]:
    if settings.SAFE_MODE or not settings.ENABLE_SYSTEM_ENFORCEMENT or not settings.is_windows():
        msg = f"[safe] block_ip {targets}"
        logger.info(msg)
        _append_monitor_log("ENFORCE: " + msg)
        return {"status": "simulated", "details": msg}
    results = []
    for ip in targets or []:
        rule_name = f"{settings.FIREWALL_RULE_PREFIX}-{ip}"
        ps = (
            f"New-NetFirewallRule -DisplayName '{rule_name}' -Direction Inbound -Action Block -RemoteAddress {ip}"
        )
        res = _run_powershell(ps)
        results.append({"ip": ip, **res})
    return {"status": "attempted", "results": results}


def _enforce_quarantine_endpoint(targets: List[str]) -> Dict[str, Any]:
    # In safe mode, just log. Real implementation could disable an interface/service.
    msg = f"quarantine_endpoint targets={targets}"
    logger.info(msg)
    _append_monitor_log("ENFORCE: " + msg)
    return {"status": "simulated", "details": msg}


def _enforce_isolate_assets(targets: List[str]) -> Dict[str, Any]:
    msg = f"isolate_assets {targets}"
    logger.info(msg)
    _append_monitor_log("ENFORCE: " + msg)
    return {"status": "simulated", "details": msg}


def _enforce_alert_operator(message: str) -> Dict[str, Any]:
    _append_monitor_log(f"OPERATOR ALERT: {message}")
    logger.warning(f"OPERATOR ALERT: {message}")
    return {"status": "notified", "message": message}


def enforce(actions: List[Dict[str, Any]], threat_id: Optional[str] = None) -> Dict[str, Any]:
    """Enforce a sequence of actions and return an execution summary.

    Respects config.settings.SAFE_MODE and ENABLE_SYSTEM_ENFORCEMENT.
    Always records activity to the threats store when threat_id is provided.
    """
    executed = []
    for act in actions:
        name = (act.get("action") or "").lower()
        targets = act.get("targets") or []
        if name == "block_ip":
            result = _enforce_block_ip(targets)
        elif name == "quarantine_endpoint":
            result = _enforce_quarantine_endpoint(targets)
        elif name == "isolate_assets":
            result = _enforce_isolate_assets(targets)
        elif name == "alert_operator":
            result = _enforce_alert_operator(act.get("message") or "Security event")
        else:
            msg = f"unknown action '{name}'"
            logger.info(msg)
            _append_monitor_log("ENFORCE: " + msg)
            result = {"status": "skipped", "details": msg}

        executed.append({
            "action": name,
            "targets": targets,
            "result": result,
        })
        # Record action against threat if available
        if threat_id:
            try:
                threats.add_action(threat_id, action=name, result='success', notes=str(result)[:500])
            except Exception as e:
                logger.debug(f"Failed to add action to threat {threat_id}: {e}")

    # Mark resolved and update store if we executed any action
    if threat_id:
        try:
            threats.update_status(threat_id, 'remediated')
        except Exception as e:
            logger.debug(f"Failed to set status=remediated for {threat_id}: {e}")

    try:
        mark_resolved({"actions_count": len(executed)})
    except Exception as e:
        logger.debug(f"Failed to mark resolved on dashboard: {e}")

    return {
        "executed_count": len(executed),
        "executed": executed,
        "summary": ("simulated" if settings.SAFE_MODE or not settings.ENABLE_SYSTEM_ENFORCEMENT else "attempted")
    }

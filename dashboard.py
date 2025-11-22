# dashboard.py
"""
Cybersecurity AI Dashboard - Web Interface Routes
dashboard for threat detection and analysis
"""

from fastapi import APIRouter, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime
import threading
import time
import os

import requests
from services.system_monitor import SystemNetworkMonitor

# Import your API functions
from api.utils import check_model_files
from services import threats_service as threats

# Configure logging
logger = logging.getLogger(__name__)

# Create router and templates
router = APIRouter()
templates = Jinja2Templates(directory="templates")

# Dashboard data storage (in production, use a database)
dashboard_stats = {
    "total_requests": 0,
    "successful_predictions": 0,
    "threats_detected": 0,
    "resolved_threats": 0,
    "last_activity": None,
    "uptime_start": datetime.now()
}

# --- In-process file-based monitor (prototype) ---
LOG_PATH = os.path.join(os.path.dirname(__file__), 'logs', 'monitor.log') if '__file__' in globals() else os.path.join('logs', 'monitor.log')
PIPELINE_ENDPOINT = 'http://127.0.0.1:8000/api/v1/pipeline/process'
_monitor_thread: Optional[threading.Thread] = None
_monitor_stop: Optional[threading.Event] = None
_monitor_lock = threading.Lock()
_system_monitor: Optional[SystemNetworkMonitor] = None


def _ensure_log_file():
    try:
        basedir = os.path.dirname(LOG_PATH)
        os.makedirs(basedir, exist_ok=True)
        if not os.path.exists(LOG_PATH):
            open(LOG_PATH, 'a', encoding='utf-8').close()
    except Exception as e:
        logger.warning(f"Failed to ensure monitor log file: {e}")


def _monitor_tail_loop(stop_event: threading.Event):
    _ensure_log_file()
    try:
        with open(LOG_PATH, 'r', encoding='utf-8') as fh:
            fh.seek(0, os.SEEK_END)
            logger.info(f"Monitor tail started on {LOG_PATH}")
            while not stop_event.is_set():
                pos = fh.tell()
                line = fh.readline()
                if not line:
                    time.sleep(0.5)
                    fh.seek(pos)
                    continue
                line = line.strip()
                if not line:
                    continue
                # Map line to features (proto): any 'MALICIOUS' triggers a high vector
                features = [100.0] * 70 if 'MALICIOUS' in line.upper() else [0.0] * 70
                try:
                    resp = requests.post(
                        PIPELINE_ENDPOINT,
                        params={'entry_point': 'web_server', 'max_steps': 3},
                        json={'features': features},
                        timeout=5
                    )
                    logger.info(f"Monitor posted event -> {resp.status_code}")
                except Exception as e:
                    logger.warning(f"Monitor failed to POST to pipeline: {e}")
    except Exception as e:
        logger.error(f"Monitor tail loop error: {e}")


def _start_monitor_thread() -> bool:
    global _monitor_thread, _monitor_stop
    with _monitor_lock:
        if _monitor_thread and _monitor_thread.is_alive():
            return False
        _monitor_stop = threading.Event()
        _monitor_thread = threading.Thread(target=_monitor_tail_loop, args=(_monitor_stop,), daemon=True)
        _monitor_thread.start()
        return True


def _stop_monitor_thread() -> bool:
    global _monitor_thread, _monitor_stop
    with _monitor_lock:
        if not _monitor_thread:
            return False
        if _monitor_stop:
            _monitor_stop.set()
        _monitor_thread = None
        return True

@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard_home(request: Request):
    """Main dashboard page"""
    try:
        # Get current model status for dashboard
        model_availability = check_model_files()
        available_models = sum(1 for available in model_availability.values() if available)
        total_models = len(model_availability)
        
        context = {
            "request": request,
            "title": "Cybersecurity AI Dashboard",
            "available_models": available_models,
            "total_models": total_models,
            "model_status": model_availability,
            "stats": dashboard_stats
        }
        
        return templates.TemplateResponse("dashboard.html", context)
        
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        raise HTTPException(status_code=500, detail=f"Dashboard loading failed: {str(e)}")

@router.get("/dashboard/api/stats")
async def get_dashboard_stats():
    """Get dashboard statistics for real-time updates"""
    try:
        model_availability = check_model_files()
        available_models = sum(1 for available in model_availability.values() if available)
        total_models = len(model_availability)
        
        uptime = datetime.now() - dashboard_stats["uptime_start"]
        uptime_str = str(uptime).split('.')[0]  # Remove microseconds
        
        th_stats = None
        try:
            th_stats = threats.stats()
        except Exception:
            th_stats = None

        if th_stats is not None:
            threats_detected = th_stats.get("total", 0)
            resolved_threats = th_stats.get("remediated", 0)
            active_threats = th_stats.get("active", 0)
        else:
            threats_detected = dashboard_stats.get("threats_detected", 0)
            resolved_threats = dashboard_stats.get("resolved_threats", 0)
            active_threats = 0

        resp = {
            "models": {
                "available": available_models,
                "total": total_models,
                "status": "healthy" if available_models > 0 else "warning"
            },
            "requests": {
                "total": dashboard_stats["total_requests"],
                "successful": dashboard_stats["successful_predictions"],
                "success_rate": (dashboard_stats["successful_predictions"] / max(dashboard_stats["total_requests"], 1)) * 100
            },
            "security": {
                "threats_detected": threats_detected,
                "resolved_threats": resolved_threats,
                "active_threats": active_threats,
                "last_activity": dashboard_stats["last_activity"]
            },
            "system": {
                "uptime": uptime_str,
                "status": "online",
                "timestamp": datetime.now().isoformat()
            }
        }

        # Attach system monitor status if available for continuous safe/alert UI
        global _system_monitor
        if _system_monitor is not None:
            try:
                sm = _system_monitor.get_status()
                if sm:
                    resp["system_monitor"] = {
                        "timestamp": sm.get("timestamp"),
                        "suspicious": sm.get("suspicious", False),
                        "metrics": sm.get("metrics", {})
                    }
            except Exception as e:
                logger.debug(f"Failed to read system monitor status: {e}")

        return resp
        
    except Exception as e:
        logger.error(f"Stats API error: {e}")
        return {
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }


@router.post("/dashboard/api/monitor/start")
async def start_monitor(source: str = "system"):
    """Start monitor: by default start BOTH system sampler and log tailer.

    - source=system: start system monitor and also start log tailer for compatibility
    - source=log: start only log tailer
    """
    global _system_monitor
    if source == "log":
        started = _start_monitor_thread()
        return {"status": "started" if started else "already-running", "mode": "log", "log_path": LOG_PATH}
    # Default: start both
    sys_started = False
    if _system_monitor is None:
        _system_monitor = SystemNetworkMonitor(PIPELINE_ENDPOINT, interval=2.0)
    sys_started = _system_monitor.start()
    log_started = _start_monitor_thread()
    return {
        "status": "started" if (sys_started or log_started) else "already-running",
        "mode": "system+log",
        "log_path": LOG_PATH
    }


@router.post("/dashboard/api/monitor/stop")
async def stop_monitor():
    """Stop both monitors (system first, then log tailer)."""
    global _system_monitor
    stopped_sys = False
    # Try system monitor first
    if _system_monitor is not None:
        stopped_sys = _system_monitor.stop()
        _system_monitor = None
    # Stop log tailer
    stopped_log = _stop_monitor_thread()
    return {"status": "stopped" if (stopped_sys or stopped_log) else "not-running", "mode": "system+log"}

@router.post("/dashboard/api/log-activity")
async def log_activity(activity_data: dict):
    """Log dashboard activity"""
    try:
        dashboard_stats["total_requests"] += 1
        dashboard_stats["last_activity"] = datetime.now().isoformat()
        
        if activity_data.get("status") == "success":
            dashboard_stats["successful_predictions"] += 1
            
        if activity_data.get("prediction") in ["ATTACK", "Bot", "DDoS"]:
            dashboard_stats["threats_detected"] += 1
        if activity_data.get("status") == "resolved":
            dashboard_stats["resolved_threats"] = dashboard_stats.get("resolved_threats", 0) + 1
            
        return {"status": "logged", "timestamp": datetime.now().isoformat()}
        
    except Exception as e:
        logger.error(f"Activity logging error: {e}")
        return {"error": str(e)}

@router.get("/dashboard/detection", response_class=HTMLResponse)
async def detection_dashboard(request: Request):
    """Threat detection interface"""
    context = {
        "request": request,
        "title": "Threat Detection",
        "page": "detection"
    }
    return templates.TemplateResponse("detection.html", context)

@router.get("/dashboard/simulation", response_class=HTMLResponse)
async def simulation_dashboard(request: Request):
    """Attack simulation interface"""
    context = {
        "request": request,
        "title": "Attack Simulation",
        "page": "simulation"
    }
    return templates.TemplateResponse("simulation.html", context)

@router.get("/dashboard/analytics", response_class=HTMLResponse)
async def analytics_dashboard(request: Request):
    """Analytics and reports interface"""
    context = {
        "request": request,
        "title": "Analytics & Reports",
        "page": "analytics"
    }
    return templates.TemplateResponse("analytics.html", context)

@router.get("/dashboard/models", response_class=HTMLResponse)
async def models_dashboard(request: Request):
    """Model status and management interface"""
    try:
        model_availability = check_model_files()
        
        context = {
            "request": request,
            "title": "Model Management",
            "page": "models",
            "models": model_availability
        }
        return templates.TemplateResponse("models.html", context)
        
    except Exception as e:
        logger.error(f"Models dashboard error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/dashboard/settings", response_class=HTMLResponse)
async def settings_dashboard(request: Request):
    """Settings and configuration interface"""
    context = {
        "request": request,
        "title": "Settings",
        "page": "settings"
    }
    return templates.TemplateResponse("settings.html", context)

# API endpoints for dashboard data
@router.get("/dashboard/api/model-status")
async def get_model_status():
    """Get detailed model status"""
    try:
        model_availability = check_model_files()
        
        # Enhanced model information
        model_details = {
            "mlp_model.h5": {
                "name": "Multi-Layer Perceptron",
                "type": "Deep Learning Classification",
                "framework": "TensorFlow/Keras",
                "status": "online" if model_availability.get("mlp_model.h5", False) else "offline",
                "description": "Neural network for multi-class threat classification",
                "expected_input": "70 features",
                "output": "12 attack classes"
            },
            "lstm_model.h5": {
                "name": "Long Short-Term Memory",
                "type": "Sequential Deep Learning",
                "framework": "TensorFlow/Keras", 
                "status": "online" if model_availability.get("lstm_model.h5", False) else "offline",
                "description": "Recurrent neural network for sequence-based threat detection",
                "expected_input": "70 features (sequential)",
                "output": "12 attack classes"
            },
            "isolation_forest.pkl": {
                "name": "Isolation Forest",
                "type": "Unsupervised Anomaly Detection",
                "framework": "Scikit-learn",
                "status": "online" if model_availability.get("isolation_forest.pkl", False) else "offline",
                "description": "Tree-based algorithm for identifying outliers and anomalies",
                "expected_input": "70 features",
                "output": "Binary (BENIGN/ATTACK)"
            },
            "autoencoder_model.h5": {
                "name": "Autoencoder Neural Network",
                "type": "Deep Learning Anomaly Detection",
                "framework": "TensorFlow/Keras",
                "status": "online" if model_availability.get("autoencoder_model.h5", False) else "offline",
                "description": "Neural network using reconstruction error for anomaly detection",
                "expected_input": "70 features",
                "output": "Binary (BENIGN/ATTACK)"
            },
            "scaler.pkl": {
                "name": "Standard Scaler",
                "type": "Preprocessing",
                "framework": "Scikit-learn",
                "status": "online" if model_availability.get("scaler.pkl", False) else "offline",
                "description": "Feature normalization and scaling",
                "expected_input": "79 raw features",
                "output": "70 scaled features"
            },
            "label_encoder.pkl": {
                "name": "Label Encoder",
                "type": "Preprocessing",
                "framework": "Scikit-learn", 
                "status": "online" if model_availability.get("label_encoder.pkl", False) else "offline",
                "description": "Converts attack class names to numerical labels",
                "expected_input": "Class names",
                "output": "Numerical labels (0-11)"
            }
        }
        
        return {
            "models": model_details,
            "summary": {
                "total": len(model_details),
                "online": sum(1 for model in model_details.values() if model["status"] == "online"),
                "offline": sum(1 for model in model_details.values() if model["status"] == "offline")
            },
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Model status API error: {e}")
        return {
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

@router.get("/dashboard/api/attack-types")
async def get_attack_types():
    """Get supported attack types and descriptions"""
    return {
        "attack_types": {
            "BENIGN": {
                "description": "Normal, legitimate network traffic",
                "severity": "low",
                "color": "success"
            },
            "Bot": {
                "description": "Botnet activity - compromised machines under remote control",
                "severity": "critical",
                "color": "danger"
            },
            "DDoS": {
                "description": "Distributed Denial of Service - coordinated traffic flood",
                "severity": "critical", 
                "color": "danger"
            },
            "DoS GoldenEye": {
                "description": "HTTP-based Denial of Service attack",
                "severity": "high",
                "color": "warning"
            },
            "DoS Hulk": {
                "description": "HTTP flood-based Denial of Service",
                "severity": "high",
                "color": "warning"
            },
            "DoS Slowhttptest": {
                "description": "Slow HTTP attack testing tool",
                "severity": "medium",
                "color": "info"
            },
            "DoS slowloris": {
                "description": "Slow connection-based DoS attack",
                "severity": "medium",
                "color": "info"
            },
            "FTP-Patator": {
                "description": "FTP brute force password attack",
                "severity": "high",
                "color": "warning"
            },
            "PortScan": {
                "description": "Network port scanning and reconnaissance",
                "severity": "medium",
                "color": "info"
            },
            "SSH-Patator": {
                "description": "SSH brute force password attack",
                "severity": "high",
                "color": "warning"
            },
            "Web Attack - Brute Force": {
                "description": "Web application brute force attack",
                "severity": "high",
                "color": "warning"
            },
            "Web Attack - XSS": {
                "description": "Cross-Site Scripting attack",
                "severity": "medium",
                "color": "info"
            }
        },
        "total_classes": 12,
        "timestamp": datetime.now().isoformat()
    }

@router.get("/dashboard/api/system-info")
async def get_system_info():
    """Get system information for dashboard"""
    try:
        import sys
        import psutil
        import platform
        
        # Get system metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        return {
            "system": {
                "platform": platform.system(),
                "python_version": sys.version.split()[0],
                "cpu_usage": cpu_percent,
                "memory_usage": memory.percent,
                "disk_usage": disk.percent,
                "available_memory": f"{memory.available / (1024**3):.1f} GB"
            },
            "application": {
                "uptime": str(datetime.now() - dashboard_stats["uptime_start"]).split('.')[0],
                "total_requests": dashboard_stats["total_requests"],
                "successful_predictions": dashboard_stats["successful_predictions"],
                "threats_detected": dashboard_stats["threats_detected"]
            },
            "timestamp": datetime.now().isoformat()
        }
        
    except ImportError:
        # Fallback if psutil is not installed
        return {
            "system": {
                "platform": "Unknown",
                "python_version": "Unknown",
                "note": "Install psutil for detailed system metrics"
            },
            "application": {
                "uptime": str(datetime.now() - dashboard_stats["uptime_start"]).split('.')[0],
                "total_requests": dashboard_stats["total_requests"],
                "successful_predictions": dashboard_stats["successful_predictions"],
                "threats_detected": dashboard_stats["threats_detected"]
            },
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"System info error: {e}")
        return {
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

# Health check for dashboard
@router.get("/dashboard/health")
async def dashboard_health():
    """Dashboard health check"""
    try:
        model_availability = check_model_files()
        available_models = sum(1 for available in model_availability.values() if available)
        
        status = "healthy" if available_models > 0 else "warning"
        
        return {
            "status": status,
            "dashboard": "operational",
            "models_available": available_models,
            "timestamp": datetime.now().isoformat(),
            "uptime": str(datetime.now() - dashboard_stats["uptime_start"]).split('.')[0]
        }
        
    except Exception as e:
        logger.error(f"Dashboard health check error: {e}")
        return {
            "status": "error",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

# Reset dashboard statistics (for testing/admin)
@router.post("/dashboard/api/reset-stats")
async def reset_dashboard_stats():
    """Reset dashboard statistics"""
    global dashboard_stats
    dashboard_stats = {
        "total_requests": 0,
        "successful_predictions": 0,
        "threats_detected": 0,
        "resolved_threats": 0,
        "last_activity": None,
        "uptime_start": datetime.now()
    }
    
    logger.info("Dashboard statistics reset")
    return {
        "status": "reset",
        "timestamp": datetime.now().isoformat()
    }


def mark_resolved(details: Optional[Dict[str, Any]] = None) -> None:
    """Mark a threat as resolved and update dashboard stats.

    This function is intended to be called by the response module after an
    enforcement action succeeded. It updates in-memory stats used by the
    dashboard overview.
    """
    try:
        dashboard_stats["resolved_threats"] = dashboard_stats.get("resolved_threats", 0) + 1
        dashboard_stats["last_activity"] = datetime.now().isoformat()
        logger.info(f"Threat marked as resolved: {details}")
    except Exception as e:
        logger.error(f"Failed to mark threat resolved: {e}")

def mark_detected(details: Optional[Dict[str, Any]] = None) -> None:
    """Mark that a threat/anomaly was detected and update dashboard stats."""
    try:
        dashboard_stats["threats_detected"] = dashboard_stats.get("threats_detected", 0) + 1
        dashboard_stats["last_activity"] = datetime.now().isoformat()
        logger.info(f"Threat detected: {details}")
    except Exception as e:
        logger.error(f"Failed to mark threat detected: {e}")



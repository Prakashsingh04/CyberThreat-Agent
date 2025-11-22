# api/routes.py
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from typing import List, Optional
import numpy as np
import time
import logging

from .utils import (
    validate_features, check_model_files, predict_anomaly
)
from agents.model_manager import load_all, get_model, get_scaler, get_label_encoder
# Agents orchestrator (lightweight)
import agents.preprocessor as agent_preproc
import agents.detection_agent as agent_detect
import agents.simulator_agent as agent_sim
import agents.decision_agent as agent_decide
import agents.response_module as agent_response
import agents.feedback as agent_feedback
from dashboard import mark_detected
from services import threats_service as threats

logger = logging.getLogger(__name__)
router = APIRouter()
# In api/routes.py - Update the InputData class
class InputData(BaseModel):
    features: List[float] = Field(..., min_length=70, max_length=79)

    @field_validator('features')
    def check_feature_length(cls, v):
        if len(v) not in [70, 75, 79]:
            raise ValueError(f'Expected 70, 75, or 79 features, got {len(v)}')
        if any(not isinstance(x, (float, int)) for x in v):
            raise ValueError('All features must be numerical')
        return v


class PredictionResponse(BaseModel):
    prediction: str = Field(..., description="Predicted class or anomaly result")
    confidence: Optional[float] = Field(None, description="Confidence score")
    model_used: str = Field(..., description="Model used for prediction")
    processing_time: float = Field(..., description="Processing time in seconds")
    status: str = Field(default="success", description="Status of the prediction")

# Global variables
models = {}
scaler = None
label_encoder = None

def initialize_models():
    global models, scaler, label_encoder
    try:
        # Use the centralized model manager to load and cache models
        load_all()
        models = {
            'autoencoder': get_model('autoencoder')
        }
        scaler = get_scaler()
        label_encoder = get_label_encoder()
        logger.info("Models initialized via model_manager.")
    except Exception as e:
        logger.error(f"Error loading models: {e}")

try:
    initialize_models()
except Exception as e:
    logger.warning(f"Model initialization error: {e}")

@router.get("/")
async def detection_home():
    return {
        "message": "Cybersecurity Detection API",
        "version": "2.0.0",
        "status": "operational",
        "models_available": {k: (v is not None) for k,v in models.items()},
        "supported_classes": list(label_encoder.classes_) if label_encoder else [],
    }

@router.post("/predict/anomaly/autoencoder", response_model=PredictionResponse)
async def predict_autoencoder(data: InputData):
    if not models.get('autoencoder') or not scaler:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail="Autoencoder model or scaler unavailable")
    start = time.time()
    try:
        pred = predict_anomaly(models['autoencoder'], data.features, scaler, method="autoencoder")
        proc_time = time.time() - start
        return PredictionResponse(prediction=pred, model_used="Autoencoder Neural Network", processing_time=round(proc_time, 4))
    except Exception as e:
        logger.error(e)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(e))

@router.get("/models/status")
async def get_models_status():
    return {
        "models": {
            "mlp": {
                "loaded": models.get('mlp') is not None,
                "type": "Deep Learning Classification",
                "framework": "TensorFlow/Keras"
            },
            "lstm": {
                "loaded": models.get('lstm') is not None,
                "type": "Deep Learning Sequential Classification",
                "framework": "TensorFlow/Keras"
            },
            "isolation_forest": {
                "loaded": models.get('isolation_forest') is not None,
                "type": "Machine Learning Anomaly Detection",
                "framework": "Scikit-learn"
            },
            "autoencoder": {
                "loaded": models.get('autoencoder') is not None,
                "type": "Deep Learning Anomaly Detection",
                "framework": "TensorFlow/Keras"
            }
        },
        "preprocessing": {
            "scaler_loaded": scaler is not None,
            "label_encoder_loaded": label_encoder is not None
        }
    }

@router.get("/info/classes")
async def get_class_info():
    if not label_encoder:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail="Label encoder not loaded")
    return {
        "supported_classes": list(label_encoder.classes_),
        "total_classes": len(label_encoder.classes_),
        "description": "Attack types that the models can detect"
    }


class PipelineResponse(BaseModel):
    detection: dict
    simulation: Optional[dict]
    actions: List[dict]
    enforcement: dict
    feedback_recorded: bool = False


@router.post("/pipeline/process", response_model=PipelineResponse)
async def process_pipeline(data: InputData, entry_point: str = "web_server", max_steps: int = 3, source_ip: Optional[str] = None, endpoint_name: Optional[str] = None):
    """Orchestrate the agents end-to-end for a single event.

    Steps: validate -> preprocess -> detect -> (simulate) -> decide -> respond -> feedback
    This endpoint is a prototype orchestrator to exercise the pipeline.
    """
    # Validate
    ok, msg = validate_features(data.features)
    if not ok:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=msg)

    # Preprocess (returns processed array and optionally scaler/encoder)
    try:
        _, scaler, label_encoder = agent_preproc.prepare(data.features)
    except Exception:
        scaler, label_encoder = None, None

    # Detection (anomaly only using autoencoder)
    anomaly = agent_detect.detect_anomaly(data.features, method='autoencoder')

    detection_summary = {
        "label": None,
        "confidence": None,
        "model_used": "autoencoder",
        "anomaly": anomaly,
        "source_ip": source_ip,
        "endpoint": endpoint_name,
    }

    # Record detection in dashboard stats and threats store when anomaly detected
    threat_record = None
    if anomaly == "ATTACK":
        try:
            mark_detected({"source_ip": source_ip, "endpoint": endpoint_name, "model": "autoencoder"})
        except Exception as e:
            logger.debug(f"Failed to mark detection in dashboard: {e}")
        try:
            threat_record = threats.add_threat(
                th_type="Anomaly",
                severity="high",
                source_ip=source_ip,
                endpoint=endpoint_name,
                model="autoencoder",
                details={"entry_point": entry_point}
            )
        except Exception as e:
            logger.warning(f"Failed to create threat record: {e}")

    # Simulation: only run when anomaly detected
    simulation_result = None
    if anomaly == "ATTACK":
        try:
            simulation_result = agent_sim.simulate_attack(entry_point=entry_point, attack_type="Anomaly", max_steps=max_steps)
        except Exception as e:
            simulation_result = {"error": str(e)}

    # Decision making
    actions = agent_decide.plan_actions(detection_summary, simulation_result)

    # Enforce actions (simulated)
    enforcement = agent_response.enforce(actions, threat_id=threat_record['id'] if threat_record else None)

    # Update threat status and action history if we created one
    if threat_record and enforcement:
        try:
            threats.update_status(threat_record['id'], 'remediated')
            threats.add_action(threat_record['id'], action='auto-remediate', result='success', notes='Automated enforcement applied')
        except Exception as e:
            logger.debug(f"Failed to update threat record: {e}")

    # Feedback
    try:
        feedback_payload = {
            "detection": detection_summary,
            "simulation_id": simulation_result.get("simulation_id") if simulation_result else None,
            "actions": actions,
            "enforcement_summary": enforcement,
        }
        agent_feedback.record(feedback_payload)
        feedback_ok = True
    except Exception:
        feedback_ok = False

    return PipelineResponse(
        detection=detection_summary,
        simulation=simulation_result,
        actions=actions,
        enforcement=enforcement,
        feedback_recorded=feedback_ok
    )

# --- Simulation utilities: Inject a test threat from a scenario ---

class InjectThreatRequest(BaseModel):
    entry_point: Optional[str] = Field(default=None, description="Entry point used in simulation")
    attack_type: str = Field(..., description="Attack type from simulation (e.g., DDoS, PortScan)")
    severity: Optional[str] = Field(default=None, description="Optional severity override: low|medium|high|critical")
    notes: Optional[str] = Field(default=None, description="Optional notes to attach to the threat")
    source_ip: Optional[str] = Field(default=None)
    endpoint: Optional[str] = Field(default=None)
    auto_remediate: Optional[bool] = Field(default=True, description="If true, immediately auto-remediate the injected threat")


def _default_severity(attack_type: str) -> str:
    at = (attack_type or '').lower()
    if any(k in at for k in ['bot', 'ddos']):
        return 'critical'
    if any(k in at for k in ['goldeneye', 'hulk', 'patator', 'brute']):
        return 'high'
    if any(k in at for k in ['portscan', 'xss', 'slowloris', 'slowhttp']):
        return 'medium'
    return 'low'


@router.post("/simulation/inject-threat")
async def inject_threat(req: InjectThreatRequest):
    """Create a test threat record based on a simulated scenario.

    Returns the newly created threat for immediate use in Threat Management.
    """
    try:
        allowed = {"low", "medium", "high", "critical"}
        sev = (req.severity or "").strip().lower() if req.severity else None
        if not sev or sev not in allowed:
            sev = _default_severity(req.attack_type)
        # Create as active first
        th = threats.add_threat(
            th_type=f"Simulation:{req.attack_type}",
            severity=sev,
            source_ip=req.source_ip,
            endpoint=req.endpoint or req.entry_point,
            model="simulation",
            details={"notes": req.notes or "injected from simulation"}
        )
        auto_flag = False
        if req.auto_remediate:
            try:
                # Plan and enforce using agents
                actions = agent_decide.plan_actions(
                    {"label": req.attack_type, "anomaly": "ATTACK", "source_ip": req.source_ip, "endpoint": req.endpoint or req.entry_point},
                    None,
                )
                enforcement = agent_response.enforce(actions, threat_id=th['id'])
                th = threats.get_threat(th['id']) or th
                agent_feedback.record({
                    "source": "simulation_inject",
                    "actions": actions,
                    "enforcement": enforcement,
                }, threat_id=th['id'], severity=th.get('severity'))
                auto_flag = True
            except Exception as e:
                logger.warning(f"Failed to auto-remediate injected threat {th['id']}: {e}")
        return {"status": "created", "auto_remediated": auto_flag, "threat": th}
    except Exception as e:
        logger.error(f"Failed to inject threat: {e}")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

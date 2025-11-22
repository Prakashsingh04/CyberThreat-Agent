 
# api/simulation_api.py
"""
Attack Simulation API for MITRE ATT&CK mapping and network analysis
Based on your cybersecurity AI project requirements
"""

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
import random
from datetime import datetime
import logging
from services import threats_service as threats
import agents.decision_agent as agent_decide
import agents.response_module as agent_response
import agents.feedback as agent_feedback
from config import settings

# Configure logging
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/simulation", tags=["Attack Simulation"])

# Pydantic models for requests/responses
class AttackSimulationRequest(BaseModel):
    """Request model for attack simulation"""
    entry_point: str = Field(..., description="Network entry point for attack")
    attack_type: str = Field(..., description="Type of attack to simulate")
    target_assets: Optional[List[str]] = Field(None, description="Specific target assets")
    max_steps: int = Field(5, ge=1, le=10, description="Maximum simulation steps")

class MITREMappingRequest(BaseModel):
    """Request for MITRE ATT&CK mapping"""
    attack_class: str = Field(..., description="Detected attack class")
    include_chain: bool = Field(True, description="Include attack chain analysis")

class NetworkAnalysisRequest(BaseModel):
    """Request for network analysis"""
    asset_id: Optional[str] = Field(None, description="Specific asset to analyze")
    include_paths: bool = Field(True, description="Include attack paths")

class AttackPath(BaseModel):
    """Represents an attack path"""
    path: List[str] = Field(..., description="Sequence of compromised assets")
    probability: float = Field(..., ge=0.0, le=1.0, description="Attack success probability")
    techniques: List[str] = Field(..., description="MITRE ATT&CK techniques used")
    estimated_time: str = Field(..., description="Estimated time to complete")
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Risk assessment score")

class SimulationResponse(BaseModel):
    """Attack simulation response"""
    simulation_id: str
    entry_point: str
    attack_type: str
    possible_paths: List[AttackPath]
    critical_assets_at_risk: List[str]
    recommended_defenses: List[str]
    timestamp: datetime

class MITREResponse(BaseModel):
    """MITRE ATT&CK mapping response"""
    attack_class: str
    techniques: List[Dict[str, str]]
    tactics: List[str]
    severity: float = Field(..., ge=0.0, le=1.0)
    detection_methods: List[str]
    next_likely_steps: List[str]

class NetworkAnalysisResponse(BaseModel):
    """Network analysis response"""
    total_assets: int
    entry_points: List[str]
    critical_assets: List[str]
    high_risk_connections: List[Dict[str, Any]]
    graph_metrics: Dict[str, float]

SUPPORTED_ATTACKS = [
    'BENIGN', 'Bot', 'DDoS', 'DoS GoldenEye', 'DoS Hulk', 'DoS Slowhttptest',
    'DoS slowloris', 'FTP-Patator', 'PortScan', 'SSH-Patator',
    'Web Attack - Brute Force', 'Web Attack - XSS'
]

# MITRE ATT&CK mappings based on CICIDS2017 attacks
MITRE_MAPPINGS = {
    "DDoS": {
        "techniques": [
            {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
            {"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"}
        ],
        "severity": 0.8,
        "tactics": ["Impact"],
        "detection_methods": [
            "Network traffic monitoring",
            "Bandwidth utilization analysis",
            "Connection rate monitoring"
        ],
        "next_steps": ["T1041", "T1071"]
    },
    "DoS Hulk": {
        "techniques": [
            {"id": "T1498.001", "name": "Direct Network Flood", "tactic": "Impact"}
        ],
        "severity": 0.7,
        "tactics": ["Impact"],
        "detection_methods": [
            "HTTP request rate monitoring",
            "Resource utilization tracking"
        ],
        "next_steps": ["T1498", "T1565"]
    },
    "DoS GoldenEye": {
        "techniques": [
            {"id": "T1498.002", "name": "Reflection Amplification", "tactic": "Impact"}
        ],
        "severity": 0.7,
        "tactics": ["Impact"],
        "detection_methods": [
            "HTTP header analysis",
            "Connection pattern monitoring"
        ],
        "next_steps": ["T1498", "T1565"]
    },
    "DoS slowloris": {
        "techniques": [
            {"id": "T1499.004", "name": "Application Exhaustion Flood", "tactic": "Impact"}
        ],
        "severity": 0.6,
        "tactics": ["Impact"],
        "detection_methods": [
            "Connection timeout monitoring",
            "Partial HTTP request detection"
        ],
        "next_steps": ["T1498", "T1499"]
    },
    "DoS Slowhttptest": {
        "techniques": [
            {"id": "T1499.004", "name": "Application Exhaustion Flood", "tactic": "Impact"}
        ],
        "severity": 0.6,
        "tactics": ["Impact"],
        "detection_methods": [
            "Slow HTTP attack detection",
            "Request completion time analysis"
        ],
        "next_steps": ["T1498", "T1499"]
    },
    "PortScan": {
        "techniques": [
            {"id": "T1046", "name": "Network Service Scanning", "tactic": "Discovery"}
        ],
        "severity": 0.4,
        "tactics": ["Discovery"],
        "detection_methods": [
            "Port scan detection",
            "Network reconnaissance monitoring"
        ],
        "next_steps": ["T1110", "T1190", "T1021"]
    },
    "FTP-Patator": {
        "techniques": [
            {"id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access"},
            {"id": "T1021.003", "name": "Distributed Component Object Model", "tactic": "Lateral Movement"}
        ],
        "severity": 0.7,
        "tactics": ["Credential Access", "Lateral Movement"],
        "detection_methods": [
            "Failed login attempt monitoring",
            "FTP connection analysis"
        ],
        "next_steps": ["T1078", "T1021", "T1083"]
    },
    "SSH-Patator": {
        "techniques": [
            {"id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access"},
            {"id": "T1021.004", "name": "SSH", "tactic": "Lateral Movement"}
        ],
        "severity": 0.8,
        "tactics": ["Credential Access", "Lateral Movement"],
        "detection_methods": [
            "SSH failed login monitoring",
            "Brute force attack detection"
        ],
        "next_steps": ["T1078", "T1021", "T1083"]
    },
    "Web Attack - Brute Force": {
        "techniques": [
            {"id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access"},
            {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}
        ],
        "severity": 0.7,
        "tactics": ["Credential Access", "Initial Access"],
        "detection_methods": [
            "Web application login monitoring",
            "HTTP request pattern analysis"
        ],
        "next_steps": ["T1078", "T1059", "T1083"]
    },
    "Web Attack - XSS": {
        "techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
            {"id": "T1059.007", "name": "JavaScript", "tactic": "Execution"}
        ],
        "severity": 0.6,
        "tactics": ["Initial Access", "Execution"],
        "detection_methods": [
            "XSS payload detection",
            "Client-side script monitoring"
        ],
        "next_steps": ["T1078", "T1059", "T1005"]
    },
    "Bot": {
        "techniques": [
            {"id": "T1071.001", "name": "Web Protocols", "tactic": "Command and Control"},
            {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"}
        ],
        "severity": 0.9,
        "tactics": ["Command and Control", "Exfiltration"],
        "detection_methods": [
            "C2 traffic analysis",
            "Behavioral pattern recognition"
        ],
        "next_steps": ["T1005", "T1083", "T1057"]
    }
}

# Mock network assets
NETWORK_ASSETS = [
    "web_server", "db_server", "domain_controller", "file_server",
    "workstation_1", "workstation_2", "firewall", "router",
    "email_server", "backup_server", "dns_server", "proxy_server"
]

@router.get("/")
async def simulation_home():
    """Simulation API home endpoint"""
    return {
        "message": "⚔️ Cybersecurity Attack Simulation API",
        "version": "2.0.0",
        "status": "operational",
        "supported_attacks": SUPPORTED_ATTACKS,
        "available_endpoints": [
            "/simulate-attack", "/analyze-network", "/mitre-mapping",
            "/attack-paths", "/techniques", "/assets"
        ],
        "features": [
            "MITRE ATT&CK mapping",
            "Attack path simulation",
            "Network topology analysis",
            "Risk assessment"
        ]
    }

@router.post("/simulate-attack", response_model=SimulationResponse)
async def simulate_attack(request: AttackSimulationRequest):
    """
    Simulate an attack scenario based on detected threat
    """
    try:
        # Validate attack type
        if request.attack_type not in SUPPORTED_ATTACKS:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported attack type. Supported: {SUPPORTED_ATTACKS}"
            )
        
        # Generate simulation ID
        simulation_id = f"sim_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{random.randint(1000,9999)}"
        
        # Generate attack paths
        possible_paths = []
        
        for i in range(min(3, request.max_steps)):
            # Create realistic attack path
            path_assets = [request.entry_point]
            current_asset = request.entry_point
            
            # Generate path based on attack type
            for step in range(min(request.max_steps - 1, 4)):
                next_candidates = [asset for asset in NETWORK_ASSETS 
                                if asset != current_asset and asset not in path_assets]
                
                if next_candidates:
                    # Prioritize critical assets for certain attack types
                    if request.attack_type in ["Bot", "DDoS"]:
                        critical_assets = [a for a in next_candidates if "server" in a]
                        next_asset = random.choice(critical_assets if critical_assets else next_candidates)
                    else:
                        next_asset = random.choice(next_candidates)
                    
                    path_assets.append(next_asset)
                    current_asset = next_asset
            
            # Get MITRE techniques for this attack
            mitre_data = MITRE_MAPPINGS.get(request.attack_type, {})
            techniques = [t["id"] for t in mitre_data.get("techniques", [])]
            
            # Calculate metrics
            probability = random.uniform(0.3, 0.9) if request.attack_type != "BENIGN" else 0.1
            risk_score = mitre_data.get("severity", 0.5) * probability
            
            attack_path = AttackPath(
                path=path_assets,
                probability=round(probability, 2),
                techniques=techniques,
                estimated_time=f"{random.randint(5, 120)} minutes",
                risk_score=round(risk_score, 2)
            )
            possible_paths.append(attack_path)
        
        # Identify critical assets at risk
        all_assets = set()
        for path in possible_paths:
            all_assets.update(path.path)
        
        critical_assets = [asset for asset in all_assets 
                          if any(keyword in asset for keyword in ["server", "controller", "domain"])]
        
        # Generate defense recommendations
        mitre_data = MITRE_MAPPINGS.get(request.attack_type, {})
        recommendations = mitre_data.get("detection_methods", [])
        recommendations.extend([
            "Implement network segmentation",
            "Enable multi-factor authentication",
            "Deploy endpoint detection and response (EDR)",
            "Update security policies"
        ])
        
        resp = SimulationResponse(
            simulation_id=simulation_id,
            entry_point=request.entry_point,
            attack_type=request.attack_type,
            possible_paths=possible_paths,
            critical_assets_at_risk=critical_assets,
            recommended_defenses=recommendations[:5],  # Limit to 5 recommendations
            timestamp=datetime.now()
        )

        # Log this simulated attack into Threat Management automatically
        try:
            sev_numeric = MITRE_MAPPINGS.get(request.attack_type, {}).get("severity", 0.5)
            # Use plain attack type for easier filtering in UI; mark simulation flag in details
            th = threats.add_threat(
                th_type=request.attack_type,
                severity=sev_numeric,
                source_ip=None,
                endpoint=request.entry_point,
                model="simulation",
                details={
                    "simulation_id": simulation_id,
                    "critical_assets_at_risk": critical_assets,
                    "recommended_defenses": recommendations[:5],
                    "origin": "simulation"
                },
                status='active'
            )
            # Append operator alert line to monitor log for visibility
            try:
                os.makedirs('logs', exist_ok=True)
                with open(os.path.join('logs','monitor.log'), 'a', encoding='utf-8') as lf:
                    lf.write(f"{datetime.utcnow().isoformat()} | OPERATOR ALERT: Simulation recorded {request.attack_type} threat id={th['id']}\n")
            except Exception:
                pass
            # Optionally auto-remediate using decision/response pipeline
            if settings.AUTO_REMEDIATE_SIMULATION:
                try:
                    actions = agent_decide.plan_actions(
                        {
                            "label": request.attack_type,
                            "anomaly": "ATTACK",
                            "source_ip": None,
                            "endpoint": request.entry_point,
                        },
                        {
                            "critical_assets_at_risk": critical_assets
                        }
                    )
                    enforcement = agent_response.enforce(actions, threat_id=th['id'])
                    agent_feedback.record(
                        {
                            "source": "simulation_auto",
                            "simulation_id": simulation_id,
                            "actions": actions,
                            "enforcement": enforcement,
                        },
                        threat_id=th['id'],
                        severity=th.get('severity')
                    )
                except Exception as ee:
                    logger.warning(f"Simulation auto-remediation failed: {ee}")
        except Exception as e:
            logger.warning(f"Failed to log simulated attack to threats: {e}")

        return resp
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Attack simulation error: {e}")
        raise HTTPException(status_code=500, detail=f"Simulation failed: {str(e)}")

@router.post("/mitre-mapping", response_model=MITREResponse)
async def get_mitre_mapping(request: MITREMappingRequest):
    """
    Get MITRE ATT&CK mapping for detected attack class
    """
    try:
        attack_class = request.attack_class
        
        if attack_class not in MITRE_MAPPINGS:
            raise HTTPException(
                status_code=404,
                detail=f"No MITRE mapping found for attack class '{attack_class}'"
            )
        
        mapping = MITRE_MAPPINGS[attack_class]
        
        return MITREResponse(
            attack_class=attack_class,
            techniques=mapping["techniques"],
            tactics=mapping["tactics"],
            severity=mapping["severity"],
            detection_methods=mapping["detection_methods"],
            next_likely_steps=mapping["next_steps"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"MITRE mapping error: {e}")
        raise HTTPException(status_code=500, detail=f"MITRE mapping failed: {str(e)}")

@router.post("/analyze-network", response_model=NetworkAnalysisResponse)
async def analyze_network(request: NetworkAnalysisRequest):
    """
    Analyze network topology and identify vulnerabilities
    """
    try:
        # Mock network analysis
        entry_points = ["web_server", "email_server", "firewall"]
        critical_assets = ["db_server", "domain_controller", "file_server"]
        
        # Generate high-risk connections
        high_risk_connections = []
        for i in range(3):
            source = random.choice(NETWORK_ASSETS)
            target = random.choice([a for a in NETWORK_ASSETS if a != source])
            
            high_risk_connections.append({
                "source": source,
                "target": target,
                "risk_level": random.choice(["medium", "high", "critical"]),
                "vulnerability_score": round(random.uniform(0.4, 0.9), 2),
                "recommendation": f"Secure connection between {source} and {target}"
            })
        
        # Generate graph metrics
        graph_metrics = {
            "density": round(random.uniform(0.3, 0.7), 2),
            "clustering_coefficient": round(random.uniform(0.4, 0.8), 2),
            "average_path_length": round(random.uniform(2.0, 4.0), 1),
            "vulnerability_index": round(random.uniform(0.3, 0.8), 2)
        }
        
        return NetworkAnalysisResponse(
            total_assets=len(NETWORK_ASSETS),
            entry_points=entry_points,
            critical_assets=critical_assets,
            high_risk_connections=high_risk_connections,
            graph_metrics=graph_metrics
        )
        
    except Exception as e:
        logger.error(f"Network analysis error: {e}")
        raise HTTPException(status_code=500, detail=f"Network analysis failed: {str(e)}")

@router.get("/attack-paths/{entry_point}")
async def get_attack_paths(entry_point: str, max_depth: int = 3):
    """
    Get possible attack paths from an entry point
    """
    try:
        if entry_point not in NETWORK_ASSETS:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown entry point. Available: {NETWORK_ASSETS}"
            )
        
        paths = []
        for i in range(3):
            path = [entry_point]
            current = entry_point
            
            for depth in range(max_depth):
                candidates = [a for a in NETWORK_ASSETS if a != current and a not in path]
                if candidates:
                    next_asset = random.choice(candidates)
                    path.append(next_asset)
                    current = next_asset
                else:
                    break
            
            paths.append({
                "path_id": f"path_{i+1}",
                "nodes": path,
                "length": len(path),
                "probability": round(random.uniform(0.2, 0.8), 2),
                "risk_score": round(random.uniform(0.3, 0.9), 2)
            })
        
        return {
            "entry_point": entry_point,
            "total_paths": len(paths),
            "paths": paths,
            "timestamp": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Attack paths analysis error: {e}")
        raise HTTPException(status_code=500, detail=f"Attack paths analysis failed: {str(e)}")

@router.get("/techniques")
async def list_mitre_techniques():
    """List available MITRE ATT&CK techniques"""
    all_techniques = []
    for attack_class, data in MITRE_MAPPINGS.items():
        for technique in data["techniques"]:
            technique_info = {
                "attack_class": attack_class,
                **technique
            }
            if technique_info not in all_techniques:
                all_techniques.append(technique_info)
    
    return {
        "total_techniques": len(all_techniques),
        "techniques": all_techniques,
        "supported_tactics": list(set(t["tactic"] for t in all_techniques))
    }

@router.get("/assets")
async def list_network_assets():
    """List available network assets"""
    return {
        "total_assets": len(NETWORK_ASSETS),
        "assets": NETWORK_ASSETS,
        "asset_categories": {
            "servers": [a for a in NETWORK_ASSETS if "server" in a],
            "workstations": [a for a in NETWORK_ASSETS if "workstation" in a],
            "network_devices": [a for a in NETWORK_ASSETS if a in ["firewall", "router", "proxy_server"]]
        }
    }

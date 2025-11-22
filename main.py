# main.py
"""

Run with: uvicorn main:app --reload
Dashboard: http://127.0.0.1:8000/web/dashboard
API Documentation: http://127.0.0.1:8000/docs
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from contextlib import asynccontextmanager
import logging
import os
import sys
import datetime

# Import routers
from api.routes import router as detection_router
from api.simulation_api import router as simulation_router
from api.threats_api import router as threats_router
from api.utils import setup_logging, check_model_files
from agents.model_manager import load_all as load_models_at_startup
from services import threats_service as threats_svc

# Import dashboard
import dashboard

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)

# Global variables
models_loaded = False
startup_time = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    global models_loaded, startup_time
    
    # Startup
    startup_time = datetime.datetime.now()
    logger.info("Starting Cybersecurity AI Detection System...")
    logger.info(f"Python version: {sys.version}")
    logger.info(f"Startup time: {startup_time}")
    
    try:
        # Create necessary directories
        os.makedirs("static/css", exist_ok=True)
        os.makedirs("static/js", exist_ok=True)
        os.makedirs("static/images", exist_ok=True)
        os.makedirs("templates", exist_ok=True)
        os.makedirs("logs", exist_ok=True)
        
        # Check model availability
        model_availability = check_model_files()
        logger.info(f"Model availability: {model_availability}")

        # Preload models at startup (cached by agents.model_manager)
        try:
            load_models_at_startup()
            logger.info("Model manager preloaded models at startup")
        except Exception as e:
            logger.warning(f"Model preloading failed: {e}")
        
        available_models = sum(1 for available in model_availability.values() if available)
        total_models = len(model_availability)
        
        if available_models == 0:
            logger.warning("No model files found! Please add your trained models to the 'models/' directory")
            logger.warning("Required files: mlp_model.h5, lstm_model.h5, autoencoder_model.h5, isolation_forest.pkl, scaler.pkl, label_encoder.pkl")
        else:
            logger.info(f"{available_models}/{total_models} model files found")
        
        models_loaded = True
        logger.info("Application startup completed successfully")
        logger.info("Dashboard available at: http://127.0.0.1:8000/web/dashboard")
        logger.info("API docs available at: http://127.0.0.1:8000/docs")
        try:
            fixed = threats_svc.sanitize_store()
            if fixed:
                logger.info(f"Sanitized threat store severities: fixed {fixed} record(s)")
            purged = threats_svc.purge_simulation_string()
            if purged:
                logger.info(f"Purged invalid simulation records: removed {purged} record(s)")
        except Exception as e:
            logger.warning(f"Threat store sanitation skipped: {e}")
        
    except Exception as e:
        logger.error(f" Startup error: {e}")
        models_loaded = False
    
    yield
    
    # Shutdown
    logger.info("Shutting down Cybersecurity AI Detection System...")
    uptime = datetime.datetime.now() - startup_time if startup_time else None
    if uptime:
        logger.info(f" Total uptime: {uptime}")

# Create FastAPI application
app = FastAPI(
    title="Cybersecurity AI Detection System",
    description="""
    ## 🛡️ Advanced Threat Detection using Machine Learning & Deep Learning
    
   
    ### 🔍 Supported Attack Types:
    `BENIGN`, `Bot`, `DDoS`, `DoS GoldenEye`, `DoS Hulk`, `DoS Slowhttptest`, 
    `DoS slowloris`, `FTP-Patator`, `PortScan`, `SSH-Patator`, 
    `Web Attack - Brute Force`, `Web Attack - XSS`
    
   
    1. **Dashboard**: Visit `/web/dashboard` for interactive web interface
    2. **API Docs**: Visit `/docs` for interactive API documentation
    3. **Classification**: Use `/api/v1/predict/classification/*` endpoints
    4. **Anomaly Detection**: Use `/api/v1/predict/anomaly/*` endpoints
    5. **Attack Simulation**: Explore `/api/v1/simulation/*` endpoints
    
  
    - **Backend**: FastAPI, Python 3.9.12
    - **ML/DL**: TensorFlow 2.12.0, scikit-learn 1.0.2
    - **Frontend**: Bootstrap 5, JavaScript
    - **Security**: MITRE ATT&CK Framework
    
    ### 📈 Performance:
    - **Response Time**: 23ms - 1.7s (depending on model)
    - **Accuracy**: 90%+ on CICIDS2017 test dataset
    - **Throughput**: Real-time processing capability
    """,
    version="2.0.0",
    terms_of_service="https://example.com/terms/",
    contact={
        "name": "Cybersecurity AI Research Team",
        "url": "https://example.com/contact/",
        "email": "cybersec@university.edu",
    },
    license_info={
        "name": "MIT License",
        "url": "https://opensource.org/licenses/MIT",
    },
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production: ["http://localhost:3000", "https://yourdomain.com"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Include routers with prefixes and tags
app.include_router(
    detection_router, 
    prefix="/api/v1", 
    tags=["🔍 Threat Detection"]
)

app.include_router(
    simulation_router, 
    prefix="/api/v1", 
    tags=["⚔️ Attack Simulation"]
)

app.include_router(
    threats_router,
    prefix="/api/v1",
    tags=["🛡️ Threat Management"]
)

app.include_router(
    dashboard.router, 
    prefix="/web", 
    tags=["🖥️ Dashboard"]
)

# Root endpoint - redirect to dashboard
@app.get("/", response_class=HTMLResponse, tags=["🏠 Home"])
async def root():
    """Redirect to cybersecurity dashboard"""
    
    # Get system status for display
    try:
        model_availability = check_model_files()
        models_status = "✅ Models Loaded" if any(model_availability.values()) else "❌ No Models Found"
        models_count = sum(1 for available in model_availability.values() if available)
        total_count = len(model_availability)
    except Exception:
        models_status = "❓ Status Unknown"
        models_count = 0
        total_count = 6
    
    uptime = datetime.datetime.now() - startup_time if startup_time else "Unknown"
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>🔒 Cybersecurity AI Detection System</title>
        <meta http-equiv="refresh" content="3; url=/web/dashboard">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
        <style>
            body {{ 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }}
            .welcome-card {{
                background: rgba(255,255,255,0.95);
                backdrop-filter: blur(10px);
                border-radius: 20px;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                padding: 3rem;
                text-align: center;
                max-width: 600px;
            }}
            .spinner-border {{
                width: 3rem;
                height: 3rem;
            }}
            .status-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 1rem;
                margin: 2rem 0;
            }}
            .status-item {{
                background: #f8f9fa;
                padding: 1rem;
                border-radius: 10px;
                border: 1px solid #dee2e6;
            }}
        </style>
    </head>
    <body>
        <div class="welcome-card">
            <div class="mb-4">
                <i class="fas fa-shield-alt text-primary" style="font-size: 4rem;"></i>
            </div>
            
            <h1 class="h2 text-primary mb-3">
                🔒 Cybersecurity AI Detection System
            </h1>
            
            <p class="text-muted mb-4">
                Advanced Machine Learning Platform for Threat Detection & Analysis
            </p>
            
            <div class="status-grid">
                <div class="status-item">
                    <div class="fw-bold text-primary">Models</div>
                    <div>{models_count}/{total_count} Active</div>
                </div>
                <div class="status-item">
                    <div class="fw-bold text-success">Status</div>
                    <div>Online</div>
                </div>
                <div class="status-item">
                    <div class="fw-bold text-info">Version</div>
                    <div>v2.0.0</div>
                </div>
                <div class="status-item">
                    <div class="fw-bold text-warning">Uptime</div>
                    <div>{str(uptime).split('.')[0] if uptime != 'Unknown' else uptime}</div>
                </div>
            </div>
            
            <div class="mb-4">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
                <p class="mt-2 text-muted">Redirecting to Dashboard...</p>
            </div>
            
            <div class="d-flex gap-2 justify-content-center">
                <a href="/web/dashboard" class="btn btn-primary">
                    <i class="fas fa-tachometer-alt"></i> Go to Dashboard
                </a>
                <a href="/docs" class="btn btn-outline-primary">
                    <i class="fas fa-book"></i> API Documentation
                </a>
            </div>
            
            <hr class="my-4">
            
            <div class="row text-center">
                <div class="col-md-4">
                    <i class="fas fa-brain text-primary mb-2"></i>
                    <h6>ML/DL Models</h6>
                    <small class="text-muted">4 Advanced Models</small>
                </div>
                <div class="col-md-4">
                    <i class="fas fa-shield-alt text-success mb-2"></i>
                    <h6>Real-time Detection</h6>
                    <small class="text-muted">23ms Response Time</small>
                </div>
                <div class="col-md-4">
                    <i class="fas fa-chart-line text-warning mb-2"></i>
                    <h6>MITRE ATT&CK</h6>
                    <small class="text-muted">Framework Integration</small>
                </div>
            </div>
        </div>
        
        <script>
            // Auto-redirect after 3 seconds
            setTimeout(() => {{
                window.location.href = '/web/dashboard';
            }}, 3000);
        </script>
    </body>
    </html>
    """
    return html_content

# Health check endpoint
@app.get("/health", tags=["🏥 Health"])
async def health_check():
    """Comprehensive system health check"""
    try:
        model_availability = check_model_files()
        available_models = sum(1 for available in model_availability.values() if available)
        total_models = len(model_availability)
        
        # Calculate uptime
        uptime = datetime.datetime.now() - startup_time if startup_time else None
        uptime_str = str(uptime).split('.')[0] if uptime else "Unknown"
        
        return {
            "status": "healthy",
            "version": "2.0.0",
            "timestamp": datetime.datetime.now().isoformat(),
            "uptime": uptime_str,
            "models": {
                "available": available_models,
                "total": total_models,
                "loaded": models_loaded,
                "details": model_availability
            },
            "system": {
                "python_version": sys.version.split()[0],
                "platform": sys.platform,
                "startup_time": startup_time.isoformat() if startup_time else None
            },
            "endpoints": {
                "dashboard": "/web/dashboard",
                "api_docs": "/docs",
                "health": "/health",
                "detection": "/api/v1/predict/*",
                "simulation": "/api/v1/simulation/*"
            },
        "message": f"System operational! {available_models}/{total_models} models ready."
        }
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return {
            "status": "error",
            "version": "2.0.0",
            "timestamp": datetime.datetime.now().isoformat(),
            "error": str(e),
            "message": f"Health check failed: {str(e)}"
        }

# API Information endpoint
@app.get("/info", tags=["ℹ️ Information"])
async def api_info():
    """Get comprehensive API information and capabilities"""
    return {
        "api_name": "Cybersecurity AI Detection System",
        "version": "2.0.0",
        "description": "Advanced threat detection using ML/DL models with MITRE ATT&CK integration",
        "author": "Cybersecurity AI Research Team",
        "contact": "cybersec@university.edu",
        "documentation": {
            "dashboard": "/web/dashboard",
            "swagger_ui": "/docs",
            "redoc": "/redoc",
            "openapi_json": "/openapi.json"
        },
        "supported_models": {
            "classification": {
                "MLP": "Multi-Layer Perceptron for deep learning classification",
                "LSTM": "Long Short-Term Memory for sequential pattern analysis"
            },
            "anomaly_detection": {
                "Isolation Forest": "Unsupervised anomaly detection algorithm",
                "Autoencoder": "Neural network-based reconstruction for anomaly detection"
            }
        },
        "supported_attacks": [
            "BENIGN", "Bot", "DDoS", "DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest",
            "DoS slowloris", "FTP-Patator", "PortScan", "SSH-Patator", 
            "Web Attack - XSS", "Web Attack - Brute Force"
        ],
        "features": {
            "input_dimensions": "70-79 (automatic preprocessing)",
            "preprocessing": "StandardScaler + Feature Selection",
            "output_format": "JSON with predictions and metadata",
            "dataset": "CICIDS2017 Cybersecurity Dataset",
            "frameworks": {
                "backend": "FastAPI",
                "ml": "scikit-learn 1.0.2",
                "dl": "TensorFlow 2.12.0",
                "frontend": "Bootstrap 5 + JavaScript"
            }
        },
        "performance": {
            "response_time_range": "0.023s - 1.7s",
            "accuracy": "90%+ on test dataset",
            "throughput": "Real-time processing",
            "concurrent_requests": "Multiple concurrent requests supported"
        },
        "endpoints": {
            "classification": {
                "mlp": "/api/v1/predict/classification/mlp",
                "lstm": "/api/v1/predict/classification/lstm"
            },
            "anomaly_detection": {
                "isolation_forest": "/api/v1/predict/anomaly/isolation_forest",
                "autoencoder": "/api/v1/predict/anomaly/autoencoder"
            },
            "simulation": {
                "attack_simulation": "/api/v1/simulation/simulate-attack",
                "network_analysis": "/api/v1/simulation/analyze-network",
                "mitre_mapping": "/api/v1/simulation/mitre-mapping"
            },
            "system": {
                "model_status": "/api/v1/models/status",
                "class_info": "/api/v1/info/classes",
                "health_check": "/health"
            }
        },
        "usage_examples": {
            "curl_classification": '''curl -X POST "http://127.0.0.1:8000/api/v1/predict/classification/mlp" -H "Content-Type: application/json" -d '{"features": [/* 75 numerical values */]}''"''',
            "curl_anomaly": '''curl -X POST "http://127.0.0.1:8000/api/v1/predict/anomaly/isolation_forest" -H "Content-Type: application/json" -d '{"features": [/* 75 numerical values */]}''"''',
            "curl_simulation": '''curl -X POST "http://127.0.0.1:8000/api/v1/simulation/simulate-attack" -H "Content-Type: application/json" -d '{"entry_point": "web_server", "attack_type": "DDoS", "max_steps": 3}'"'''
        }
    }

# Custom error handlers
@app.exception_handler(404)
async def not_found_handler(request: Request, exc: HTTPException):
    """Custom 404 handler"""
    return HTMLResponse(
        content="""
        <html>
        <head>
            <title>404 - Page Not Found</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body class="bg-light d-flex align-items-center min-vh-100">
            <div class="container text-center">
                <div class="row justify-content-center">
                    <div class="col-md-6">
                        <h1 class="display-1 text-primary">404</h1>
                        <h2>Page Not Found</h2>
                        <p class="text-muted">The requested page could not be found.</p>
                        <a href="/web/dashboard" class="btn btn-primary">Go to Dashboard</a>
                        <a href="/docs" class="btn btn-outline-primary">API Documentation</a>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """,
        status_code=404
    )

@app.exception_handler(500)
async def internal_error_handler(request: Request, exc: HTTPException):
    """Custom 500 handler"""
    logger.error(f"Internal server error: {exc}")
    return HTMLResponse(
        content="""
        <html>
        <head>
            <title>500 - Internal Server Error</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body class="bg-light d-flex align-items-center min-vh-100">
            <div class="container text-center">
                <div class="row justify-content-center">
                    <div class="col-md-6">
                        <h1 class="display-1 text-danger">500</h1>
                        <h2>Internal Server Error</h2>
                        <p class="text-muted">Something went wrong on our end. Please try again later.</p>
                        <a href="/web/dashboard" class="btn btn-primary">Go to Dashboard</a>
                        <a href="/health" class="btn btn-outline-primary">Check System Health</a>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """,
        status_code=500
    )

# Startup message
@app.on_event("startup")
async def startup_message():
    """Display startup message"""
    print("\n" + "="*80)
    print("CYBERSECURITY AI DETECTION SYSTEM")
    print("="*80)
    print("Dashboard: http://127.0.0.1:8000/web/dashboard")
    print("API Docs: http://127.0.0.1:8000/docs")
    print("Health:   http://127.0.0.1:8000/health")
    print("Info:     http://127.0.0.1:8000/info")
    print("="*80 + "\n")

# Development server
if __name__ == "__main__":
    import uvicorn
    
    logger.info("Starting development server...")
    logger.info("Use Ctrl+C to stop the server")
    
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info",
        access_log=True
    )

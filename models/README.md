# Models Directory

This directory contains trained models and associated preprocessing objects used by the Cybersecurity AI Detection System.

> ⚠️ **Model binaries are not tracked in Git.** Per `.gitignore`, `models/*.h5` and `models/*.pkl` are excluded from version control. You must supply your own trained files here before running detection/anomaly endpoints.

## Expected files

| File | Purpose | Required for |
|------|---------|--------------|
| `autoencoder_model.h5` | Keras autoencoder — anomaly detection (BENIGN vs ATTACK) | Anomaly/pipeline endpoints |
| `isolation_forest.pkl` | scikit-learn Isolation Forest — anomaly detection | Anomaly endpoints |
| `mlp_model.h5` | Multi-Layer Perceptron — multi-class classification | Classification endpoints |
| `lstm_model.h5` | LSTM — sequential classification | Classification endpoints |
| `scaler.pkl` | StandardScaler — feature normalization | All model endpoints |
| `label_encoder.pkl` | LabelEncoder — class name ↔ label conversion | All model endpoints |

Minimum set to run the anomaly-detection pipeline: `autoencoder_model.h5`, `scaler.pkl`, `label_encoder.pkl`.

Without these files, anomaly endpoints return `503 Service Unavailable` and the dashboard reports the models as offline.

## How to add models

1. Train or obtain your model files (see `notebooks/` for training exploration, if present).
2. Place them in this directory:
   ```
   models/
   ├── autoencoder_model.h5
   ├── scaler.pkl
   └── label_encoder.pkl
   ```
3. Restart the application (`python main.py`). Startup logs will report how many model files were found.

## Related

- `config/settings.py` — runtime configuration and safe-mode toggles
- `agents/model_manager.py` — centralized model loading and caching
- `api/utils.py` — `check_model_files()` helper used at startup and in health endpoints

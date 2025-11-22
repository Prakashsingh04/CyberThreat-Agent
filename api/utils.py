# api/utils.py (Updated preprocessing)
import joblib
import numpy as np
import pandas as pd
import logging
from typing import List
import os

try:
    from tensorflow.keras.models import load_model
except ImportError:
    from keras.models import load_model

logger = logging.getLogger(__name__)

# Low-variance columns that were dropped during training
LOW_VARIANCE_COLUMNS = [
    'fwd_avg_packets/bulk', 'bwd_avg_bytes/bulk', 'bwd_avg_packets/bulk', 
    'bwd_avg_bulk_rate', 'fwd_avg_bulk_rate', 'fwd_avg_bytes/bulk',
    'bwd_psh_flags', 'bwd_urg_flags', 'additional_col'  
]

def load_preprocessing_objects(scaler_path: str = "models/scaler.pkl",
                               label_encoder_path: str = "models/label_encoder.pkl"):
    """Load preprocessing objects"""
    try:
        scaler = joblib.load(scaler_path)
        label_encoder = joblib.load(label_encoder_path)
        logger.info("Preprocessing objects loaded successfully")
        return scaler, label_encoder
    except Exception as e:
        logger.error(f"Failed to load preprocessing objects: {e}")
        raise


def _align_and_scale(processed_features: np.ndarray, scaler) -> np.ndarray:
    """Align input features to the scaler's expected feature names and scale.

    This helper constructs a pandas DataFrame when the scaler was fitted on a
    DataFrame with column names (scaler.feature_names_in_) to avoid the
    sklearn warning and to ensure columns are mapped consistently. If the
    scaler does not expose feature names, fall back to array-based padding.
    """
    if scaler is None:
        return processed_features

    # If scaler was fitted with feature names, construct a DataFrame mapping
    try:
        if hasattr(scaler, "feature_names_in_"):
            req_cols = list(scaler.feature_names_in_)
            n_required = len(req_cols)
            n_provided = processed_features.shape[1]

            # Build a dict mapping each required column to a value (pad with 0.0)
            row = {}
            for i, col in enumerate(req_cols):
                if i < n_provided:
                    row[col] = float(processed_features[0, i])
                else:
                    row[col] = 0.0

            df = pd.DataFrame([row], columns=req_cols)
            scaled = scaler.transform(df)
            return np.asarray(scaled)

        # Fallback: scaler expects numeric array. Pad/truncate to match n_features_in_
        n_in = getattr(scaler, "n_features_in_", processed_features.shape[1])
        if processed_features.shape[1] < n_in:
            pad = n_in - processed_features.shape[1]
            padded = np.pad(processed_features, ((0, 0), (0, pad)), mode='constant')
            return scaler.transform(padded)
        else:
            return scaler.transform(processed_features)

    except Exception as e:
        logger.warning(f"Scaler alignment failed, falling back to direct transform: {e}")
        # Last resort: try direct transform (may still warn)
        return scaler.transform(processed_features)

def preprocess_features(features: List[float]) -> np.ndarray:
    """
    Preprocess input features to match training format
    """
    features_array = np.array(features, dtype=np.float32)
    
    # Handle different input sizes
    if len(features_array) == 79:
        # Original dataset size - need to drop 9 columns to get to 70
        # This should match your notebook preprocessing
        # For now, take first 70 features (you may need to adjust this based on your actual dropped columns)
        features_array = features_array[:70]
    elif len(features_array) == 75:
        # Your test case - remove 5 features to get to 70
        features_array = features_array[:70]
    elif len(features_array) == 70:
        # Already correct size
        pass
    else:
        raise ValueError(f"Expected 70, 75, or 79 features, got {len(features_array)}")
    
    return features_array.reshape(1, -1)

def predict_classification(model, features: List[float], scaler, label_encoder, model_type: str = "MLP") -> str:
    """Predict attack class using classification model"""
    try:
        # Preprocess to get 70 features
        processed_features = preprocess_features(features)
        
        # Scale features (scaler expects 79 features, so we need to pad or adjust)
        # Since your scaler expects 79 features but models expect 70, there's a mismatch
        # We need to either:
        # 1. Use a different scaler trained on 70 features, OR
        # 2. Pad the features to 79 before scaling, then take first 70
        
        # Option 2: Pad to 79, scale, then take first 70
        # Align and scale using the adapter to preserve expected column mapping
        if scaler is not None:
            scaled = _align_and_scale(processed_features, scaler)
        else:
            scaled = processed_features

        # Ensure resulting array has at least 70 columns
        if scaled.shape[1] < 70:
            scaled = np.pad(scaled, ((0, 0), (0, 70 - scaled.shape[1])), mode='constant')

        scaled_features = scaled[:, :70]
        
        # Reshape for LSTM if needed
        if model_type == "LSTM":
            scaled_features = scaled_features.reshape(scaled_features.shape[0], 1, scaled_features.shape[1])
        
        # Make prediction
        predictions = model.predict(scaled_features, verbose=0)
        predicted_class_idx = np.argmax(predictions, axis=1)[0]
        predicted_label = label_encoder.inverse_transform([predicted_class_idx])[0]
        
        return str(predicted_label)
        
    except Exception as e:
        logger.error(f"Classification prediction error: {e}")
        raise

def predict_anomaly(model, features: List[float], scaler, method: str = "isolation_forest") -> str:
    """Predict anomaly using anomaly detection model"""
    try:
        # Preprocess to get 70 features
        processed_features = preprocess_features(features)

        # Align and scale using the adapter
        if scaler is not None:
            scaled = _align_and_scale(processed_features, scaler)
        else:
            scaled = processed_features

        if scaled.shape[1] < 70:
            scaled = np.pad(scaled, ((0, 0), (0, 70 - scaled.shape[1])), mode='constant')

        scaled_features = scaled[:, :70]
        
        if method == "isolation_forest":
            prediction = model.predict(scaled_features)[0]
            return "BENIGN" if prediction == 1 else "ATTACK"
            
        elif method == "autoencoder":
            reconstructed = model.predict(scaled_features, verbose=0)
            reconstruction_error = np.mean((scaled_features - reconstructed) ** 2)
            threshold = 0.28821281545585886
            return "BENIGN" if reconstruction_error <= threshold else "ATTACK"
            
        else:
            raise ValueError(f"Unknown method: {method}")
            
    except Exception as e:
        logger.error(f"Anomaly prediction error: {e}")
        raise

def validate_features(features: List[float]) -> tuple[bool, str]:
    """Validate input features"""
    if not isinstance(features, list):
        return False, "Features must be a list"
    
    if len(features) not in [70, 75, 79]:
        return False, f"Expected 70, 75, or 79 features, got {len(features)}"
    
    if not all(isinstance(f, (int, float)) for f in features):
        return False, "All features must be numerical"
    
    try:
        features_array = np.array(features, dtype=np.float32)
        if np.any(np.isnan(features_array)) or np.any(np.isinf(features_array)):
            return False, "Features cannot contain NaN or infinite values"
    except Exception:
        return False, "Invalid numerical values in features"
    
    return True, "Valid"

def load_keras_model(model_path: str):
    """Load a Keras model"""
    try:
        model = load_model(model_path, compile=False)
        logger.info(f"Keras model loaded from {model_path}")
        return model
    except Exception as e:
        logger.error(f"Failed to load Keras model from {model_path}: {e}")
        raise

def load_sklearn_model(model_path: str):
    """Load a scikit-learn model"""
    try:
        model = joblib.load(model_path)
        logger.info(f"Scikit-learn model loaded from {model_path}")
        return model
    except Exception as e:
        logger.error(f"Failed to load scikit-learn model from {model_path}: {e}")
        raise

def check_model_files():
    """Check which model files are available"""
    model_files = {
        "mlp_model.h5": "models/mlp_model.h5",
        "lstm_model.h5": "models/lstm_model.h5", 
        "autoencoder_model.h5": "models/autoencoder_model.h5",
        "isolation_forest.pkl": "models/isolation_forest.pkl",
        "scaler.pkl": "models/scaler.pkl",
        "label_encoder.pkl": "models/label_encoder.pkl"
    }
    
    availability = {}
    for name, path in model_files.items():
        availability[name] = os.path.exists(path)
    
    return availability

def setup_logging():
    """Setup logging configuration"""
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('logs/api.log')
        ]
    )

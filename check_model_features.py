# check_model_features.py
"""
Check the exact number of features your trained models expect
"""
import joblib
import numpy as np
from tensorflow.keras.models import load_model

def check_model_input_shapes():
    """Check input shapes of all your trained models"""
    
    try:
        # Load preprocessing objects
        scaler = joblib.load("models/scaler.pkl")
        le = joblib.load("models/label_encoder.pkl")
        
        print("=== Preprocessing Objects ===")
        print(f"Scaler expected features: {scaler.n_features_in_}")
        print(f"Label encoder classes: {list(le.classes_)}")
        print(f"Number of classes: {len(le.classes_)}")
        
    except Exception as e:
        print(f"Error loading preprocessing objects: {e}")
        return
    
    try:
        # Check Isolation Forest
        iso_forest = joblib.load("models/isolation_forest.pkl")
        print(f"\n=== Isolation Forest ===")
        print(f"Expected features: {iso_forest.n_features_in_}")
        
    except Exception as e:
        print(f"Error loading Isolation Forest: {e}")
    
    try:
        # Check Autoencoder
        autoencoder = load_model("models/autoencoder_model.h5")
        print(f"\n=== Autoencoder ===")
        print(f"Input shape: {autoencoder.input_shape}")
        print(f"Expected features: {autoencoder.input_shape[1]}")
        
    except Exception as e:
        print(f"Error loading Autoencoder: {e}")
    
    try:
        # Check MLP
        mlp = load_model("models/mlp_model.h5")
        print(f"\n=== MLP Model ===")
        print(f"Input shape: {mlp.input_shape}")
        print(f"Expected features: {mlp.input_shape[1]}")
        
    except Exception as e:
        print(f"Error loading MLP: {e}")
    
    try:
        # Check LSTM
        lstm = load_model("models/lstm_model.h5")
        print(f"\n=== LSTM Model ===")
        print(f"Input shape: {lstm.input_shape}")
        print(f"Expected features: {lstm.input_shape[2]}")  # LSTM has shape (batch, timesteps, features)
        
    except Exception as e:
        print(f"Error loading LSTM: {e}")
    
    # Load and check actual training data shapes
    try:
        print(f"\n=== Training Data Shapes ===")
        X_train_scaled = joblib.load("models/X_train_scaled.pkl")
        X_test_scaled = joblib.load("models/X_test_scaled.pkl")
        print(f"X_train_scaled shape: {X_train_scaled.shape}")
        print(f"X_test_scaled shape: {X_test_scaled.shape}")
        print(f"Actual feature count: {X_train_scaled.shape[1]}")
        
    except Exception as e:
        print(f"Error loading training data: {e}")

if __name__ == "__main__":
    check_model_input_shapes()
    
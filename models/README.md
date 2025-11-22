
# Models Directory

This directory contains all trained models and associated preprocessing objects.

## Models

- `mlp_model.h5`: Multi-Layer Perceptron (MLP) Keras model for multi-class classification.
- `lstm_model.h5`: Long Short-Term Memory (LSTM) Keras model (if available).
- `autoencoder_model.h5`: Keras autoencoder model for anomaly detection.
- `isolation_forest.pkl`: Isolation Forest scikit-learn model for anomaly detection.

## Preprocessing Objects

- `scaler.pkl`: StandardScaler used for feature scaling.
- `label_encoder.pkl`: LabelEncoder for class label conversions.

## Data

- Train/test split feature and label files (scaled and unscaled).

Please ensure these models and files are present before running the API.

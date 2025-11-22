# extract_sample_data.py
"""
Extract sample features from your trained dataset for dashboard testing
"""
import joblib
import pandas as pd
import numpy as np

def extract_sample_features():
    """Extract sample features from your dataset"""
    
    # Try to load your actual training/test data
    try:
        print("🔍 Looking for training data...")
        
        # Try different possible filenames
        possible_files = [
            "models/X_test_scaled.pkl",
            "models/X_test.pkl", 
            "models/X_train_scaled.pkl",
            "models/X_train.pkl"
        ]
        
        X_data = None
        y_data = None
        
        for file_path in possible_files:
            try:
                X_data = joblib.load(file_path)
                print(f"✅ Loaded data from: {file_path}")
                print(f"📊 Shape: {X_data.shape}")
                break
            except FileNotFoundError:
                continue
        
        # Try to load labels
        try:
            y_data = joblib.load("models/y_test.pkl")
            print(f"✅ Loaded labels: {y_data.shape}")
        except:
            try:
                y_data = joblib.load("models/y_train.pkl") 
                print(f"✅ Loaded labels: {y_data.shape}")
            except:
                print("⚠️ Could not load labels")
        
        if X_data is not None:
            print(f"\n📋 Dataset Info:")
            print(f"Features shape: {X_data.shape}")
            print(f"First sample (75 features): {X_data[0].tolist()}")
            
            if len(X_data[0]) > 70:
                print(f"First 75 features: {X_data[0][:75].tolist()}")
            
            return X_data, y_data
        else:
            print("❌ Could not find training data files")
            return None, None
            
    except Exception as e:
        print(f"❌ Error loading data: {e}")
        return None, None

def get_attack_samples(X_data, y_data):
    """Get sample features for different attack types"""
    
    if X_data is None or y_data is None:
        print("❌ No data available")
        return {}
    
    # Load label encoder to understand class mapping
    try:
        label_encoder = joblib.load("models/label_encoder.pkl")
        class_names = label_encoder.classes_
        print(f"📝 Available classes: {list(class_names)}")
    except:
        print("⚠️ Could not load label encoder")
        return {}
    
    samples = {}
    
    # Get samples for each attack type (exclude BENIGN)
    for class_idx, class_name in enumerate(class_names):
        if class_name != 'BENIGN':
            # Find samples of this class
            class_indices = np.where(y_data == class_idx)[0]
            
            if len(class_indices) > 0:
                # Get first sample of this class
                sample_idx = class_indices[0]
                sample_features = X_data[sample_idx]
                
                # Take first 75 features if more than 75
                if len(sample_features) > 75:
                    sample_features = sample_features[:75]
                
                samples[class_name] = sample_features.tolist()
                print(f"✅ {class_name}: Found {len(class_indices)} samples")
            else:
                print(f"❌ {class_name}: No samples found")
    
    return samples

if __name__ == "__main__":
    print("🚀 Extracting sample features from your dataset...\n")
    
    # Extract data
    X_data, y_data = extract_sample_features()
    
    # Get attack samples
    attack_samples = get_attack_samples(X_data, y_data)
    
    if attack_samples:
        print(f"\n📊 Generated {len(attack_samples)} attack samples:")
        
        # Print JavaScript format for easy copy-paste
        print("\n" + "="*80)
        print("📋 COPY THIS TO YOUR dashboard.js:")
        print("="*80)
        
        print("const ATTACK_SAMPLES = {")
        for attack_type, features in attack_samples.items():
            print(f"    '{attack_type}': [")
            # Print in chunks of 10 for readability
            for i in range(0, len(features), 10):
                chunk = features[i:i+10]
                chunk_str = ", ".join(f"{f:.10g}" for f in chunk)
                if i + 10 < len(features):
                    print(f"        {chunk_str},")
                else:
                    print(f"        {chunk_str}")
            print("    ],")
        print("};")
        
        print(f"\n// Your original BENIGN sample:")
        print("const BENIGN_SAMPLE = [")
        benign_sample = [
            53.0, 31471.0, 2.0, 2.0, 62.0, 446.0, 31.0, 31.0, 31.0, 0.0,
            223.0, 223.0, 223.0, 0.0, 16141.84487, 127.1011407, 10490.33333,
            18127.37031, 31422.0, 1.0, 1.0, 1.0, 0.0, 1.0, 1.0, 48.0,
            48.0, 0.0, 48.0, 48.0, 0.0, 0.0, 0.0, 0.0, 64.0, 64.0,
            63.55057037, 63.55057037, 31.0, 223.0, 107.8, 105.162731,
            11059.2, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            1.0, 134.75, 31.0, 223.0, 64.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 2.0, 62.0, 2.0, 446.0, -1.0,
            -1.0, 1.0, 32.0, 0.0, 0.0, 0.0, 0.0, 0.0
        ]
        for i in range(0, len(benign_sample), 10):
            chunk = benign_sample[i:i+10]
            chunk_str = ", ".join(f"{f:.10g}" for f in chunk)
            if i + 10 < len(benign_sample):
                print(f"    {chunk_str},")
            else:
                print(f"    {chunk_str}")
        print("];")
        
        print("="*80)
        
    else:
        print("\n❌ Could not extract attack samples")
        print("💡 Please check if your model files are in the 'models/' directory")

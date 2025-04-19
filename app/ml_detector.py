import numpy as np
from collections import deque
import os
import logging
import tensorflow as tf

logger = logging.getLogger('MLDDoSDetector')

class MLDDoSDetector:
    def __init__(self, window_size=30):
        self.data_window = deque(maxlen=window_size)
        self.scaler_params = {  # From your training data
            'min': [0, 0, 0, 0],
            'max': [1000, 1000000, 100, 100]
        }
        
        # Initialize model as None
        self.model = None
        
        # Look for model in models directory - UPDATED PATH
        model_path = os.path.join(os.path.dirname(__file__), 'models', 'ddos_model.h5')
        if os.path.exists(model_path):
            try:
                self.model = self.load_model(model_path)
                logger.info("ML model loaded successfully")
            except Exception as e:
                logger.error(f"Failed to load ML model: {e}")
        else:
            logger.warning(f"Model file {model_path} not found. Running without ML detection")

    def load_model(self, model_path):
        # Load a standard Keras model
        return tf.keras.models.load_model(model_path)

    def preprocess(self, data):
        # Normalize using min-max scaling
        features = np.array([
            data['connections'],
            data['traffic_rate'] * 1024,  # Convert back to bytes
            data['system_stats']['cpu'],
            data['system_stats']['memory']
        ])
        # Convert lists to NumPy arrays
        min_vals = np.array(self.scaler_params['min'])
        max_vals = np.array(self.scaler_params['max'])
        normalized = (features - min_vals) / (max_vals - min_vals)
        return normalized.astype(np.float32)

    def predict_anomaly(self, current_data):
        if not self.model:
            return 0.0  # Return neutral score if no model is loaded
            
        # Update sliding window
        self.data_window.append(self.preprocess(current_data))
        
        if len(self.data_window) < self.data_window.maxlen:
            return 0.0  # Not enough data
        
        # Prepare input tensor
        input_data = np.array(self.data_window, dtype=np.float32)
        input_data = input_data.reshape((1, self.data_window.maxlen, 4))
        
        # Make prediction
        output = self.model.predict(input_data, verbose=0)
        
        return float(output[0][0])
import os
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout

# Define the model - simple LSTM for anomaly detection
def create_simple_model(window_size=30, features=4):
    model = Sequential([
        LSTM(64, activation='relu', input_shape=(window_size, features), 
             return_sequences=True),
        Dropout(0.2),
        LSTM(32, activation='relu'),
        Dropout(0.2),
        Dense(16, activation='relu'),
        Dense(1, activation='sigmoid')  # Output between 0-1 (anomaly score)
    ])
    
    model.compile(optimizer='adam', loss='binary_crossentropy')
    
    # Create the models directory if it doesn't exist
    models_dir = os.path.join('app', 'models')
    os.makedirs(models_dir, exist_ok=True)
    
    # Save the model
    model_path = os.path.join(models_dir, 'ddos_model.h5')
    model.save(model_path)
    print(f"Placeholder model saved to {model_path}")

if __name__ == "__main__":
    create_simple_model()
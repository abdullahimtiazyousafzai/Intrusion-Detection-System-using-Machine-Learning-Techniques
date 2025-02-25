from flask import Flask, request, jsonify
import pandas as pd
import numpy as np
import pickle
from flask_cors import CORS  # Import CORS after Flask

# Initialize Flask app first
app = Flask(__name__)

# Enable CORS to allow cross-origin requests (important for React and Flask on different ports)
CORS(app)

# Define the RandomForest class for prediction
class RandomForest:
    def _init_(self):
        self.rfc_attack = None
        self.rfc_category = None
        self.rfc_subcategory = None

    def predict(self, X_test):
        # Predict attack
        predict_attack = self.rfc_attack.predict(X_test)

        # Use 'attack' predictions as a feature for category prediction
        test_category = np.concatenate((X_test, predict_attack.reshape(-1, 1)), axis=1)
        predict_category = self.rfc_category.predict(test_category)

        # Use 'category' predictions as a feature for subcategory prediction
        test_subcategory = np.concatenate(
            (test_category, predict_category.reshape(-1, 1)), axis=1
        )
        predict_subcategory = self.rfc_subcategory.predict(test_subcategory)

        # Return predictions as a DataFrame
        return pd.DataFrame({
            'attack': predict_attack,
            'category': predict_category,
            'subcategory': predict_subcategory,
        })

# Load the pretrained RandomForest model
try:
    with open('random_forest_model.pkl', 'rb') as f:
        rf_loaded = pickle.load(f)
    print("Model loaded successfully")
except Exception as e:
    print(f"Error loading model: {str(e)}")

# Define a route for receiving data and making predictions
@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Get JSON data from the request
        data = request.get_json()
        print(f"Received data: {data}")  # Debugging log for received data

        # Extract the input features from the request
        features = np.array([[data['seq'], data['stddev'], data['N_IN_Conn_P_SrcIP'],
                              data['min'], data['state_number'], data['mean'],
                              data['N_IN_Conn_P_DstIP'], data['drate'], data['srate'], data['max']]])

        print(f"Features extracted: {features}")  # Debugging log for features

        # Make predictions using the loaded model
        predictions = rf_loaded.predict(features)
        print(f"Prediction made: {predictions}")  # Debug log for prediction

        # Convert predictions to a dictionary for response
        response = {
            'attack': int(predictions['attack'][0]),
            'category': int(predictions['category'][0]),
            'subcategory': int(predictions['subcategory'][0]),
        }

        return jsonify(response)

    except Exception as e:
        print(f"Error occurred: {str(e)}")  # More detailed error logging
        return jsonify({'error': str(e)}), 400

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
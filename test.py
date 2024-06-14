from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
from urllib.parse import urlparse, parse_qs
import re
import datetime

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Load the model
model = joblib.load("random_forest_model.pkl")



@app.route('/api/threat-detection', methods=['POST'])
def predict_threat():
    try:
        # Get data from the request
        data = request.get_json()
        url = data['url']
        
        # Check for SQL injection threat
        if re.search(r'\b(select|union|insert|update|admin|delete|drop|truncate)\b', url, re.IGNORECASE):
            return jsonify({'prediction': 'SQL Injection Detected'})

        # Check for XSS threat
        if re.search(r'<(script|img|svg|iframe)', url, re.IGNORECASE):
            return jsonify({'prediction': 'Cross-Site Scripting (XSS) Detected'})
            
        params = parse_url_params(url)
        
        # Test the model with provided input
        prediction = test_model(model, params)
        
        if prediction == 0:  # Assuming 0 means safe and 1 means threat
            return jsonify({'prediction': 'Safe'})
        else:
            return jsonify({'prediction': 'Threat Detected'})
    except Exception as e:
        return jsonify({'error': str(e)})

user_credentials = []

def detect_threat(input_data):
    sql_injection_patterns = [
        r'\b(select|union|insert|update|delete|drop|truncate|admin)\b',
        r'(--|\bexec\b|\bexecute\b|\bshutdown\b|\bgrant\b|\bprivileges\b)'
    ]
    xss_patterns = [
        r'<(script|img|svg|iframe)',
        r'[\\"\'\(\)\[\]{}<>]'
    ]
    all_patterns = sql_injection_patterns + xss_patterns

    for pattern in all_patterns:
        if re.search(pattern, input_data, re.IGNORECASE):
            return True
    return False

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        threat_detected = detect_threat(username) or detect_threat(password)

        login_data = {
            'username': username,
            'password': password,
            'timestamp': datetime.datetime.now().isoformat(),
            'status': 'Denied - Threat Detected' if threat_detected else 'Accepted'
        }
        user_credentials.append(login_data)

        if threat_detected:
            return jsonify({'message': 'Threat detected in login credentials'}), 401

        return jsonify({'message': 'Login successful'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/user-credentials', methods=['GET'])
def get_user_credentials():
    try:
        return jsonify({'user_credentials': user_credentials}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
def parse_url_params(url):
    # Parse the URL parameters
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    return params

def test_model(model, params):
    # Prepare the features for prediction
    features = [
        float(params.get('payload_len', [0])[0]),
        float(params.get('alpha', [0])[0]),
        float(params.get('non_alpha', [0])[0]),
        float(params.get('attack_feature', [0])[0])
    ]
    # Define feature names
    feature_names = ['payload_len', 'alpha', 'non_alpha', 'attack_feature']
    # Create DataFrame with feature names
    features_df = pd.DataFrame([features], columns=feature_names)
    # Make predictions using the model
    prediction = model.predict(features_df)
    # Return the prediction result
    return prediction[0]

if __name__ == '__main__':
    app.run(debug=True, port=8080)

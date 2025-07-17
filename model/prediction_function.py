
# Prediction function for Flask backend
import joblib
import numpy as np

def load_model():
    """Load the trained model and scaler"""
    model = joblib.load('phishing_model_random_forest.pkl')
    scaler = None
    if 'None' != 'None':
        scaler = joblib.load('None')
    return model, scaler

def predict_phishing(features):
    """
    Predict if a URL is phishing or legitimate
    
    Args:
        features: List or array of 48 features extracted from URL
        
    Returns:
        prediction: 0 for legitimate, 1 for phishing
        probability: Confidence score
    """
    model, scaler = load_model()
    
    # Convert to numpy array and reshape
    features = np.array(features).reshape(1, -1)
    
    # Scale features if scaler is available
    if scaler is not None:
        features = scaler.transform(features)
    
    # Make prediction
    prediction = model.predict(features)[0]
    probability = model.predict_proba(features)[0]
    
    return {
        'prediction': int(prediction),
        'is_phishing': bool(prediction),
        'confidence': float(max(probability)),
        'probabilities': {
            'legitimate': float(probability[0]),
            'phishing': float(probability[1])
        }
    }

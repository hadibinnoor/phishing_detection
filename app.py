from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import re
import urllib.parse
import sys
import os
import numpy as np
import argparse
from urllib.parse import urlparse, parse_qs

# Add the model directory to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'model'))

# Initialize app
app = Flask(__name__)
CORS(app, origins=["*"])  # Enable CORS for all origins including Chrome extensions

# Global variables for model and scaler
model = None
scaler = None

def load_model():
    """Load the trained model"""
    global model, scaler
    try:
        model_path = os.path.join(os.path.dirname(__file__), '..', 'model', 'phishing_model_random_forest.pkl')
        model = joblib.load(model_path)
        print("Model loaded successfully!")
        return True
    except Exception as e:
        print(f"Error loading model: {e}")
        return False

def extract_features(url):
    """
    Extract 48 features from URL that match the trained model requirements
    Based on the feature set from Phishing_Legitimate_full.csv
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path
        query = parsed.query
        full_url = url.lower()
        
        features = {}
        
        # 1. NumDots - Number of dots in URL
        features['NumDots'] = url.count('.')
        
        # 2. SubdomainLevel - Number of subdomains
        if domain:
            domain_parts = domain.split('.')
            features['SubdomainLevel'] = len(domain_parts) - 2 if len(domain_parts) > 2 else 0
        else:
            features['SubdomainLevel'] = 0
            
        # 3. PathLevel - Number of path levels
        features['PathLevel'] = len([p for p in path.split('/') if p]) if path else 0
        
        # 4. UrlLength - Total URL length
        features['UrlLength'] = len(url)
        
        # 5. NumDash - Number of dashes in URL
        features['NumDash'] = url.count('-')
        
        # 6. NumDashInHostname - Number of dashes in hostname
        features['NumDashInHostname'] = domain.count('-')
        
        # 7. AtSymbol - Presence of @ symbol
        features['AtSymbol'] = 1 if '@' in url else 0
        
        # 8. TildeSymbol - Presence of ~ symbol
        features['TildeSymbol'] = 1 if '~' in url else 0
        
        # 9. NumUnderscore - Number of underscores
        features['NumUnderscore'] = url.count('_')
        
        # 10. NumPercent - Number of % symbols
        features['NumPercent'] = url.count('%')
        
        # 11. NumQueryComponents - Number of query components
        if query:
            features['NumQueryComponents'] = len(parse_qs(query))
        else:
            features['NumQueryComponents'] = 0
            
        # 12. NumAmpersand - Number of & symbols
        features['NumAmpersand'] = url.count('&')
        
        # 13. NumHash - Number of # symbols
        features['NumHash'] = url.count('#')
        
        # 14. NumNumericChars - Number of numeric characters
        features['NumNumericChars'] = sum(c.isdigit() for c in url)
        
        # 15. NoHttps - Not using HTTPS
        features['NoHttps'] = 1 if parsed.scheme != 'https' else 0
        
        # 16. RandomString - Contains random-like strings
        random_patterns = [r'[a-z]{8,}[0-9]{3,}', r'[0-9]{4,}[a-z]{4,}']
        features['RandomString'] = 1 if any(re.search(pattern, full_url) for pattern in random_patterns) else 0
        
        # 17. IpAddress - Contains IP address
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        features['IpAddress'] = 1 if re.search(ip_pattern, domain) else 0
        
        # 18. DomainInSubdomains - Domain name in subdomains
        if domain and '.' in domain:
            domain_parts = domain.split('.')
            main_domain = '.'.join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain
            subdomain_part = '.'.join(domain_parts[:-2]) if len(domain_parts) > 2 else ''
            features['DomainInSubdomains'] = 1 if main_domain in subdomain_part else 0
        else:
            features['DomainInSubdomains'] = 0
            
        # 19. DomainInPaths - Domain name in paths
        features['DomainInPaths'] = 1 if domain and domain.replace('.', '') in path.replace('/', '') else 0
        
        # 20. HttpsInHostname - 'https' string in hostname
        features['HttpsInHostname'] = 1 if 'https' in domain else 0
        
        # 21. HostnameLength - Length of hostname
        features['HostnameLength'] = len(domain)
        
        # 22. PathLength - Length of path
        features['PathLength'] = len(path)
        
        # 23. QueryLength - Length of query
        features['QueryLength'] = len(query)
        
        # 24. DoubleSlashInPath - Double slash in path
        features['DoubleSlashInPath'] = 1 if '//' in path else 0
        
        # 25. NumSensitiveWords - Number of sensitive words
        sensitive_words = ['secure', 'account', 'webscr', 'login', 'ebayisapi', 'signin', 'banking', 'confirm']
        features['NumSensitiveWords'] = sum(1 for word in sensitive_words if word in full_url)
        
        # 26-48: Advanced features (simplified implementations)
        # These would typically require webpage content analysis, but we'll provide reasonable defaults
        
        # 26. EmbeddedBrandName - Contains known brand names
        brand_names = ['paypal', 'ebay', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'twitter']
        features['EmbeddedBrandName'] = sum(1 for brand in brand_names if brand in full_url)
        
        # 27-48: Additional features with default values based on URL structure
        features['PctExtHyperlinks'] = 0  # Would need HTML analysis
        features['PctExtResourceUrls'] = 0  # Would need HTML analysis
        features['ExtFavicon'] = 0  # Would need HTML analysis
        features['InsecureForms'] = 0  # Would need HTML analysis
        features['RelativeFormAction'] = 0  # Would need HTML analysis
        features['ExtFormAction'] = 0  # Would need HTML analysis
        features['AbnormalFormAction'] = 0  # Would need HTML analysis
        features['PctNullSelfRedirectHyperlinks'] = 0  # Would need HTML analysis
        features['FrequentDomainNameMismatch'] = 0  # Would need HTML analysis
        features['FakeLinkInStatusBar'] = 0  # Would need HTML analysis
        features['RightClickDisabled'] = 0  # Would need HTML analysis
        features['PopUpWindow'] = 0  # Would need HTML analysis
        features['SubmitInfoToEmail'] = 0  # Would need HTML analysis
        features['IframeOrFrame'] = 0  # Would need HTML analysis
        features['MissingTitle'] = 0  # Would need HTML analysis
        features['ImagesOnlyInForm'] = 0  # Would need HTML analysis
        
        # Runtime features (simplified)
        features['SubdomainLevelRT'] = features['SubdomainLevel']
        features['UrlLengthRT'] = 1 if features['UrlLength'] > 100 else 0
        features['PctExtResourceUrlsRT'] = 0
        features['AbnormalExtFormActionR'] = 0
        features['ExtMetaScriptLinkRT'] = 0
        features['PctExtNullSelfRedirectHyperlinksRT'] = 0
        
        # Convert to list in the correct order (first 48 features)
        feature_names = [
            'NumDots', 'SubdomainLevel', 'PathLevel', 'UrlLength', 'NumDash', 'NumDashInHostname',
            'AtSymbol', 'TildeSymbol', 'NumUnderscore', 'NumPercent', 'NumQueryComponents',
            'NumAmpersand', 'NumHash', 'NumNumericChars', 'NoHttps', 'RandomString', 'IpAddress',
            'DomainInSubdomains', 'DomainInPaths', 'HttpsInHostname', 'HostnameLength', 'PathLength',
            'QueryLength', 'DoubleSlashInPath', 'NumSensitiveWords', 'EmbeddedBrandName',
            'PctExtHyperlinks', 'PctExtResourceUrls', 'ExtFavicon', 'InsecureForms', 'RelativeFormAction',
            'ExtFormAction', 'AbnormalFormAction', 'PctNullSelfRedirectHyperlinks',
            'FrequentDomainNameMismatch', 'FakeLinkInStatusBar', 'RightClickDisabled', 'PopUpWindow',
            'SubmitInfoToEmail', 'IframeOrFrame', 'MissingTitle', 'ImagesOnlyInForm', 'SubdomainLevelRT',
            'UrlLengthRT', 'PctExtResourceUrlsRT', 'AbnormalExtFormActionR', 'ExtMetaScriptLinkRT',
            'PctExtNullSelfRedirectHyperlinksRT'
        ]
        
        feature_vector = [features.get(name, 0) for name in feature_names]
        return feature_vector, features
        
    except Exception as e:
        print(f"Error extracting features: {e}")
        # Return default feature vector if extraction fails
        return [0] * 48, {}

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "Phishing URL Detection API is running",
        "endpoints": {
            "/predict": "POST - Predict if a URL is phishing or legitimate",
            "/health": "GET - Check API health status"
        },
        "model_status": "loaded" if model is not None else "not_loaded"
    })

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy" if model is not None else "unhealthy",
        "model_loaded": model is not None,
        "message": "API is running correctly" if model is not None else "Model not loaded"
    })

@app.route("/predict", methods=["POST"])
def predict():
    try:
        if model is None:
            return jsonify({"error": "Model not loaded"}), 500
            
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
            
        url = data.get("url")
        if not url:
            return jsonify({"error": "No URL provided"}), 400

        # Extract features
        feature_vector, feature_details = extract_features(url)
        
        # Make prediction
        features_array = np.array(feature_vector).reshape(1, -1)
        prediction = model.predict(features_array)[0]
        probabilities = model.predict_proba(features_array)[0]
        
        # Prepare response
        response = {
            "url": url,
            "prediction": "phishing" if prediction == 1 else "legitimate",
            "is_phishing": bool(prediction),
            "confidence": float(max(probabilities)),
            "probabilities": {
                "legitimate": float(probabilities[0]),
                "phishing": float(probabilities[1])
            },
            "risk_level": "high" if max(probabilities) > 0.8 else "medium" if max(probabilities) > 0.6 else "low",
            "key_features": {
                "url_length": feature_details.get('UrlLength', 0),
                "has_https": not feature_details.get('NoHttps', 1),
                "has_ip_address": bool(feature_details.get('IpAddress', 0)),
                "suspicious_symbols": feature_details.get('AtSymbol', 0) + feature_details.get('TildeSymbol', 0),
                "sensitive_words": feature_details.get('NumSensitiveWords', 0)
            }
        }

        return jsonify(response), 200

    except Exception as e:
        return jsonify({"error": f"Prediction failed: {str(e)}"}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Phishing Detection API')
    parser.add_argument('--port', '-p', type=int, default=5001, 
                        help='Port to run the server on (default: 5001)')
    parser.add_argument('--host', type=str, default='0.0.0.0', 
                        help='Host to run the server on (default: 0.0.0.0)')
    parser.add_argument('--debug', action='store_true', default=True,
                        help='Run in debug mode (default: True)')
    args = parser.parse_args()
    
    # Load model on startup
    if load_model():
        print(f"Starting Flask app with loaded model on {args.host}:{args.port}...")
        # Use port from command line args or default to 5001
        app.run(debug=args.debug, host=args.host, port=args.port)
    else:
        print("Failed to load model. Exiting.")
        sys.exit(1) 
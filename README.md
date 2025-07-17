# Phishing URL Detection API

A Flask-based web API that detects phishing URLs using a pre-trained machine learning model. The API extracts 48 features from URLs and uses a Random Forest classifier to determine if a URL is legitimate or phishing.

## Features

- 🔍 **Real-time URL Analysis**: Instantly analyze URLs for phishing indicators
- 🤖 **Machine Learning**: Uses a trained Random Forest model with 48 feature extraction
- 🌐 **CORS Enabled**: Ready for Chrome extension integration
- 📊 **Detailed Results**: Provides confidence scores, risk levels, and feature analysis
- 🛡️ **Error Handling**: Robust error handling and validation
- 🚀 **Easy Deployment**: Simple Flask app with minimal dependencies

## Installation

### Prerequisites

- Python 3.8 or higher
- Virtual environment (recommended)

### Setup

1. **Clone or navigate to the backend directory**:
   ```bash
   cd /path/to/your/phishing_detection/backend
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python -m venv venv
   
   # On macOS/Linux:
   source venv/bin/activate
   
   # On Windows:
   venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Verify the model file exists**:
   Make sure `../model/phishing_model_random_forest.pkl` exists in the parent model directory.

## Usage

### Starting the API

#### Quick Start (Recommended)

```bash
# Using the start script (easiest method)
./start_api.sh

# Or with a custom port
./start_api.sh 8080
```

#### Manual Start

```bash
# Activate virtual environment and start
source venv/bin/activate
python app.py
```

The API will start on `http://localhost:5001` with debug mode enabled.

**Note**: Port 5000 is often used by macOS AirPlay Receiver. If you need to use a different port, you can use the following methods:

#### Running on Custom Ports

**Method 1: Modify app.py directly**
Edit the last line in `app.py`:
```python
app.run(debug=True, host='0.0.0.0', port=YOUR_PORT_NUMBER)
```

**Method 2: Using Flask CLI**
```bash
export FLASK_APP=app.py
export FLASK_DEBUG=1
flask run --host=0.0.0.0 --port=5002
```

**Method 3: Using Python with command line arguments**
```bash
# Run on a specific port
python app.py --port 5002

# Run on a specific host and port
python app.py --host 127.0.0.1 --port 8080

# Show help for all options
python app.py --help
```

### API Endpoints

#### 1. Health Check
```http
GET /health
```

**Response**:
```json
{
  "status": "healthy",
  "model_loaded": true,
  "message": "API is running correctly"
}
```

#### 2. Root Endpoint
```http
GET /
```

**Response**:
```json
{
  "message": "Phishing URL Detection API is running",
  "endpoints": {
    "/predict": "POST - Predict if a URL is phishing or legitimate",
    "/health": "GET - Check API health status"
  },
  "model_status": "loaded"
}
```

#### 3. URL Prediction
```http
POST /predict
Content-Type: application/json

{
  "url": "https://example.com"
}
```

**Response**:
```json
{
  "url": "https://example.com",
  "prediction": "legitimate",
  "is_phishing": false,
  "confidence": 0.85,
  "probabilities": {
    "legitimate": 0.85,
    "phishing": 0.15
  },
  "risk_level": "low",
  "key_features": {
    "url_length": 19,
    "has_https": true,
    "has_ip_address": false,
    "suspicious_symbols": 0,
    "sensitive_words": 0
  }
}
```

### Testing the API

Run the included test script to verify everything works:

```bash
python test_api.py
```

The test script will:
- Check API health
- Test 10 sample URLs (mix of legitimate and suspicious)
- Allow you to test custom URLs interactively

### Example Usage with curl

```bash
# Test a legitimate URL
curl -X POST http://localhost:5001/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.google.com"}'

# Test a suspicious URL
curl -X POST http://localhost:5001/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal-security-update.com.suspicious-domain.tk"}'
```

### Example Usage with Python

```python
import requests

# Make a prediction
response = requests.post(
    'http://localhost:5001/predict',
    json={'url': 'https://example.com'},
    headers={'Content-Type': 'application/json'}
)

result = response.json()
print(f"Prediction: {result['prediction']}")
print(f"Confidence: {result['confidence']:.3f}")
```

## Chrome Extension Integration

The API is configured with CORS enabled for all origins, making it ready for Chrome extension use:

```javascript
// Example Chrome extension code
fetch('http://localhost:5001/predict', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    url: currentTabUrl
  })
})
.then(response => response.json())
.then(data => {
  console.log('Prediction:', data.prediction);
  console.log('Confidence:', data.confidence);
});
```

## Feature Extraction

The API extracts 48 features from each URL, including:

### URL Structure Features (1-25)
- Number of dots, dashes, subdomains
- URL and path length
- Presence of suspicious symbols (@, ~, %)
- HTTPS usage
- IP address detection
- Sensitive word counting

### Advanced Features (26-48)
- Brand name embedding detection
- Security indicator analysis
- Domain structure analysis

## Model Information

- **Algorithm**: Random Forest Classifier
- **Features**: 48 engineered features
- **Training Data**: Phishing and legitimate URL dataset
- **Model File**: `phishing_model_random_forest.pkl`

## Error Handling

The API includes comprehensive error handling:

- **400 Bad Request**: Missing URL or invalid JSON
- **404 Not Found**: Invalid endpoint
- **500 Internal Server Error**: Model loading issues or prediction failures

## Development

### Project Structure
```
backend/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── test_api.py           # API testing script
├── README.md             # This file
└── venv/                 # Virtual environment

../model/
├── phishing_model_random_forest.pkl  # Trained model
├── prediction_function.py            # Model utilities
└── train_model.py                    # Training script
```

### Adding New Features

To add new URL features:

1. Modify the `extract_features()` function in `app.py`
2. Ensure the feature vector maintains 48 elements
3. Update the feature names list to match
4. Retrain the model if necessary

## Troubleshooting

### Common Issues

1. **Model not loading**:
   - Verify `../model/phishing_model_random_forest.pkl` exists
   - Check file permissions
   - Ensure scikit-learn version compatibility

2. **Connection refused**:
   - Make sure the Flask app is running
   - Check if port 5000 is available
   - Try a different port: `app.run(port=5001)`

3. **Import errors**:
   - Activate virtual environment
   - Install requirements: `pip install -r requirements.txt`
   - Check Python version (3.8+ required)

### Debug Mode

The API runs in debug mode by default. For production, disable it:

```python
app.run(debug=False, host='0.0.0.0', port=5000)
```

## License

This project is for educational and research purposes.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

---

🔒 **Security Note**: This API is designed for research and educational purposes. For production use, implement proper authentication, rate limiting, and security measures. 
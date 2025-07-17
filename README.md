# Phishing URL Detection API

A Flask-based web API that detects phishing URLs using a pre-trained machine learning model. The API extracts 48 features from URLs and uses a Random Forest classifier to determine if a URL is legitimate or phishing.

## Features

- 🔍 **Real-time URL Analysis** with 97.9% accuracy
- 🤖 **Machine Learning** powered by Random Forest classifier
- 🌐 **CORS Enabled** for Chrome extension integration
- 📊 **Detailed Results** with confidence scores and risk levels

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
   Make sure `model/phishing_model_random_forest.pkl` exists in the model directory.

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

#### Custom Ports

```bash
# Using command line arguments
python app.py --port 8080

# Show all options
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

The test script will check API health and test sample URLs with different risk levels.

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

The API extracts 48 features from each URL:
- URL structure (dots, dashes, subdomains, length)
- Security indicators (HTTPS, IP addresses, suspicious symbols)
- Content analysis (sensitive words, brand names)
- Domain and path characteristics

## Model Performance

- **Algorithm**: Random Forest Classifier
- **Accuracy**: 97.9%
- **Features**: 48 engineered URL features
- **Model File**: `phishing_model_random_forest.pkl`

### Classification Metrics
| Class | Precision | Recall | F1-Score | Support |
|-------|-----------|---------|----------|---------|
| Legitimate (0) | 0.97 | 0.98 | 0.98 | 1000 |
| Phishing (1) | 0.98 | 0.97 | 0.98 | 1000 |
| **Overall** | **0.98** | **0.98** | **0.98** | **2000** |

## Error Handling

The API includes comprehensive error handling:

- **400 Bad Request**: Missing URL or invalid JSON
- **404 Not Found**: Invalid endpoint
- **500 Internal Server Error**: Model loading issues or prediction failures

## Project Structure
```
backend/
├── app.py                            # Main Flask application
├── requirements.txt                  # Dependencies
├── venv/                            # Virtual environment
└── model/                           # Model directory
    ├── phishing_model_random_forest.pkl  # Trained model
    ├── train_model.py                     # Training script
    └── prediction_function.py            # Model utilities
```

## Troubleshooting

- **Model not loading**: Ensure `model/phishing_model_random_forest.pkl` exists
- **Port conflicts**: Use `python app.py --port 8080` for different port
- **Import errors**: Activate virtual environment and install requirements

---

🔒 **Note**: This API is for research and educational purposes. 
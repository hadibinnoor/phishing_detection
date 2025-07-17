#!/bin/bash

# Phishing Detection API Startup Script

echo "🚀 Starting Phishing Detection API..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Please run setup first:"
    echo "   python -m venv venv"
    echo "   source venv/bin/activate"
    echo "   pip install -r requirements.txt"
    exit 1
fi

# Activate virtual environment
echo "📦 Activating virtual environment..."
source venv/bin/activate

# Check if model exists
if [ ! -f "../model/phishing_model_random_forest.pkl" ]; then
    echo "❌ Model file not found at ../model/phishing_model_random_forest.pkl"
    echo "   Please ensure the model file exists in the correct location."
    exit 1
fi

# Default port
PORT=${1:-5001}

echo "🔍 Starting API on port $PORT..."
echo "📡 API will be available at: http://localhost:$PORT"
echo "🏥 Health check: http://localhost:$PORT/health"
echo "🔧 Prediction endpoint: http://localhost:$PORT/predict"
echo ""
echo "Press Ctrl+C to stop the server"
echo "=================================="

# Start the Flask application
python app.py --port $PORT 
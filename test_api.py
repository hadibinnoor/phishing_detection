#!/usr/bin/env python3
"""
Simple test script for the Phishing Detection API
"""

import requests
import json

# API endpoint
API_URL = "http://localhost:5001"

def test_api():
    """Test the phishing detection API with sample URLs"""
    
    test_urls = [
        "https://www.google.com",
        "https://github.com/user/repo", 
        "http://paypal-security-update.com.suspicious-domain.tk",
        "https://secure-bank-login@malicious-site.com"
    ]
    
    print("🔍 Testing Phishing Detection API")
    print("=" * 50)
    
    # Test health endpoint
    try:
        health_response = requests.get(f"{API_URL}/health")
        if health_response.status_code == 200:
            print("✅ API Health Check: PASSED")
        else:
            print("❌ API Health Check: FAILED")
            return
    except requests.exceptions.ConnectionError:
        print("❌ Connection Error: Make sure the API is running on localhost:5001")
        return
    
    print("\n🧪 Testing URL Predictions:")
    print("-" * 50)
    
    for i, url in enumerate(test_urls, 1):
        try:
            payload = {"url": url}
            response = requests.post(
                f"{API_URL}/predict", 
                json=payload,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                result = response.json()
                prediction = result['prediction'].upper()
                confidence = result['confidence']
                
                if result['is_phishing']:
                    status_icon = "🚨"
                    status_color = f"\033[91m{prediction}\033[0m"  # Red
                else:
                    status_icon = "✅"
                    status_color = f"\033[92m{prediction}\033[0m"  # Green
                
                print(f"\n{i:2d}. {url}")
                print(f"    {status_icon} Prediction: {status_color}")
                print(f"    📊 Confidence: {confidence:.3f}")
                
            else:
                print(f"\n{i:2d}. {url}")
                print(f"    ❌ Error: {response.status_code}")
                
        except Exception as e:
            print(f"\n{i:2d}. {url}")
            print(f"    ❌ Exception: {str(e)}")
    
    print("\n" + "=" * 50)
    print("🎉 API Testing Complete!")

if __name__ == "__main__":
    test_api() 
#!/usr/bin/env python3
"""
Test script for the Phishing Detection API
"""

import requests
import json

# API endpoint
API_URL = "http://localhost:5001"

def test_api():
    """Test the phishing detection API with sample URLs"""
    
    # Test URLs - mix of legitimate and potentially phishing
    test_urls = [
        "https://www.google.com",
        "https://github.com/user/repo",
        "http://paypal-security-update.com.suspicious-domain.tk",
        "https://127.0.0.1:8080/login",
        "https://amazon.com/login",
        "http://bit.ly/malicious-link",
        "https://secure-bank-login@malicious-site.com",
        "https://www.microsoft.com/downloads",
        "http://paypal.verification.account-suspended.tk/login",
        "https://stackoverflow.com/questions/python",
        "fl1pkart.c0m"
    ]
    
    print("🔍 Testing Phishing Detection API")
    print("=" * 50)
    
    # Test health endpoint
    try:
        health_response = requests.get(f"{API_URL}/health")
        if health_response.status_code == 200:
            print("✅ API Health Check: PASSED")
            print(f"   Status: {health_response.json()}")
        else:
            print("❌ API Health Check: FAILED")
            return
    except requests.exceptions.ConnectionError:
        print("❌ Connection Error: Make sure the API is running on localhost:5000")
        return
    
    print("\n🧪 Testing URL Predictions:")
    print("-" * 50)
    
    for i, url in enumerate(test_urls, 1):
        try:
            # Make prediction request
            payload = {"url": url}
            response = requests.post(
                f"{API_URL}/predict", 
                json=payload,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                result = response.json()
                
                # Display results
                prediction = result['prediction'].upper()
                confidence = result['confidence']
                risk_level = result['risk_level'].upper()
                
                # Color coding for terminal output
                if result['is_phishing']:
                    status_icon = "🚨" if confidence > 0.8 else "⚠️"
                    status_color = f"\033[91m{prediction}\033[0m"  # Red
                else:
                    status_icon = "✅"
                    status_color = f"\033[92m{prediction}\033[0m"  # Green
                
                print(f"\n{i:2d}. {url}")
                print(f"    {status_icon} Prediction: {status_color}")
                print(f"    📊 Confidence: {confidence:.3f} | Risk: {risk_level}")
                print(f"    🔧 Key Features:")
                print(f"        URL Length: {result['key_features']['url_length']}")
                print(f"        HTTPS: {result['key_features']['has_https']}")
                print(f"        IP Address: {result['key_features']['has_ip_address']}")
                print(f"        Suspicious Symbols: {result['key_features']['suspicious_symbols']}")
                print(f"        Sensitive Words: {result['key_features']['sensitive_words']}")
                
            else:
                print(f"\n{i:2d}. {url}")
                print(f"    ❌ Error: {response.status_code} - {response.text}")
                
        except Exception as e:
            print(f"\n{i:2d}. {url}")
            print(f"    ❌ Exception: {str(e)}")
    
    print("\n" + "=" * 50)
    print("🎉 API Testing Complete!")

def test_custom_url():
    """Test with a custom URL input"""
    print("\n🔧 Custom URL Testing")
    print("-" * 30)
    
    while True:
        url = input("\nEnter a URL to test (or 'quit' to exit): ").strip()
        
        if url.lower() in ['quit', 'exit', 'q']:
            break
            
        if not url:
            print("Please enter a valid URL")
            continue
            
        try:
            payload = {"url": url}
            response = requests.post(
                f"{API_URL}/predict", 
                json=payload,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"\n📊 Analysis Results:")
                print(f"URL: {result['url']}")
                print(f"Prediction: {result['prediction'].upper()}")
                print(f"Confidence: {result['confidence']:.3f}")
                print(f"Risk Level: {result['risk_level'].upper()}")
                print(f"Probabilities: Legitimate={result['probabilities']['legitimate']:.3f}, Phishing={result['probabilities']['phishing']:.3f}")
            else:
                print(f"❌ Error: {response.status_code} - {response.text}")
                
        except requests.exceptions.ConnectionError:
            print("❌ Connection Error: Make sure the API is running")
            break
        except Exception as e:
            print(f"❌ Exception: {str(e)}")

if __name__ == "__main__":
    # Run automatic tests
    test_api()
    
    # Ask if user wants to test custom URLs
    while True:
        choice = input("\nDo you want to test custom URLs? (y/n): ").strip().lower()
        if choice in ['y', 'yes']:
            test_custom_url()
            break
        elif choice in ['n', 'no']:
            print("Thanks for testing! 🚀")
            break
        else:
            print("Please enter 'y' or 'n'") 
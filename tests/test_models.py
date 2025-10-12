import sys
import os

# Add the parent directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

from src.model_integration import EnsembleDetector, detect_phishing_url, detect_phishing_email
from src.url_analyzer import URLAnalyzer
from src.email_analyzer import EmailAnalyzer

def test_model_integration():
    """Test the complete model integration pipeline."""
    print("🧪 TESTING MODEL INTEGRATION")
    print("=" * 50)
    
    # Initialize analyzers
    url_analyzer = URLAnalyzer()
    email_analyzer = EmailAnalyzer()
    detector = EnsembleDetector()
    
    # Test URLs with expected outcomes
    test_cases = [
        # (input, type, expected_phishing)
        ("https://www.google.com", "url", False),
        ("http://192.168.1.1/secure.login.verify", "url", True),
        ("https://paypal-account-security.com", "url", True),
        ("security@paypal.com", "email", False),
        ("noreply@amazon-verification.net", "email", True),  
        ("support@microsoft-update.com", "email", True),     
    ]
    
    print("\n🔍 Running Test Cases...")
    for i, (test_input, input_type, expected_high_risk) in enumerate(test_cases, 1):
        print(f"\n{i}. Testing {input_type.upper()}: {test_input}")
        
        if input_type == "url":
            result = detect_phishing_url(test_input, url_analyzer)
        else:
            result = detect_phishing_email(test_input, email_analyzer)
        
        # Display results
        print(f"   Result: {'PHISHING' if result['is_phishing'] else 'SAFE'}")
        print(f"   Confidence: {result['confidence']:.2f}")
        print(f"   Risk Level: {result['risk_level']}")
        print(f"   Explanation: {result['explanation'].split('.')[0]}...")
        
        # Check if result matches expectation
        actual_high_risk = result['is_phishing'] 
        status = "✅ PASS" if actual_high_risk == expected_high_risk else "❌ FAIL"
        print(f"   Test: {status}")
    
    print("\n" + "=" * 50)
    print("📊 Testing Individual Classifiers...")
    
    # Test individual classifier components
    test_url = "https://suspicious-site.xyz/login"
    features = url_analyzer.extract_features(test_url)
    
    print(f"\nTesting URL: {test_url}")
    print("Extracted features:")
    for key, value in features.items():
        if value != 0:  # Only show non-zero features
            print(f"  {key}: {value}")
    
    # Test ensemble detector
    result = detector.analyze_url(features)
    print(f"\nEnsemble Result:")
    print(f"  Phishing: {result['is_phishing']}")
    print(f"  Confidence: {result['confidence']:.2f}")
    print(f"  Rule-based: {result['rule_based_result']} (conf: {result['rule_based_confidence']:.2f})")
    print(f"  ML Model: {result['ml_result']} (conf: {result['ml_confidence']:.2f})")
    
    print("\n🎉 MODEL INTEGRATION TEST COMPLETED!")

if __name__ == "__main__":
    test_model_integration()
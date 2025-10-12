import sys
import os

# Add the parent directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

from src.email_analyzer import EmailAnalyzer

def test_email_analyzer():
    analyzer = EmailAnalyzer()
    
    # Test email addresses
    test_emails = [
        "security@paypal.com",
        "support@paypal-security.net", 
        "noreply@amazon-verification.com"
    ]
    
    for email_addr in test_emails:
        print(f"\nTesting email: {email_addr}")
        features = analyzer.extract_features(email_addr)
        print(f"Extracted {len(features)} features")
        # Show key features
        key_features = {
            'suspicious_sender': features.get('suspicious_sender'),
            'phishing_score': features.get('phishing_score'),
            'phishing_confidence': features.get('phishing_confidence')
        }
        for key, value in key_features.items():
            print(f"  {key}: {value}")

if __name__ == "__main__":
    test_email_analyzer()
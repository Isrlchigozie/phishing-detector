import sys
import os

# Add the parent directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

from src.url_analyzer import URLAnalyzer

def test_url_analyzer():
    analyzer = URLAnalyzer()
    
    test_urls = [
        "https://www.google.com",
        "https://www.paypal.com.login.secure.verify-account.com",
        "http://192.168.1.1/login",
        "https://amazon-security-verification.com"
    ]
    
    for url in test_urls:
        print(f"\nTesting URL: {url}")
        features = analyzer.extract_features(url)
        print(f"Extracted {len(features)} features")
        # Show only the most important features
        important_features = {
            'url_length': features.get('url_length'),
            'has_https': features.get('has_https'),
            'has_ip': features.get('has_ip'),
            'suspicious_tld': features.get('suspicious_tld'),
            'domain_age_days': features.get('domain_age_days'),
            'suspicious_keywords': features.get('suspicious_keywords')
        }
        for key, value in important_features.items():
            print(f"  {key}: {value}")

if __name__ == "__main__":
    test_url_analyzer()
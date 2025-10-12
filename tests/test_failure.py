import sys
import os

# Add the parent directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

from src.model_integration import detect_phishing_url
from src.url_analyzer import URLAnalyzer

def test_failure_case():
    """Test what happens when we expect the wrong result"""
    url_analyzer = URLAnalyzer()
    
    # This should be SAFE, but let's say we expect PHISHING (wrong expectation)
    test_url = "https://www.google.com"
    expected_phishing = True  # This is WRONG - google should be safe
    
    print("🧪 Testing Failure Case")
    print("=" * 40)
    print(f"Testing: {test_url}")
    print(f"Wrong Expectation: PHISHING (but should be SAFE)")
    
    result = detect_phishing_url(test_url, url_analyzer)
    actual_phishing = result['is_phishing']
    
    status = "✅ PASS" if actual_phishing == expected_phishing else "❌ FAIL"
    
    print(f"Actual Result: {'PHISHING' if actual_phishing else 'SAFE'}")
    print(f"Test Status: {status}")
    print(f"Explanation: {result['explanation']}")

if __name__ == "__main__":
    test_failure_case()
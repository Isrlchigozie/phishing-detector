import sys
import os

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

print("Python path updated successfully!")
print("Current working directory:", os.getcwd())
print("Python path:", sys.path)

# Now try to import
try:
    from src.url_analyzer import URLAnalyzer
    from src.email_analyzer import EmailAnalyzer
    print("✅ All imports successful!")
    
    # Test the analyzers
    print("\n--- Testing URL Analyzer ---")
    url_analyzer = URLAnalyzer()
    features = url_analyzer.extract_features("https://www.google.com")
    print("URL features extracted:", len(features))
    
    print("\n--- Testing Email Analyzer ---")
    email_analyzer = EmailAnalyzer()
    features = email_analyzer.extract_features("test@example.com")
    print("Email features extracted:", len(features))
    
except ImportError as e:
    print("❌ Import failed:", e)
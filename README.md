# Phishing Detector - AI-Powered Security System

A real-time web application that detects phishing URLs and emails using ensemble AI methods. Achieves **88.2% accuracy** with zero false positives.

![Phishing Detector](https://img.shields.io/badge/Accuracy-88.2%25-brightgreen)
![Python](https://img.shields.io/badge/Python-3.11-blue)
![Flask](https://img.shields.io/badge/Flask-2.3.3-lightgrey)

##  Live Demo

**Access the live application:** [https://isrlchiigozie.pythonanywhere.com/](https://isrlchiigozie.pythonanywhere.com/)

##  Performance Metrics

- **Overall Accuracy**: 88.2%
- **URL Detection**: 100% Perfect
- **Email Detection**: 77.8%
- **Precision**: 100% (No False Positives)
- **Recall**: 81.8%
- **F1-Score**: 90.0%

##  Features

- 🔗 **URL Analysis**: Detects malicious websites in real-time
-  **Email Analysis**: Identifies phishing emails and content
-  **AI-Powered**: Ensemble learning with rule-based + ML approaches
-  **Beautiful UI**: Modern, responsive web interface
-  **Real-time Results**: Analysis completed in under 2 seconds
-  **Explainable AI**: Clear reasons for each detection decision
-  **Prevention Advice**: Actionable security recommendations

## System Architecture



User Input → Feature Extraction → AI Analysis → Results Display
↓              ↓               ↓              ↓
URL/Email    27+ Features    Ensemble Model  Color-coded Risk
(Rule-based + ML)  + Explanations



## Technology Stack

- **Backend**: Python, Flask, NumPy
- **AI/ML**: Ensemble Learning, Feature Engineering
- **Frontend**: HTML5, CSS3, JavaScript
- **Styling**: Modern CSS with gradients & animations
- **Icons**: Font Awesome
- **Deployment**: pythonanywhere
- **Development**: VS Code

## Quick Start

### Test the Live Application

1. Visit: [https://isrlchiigozie.pythonanywhere.com/](https://isrlchiigozie.pythonanywhere.com/)
2. **Test URLs**:
   - Safe: `https://www.google.com`
   - Phishing: `https://paypal-verify-account.com`
3. **Test Emails**:
   - Safe: `security@paypal.com`
   - Phishing: `support@paypal-security.net`

### Local Development

# 1. Clone repository
git clone https://github.com/isrlchigozie/phishing-detector.git
cd phishing-detector

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run application
python app.py

# 4. Access at: http://localhost:5000


📁 Project Structure


phishing-detector/
├── app.py                 # Main Flask application
├── wsgi.py              # WSGI entry point
├── requirements.txt      # Python dependencies
├── src/                  # Core detection engine
│   ├── url_analyzer.py    # URL feature extraction (15+ features)
│   ├── email_analyzer.py  # Email analysis (12+ features)
│   ├── model_integration.py # AI ensemble detection
│   └── utils.py           # Helper functions
├── templates/            # Web interface
│   └── index.html         # Main UI with modern design
└── tests/                # Comprehensive test suite
    └── comprehensive_evaluation.py


 How It Works

Feature Extraction

· URL Analysis: 15+ features including domain age, HTTPS, IP addresses, suspicious TLDs
· Email Analysis: 12+ features including sender verification, urgent language, grammar analysis

AI Detection

· Ensemble Approach: Combines rule-based scoring with simulated ML models
· Weighted Voting: 60% rule-based + 40% ML for optimal accuracy
· Confidence Scoring: Risk levels from VERY LOW to HIGH

Prevention System

· Color-coded risk assessment
· Detailed explanation for each detection
· Actionable security recommendations
· Export functionality for reports

pTesting & Evaluation

Comprehensive testing with 17 carefully curated test cases:

· 8 URL test cases (4 legitimate, 4 phishing) - 100% accuracy
· 9 Email test cases (3 legitimate, 6 phishing) - 77.8% accuracy
· Real-world examples including actual scam emails


📄 License

MT

Built with ❤️ by Li, using Python, Flask, and modern web technologies.
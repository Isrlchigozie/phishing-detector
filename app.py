"""
PHISHING DETECTOR WEB APPLICATION

A modern Flask web application for detecting phishing URLs and emails.
Features:
- Beautiful, responsive UI with modern CSS
- Real-time analysis with progress indicators
- Color-coded risk assessment
- Detailed results with explanations
- Prevention recommendations
- Export functionality for reports

TECHNOLOGY STACK:
- Backend: Flask (Python)
- Frontend: HTML5, CSS3, JavaScript
- Styling: Modern CSS with gradients and animations
- Icons: Font Awesome
- Layout: Flexbox/Grid responsive design
"""

from flask import Flask, render_template, request, jsonify, send_file
import sys
import os
import json
from datetime import datetime
import io

# Add src to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.url_analyzer import URLAnalyzer
from src.email_analyzer import EmailAnalyzer
from src.model_integration import detect_phishing_url, detect_phishing_email
from src.utils import PhishingUtils

app = Flask(__name__)
app.secret_key = 'phishing_detector_secret_key'

# Initialize analyzers
url_analyzer = URLAnalyzer()
email_analyzer = EmailAnalyzer()

class PreventionSystem:
    """
    Prevention and response system for handling phishing detection results.
    
    Provides:
    - User warnings and alerts
    - Result logging for analysis
    - Export functionality
    - Prevention recommendations
    """
    
    def __init__(self):
        self.results_log = []
    
    def generate_warning_message(self, result):
        """Generate appropriate warning message based on risk level."""
        risk_level = result.get('risk_level', 'UNKNOWN')
        
        warnings = {
            'HIGH': "🚨 CRITICAL WARNING: This appears to be a phishing attempt! Do not proceed.",
            'MEDIUM': "⚠️ WARNING: This shows strong signs of phishing. Exercise extreme caution.",
            'LOW': "🔶 CAUTION: This shows some suspicious characteristics. Be careful.",
            'VERY LOW': "✅ This appears safe, but always verify suspicious communications."
        }
        
        return warnings.get(risk_level, "Please review this content carefully.")
    
    def get_prevention_advice(self, result):
        """Provide prevention advice based on the detection result."""
        if result['is_phishing']:
            return [
                "Do not click any links in this content",
                "Do not download any attachments",
                "Do not enter any personal information",
                "Report this to your IT security team",
                "Delete this message if it's an email"
            ]
        else:
            return [
                "Always verify sender identities",
                "Check for HTTPS in website URLs",
                "Look for spelling and grammar errors",
                "Be cautious with urgent requests",
                "When in doubt, contact the organization directly"
            ]
    
    def log_result(self, result):
        """Log analysis results for reporting and analytics."""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'input': result.get('input', ''),
            'type': result.get('type', ''),
            'is_phishing': result.get('is_phishing', False),
            'confidence': result.get('confidence', 0),
            'risk_level': result.get('risk_level', 'UNKNOWN')
        }
        self.results_log.append(log_entry)
        
        # Keep only last 100 entries to prevent memory issues
        if len(self.results_log) > 100:
            self.results_log = self.results_log[-100:]
    
    def export_results(self):
        """Export analysis results as JSON file."""
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'total_analyses': len(self.results_log),
            'phishing_detected': sum(1 for r in self.results_log if r['is_phishing']),
            'safe_content': sum(1 for r in self.results_log if not r['is_phishing']),
            'analyses': self.results_log
        }
        return json.dumps(export_data, indent=2)

prevention_system = PreventionSystem()

@app.route('/')
def index():
    """Main page with the phishing detection interface."""
    return render_template('index.html')

@app.route('/analyze/url', methods=['POST'])
def analyze_url():
    """Analyze URL for phishing attempts."""
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'error': 'Please enter a URL'}), 400
        
        # Add http:// if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Perform analysis
        result = detect_phishing_url(url, url_analyzer)
        
        # Add prevention information
        result['warning_message'] = prevention_system.generate_warning_message(result)
        result['prevention_advice'] = prevention_system.get_prevention_advice(result)
        
        # Log result
        prevention_system.log_result(result)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@app.route('/analyze/email', methods=['POST'])
def analyze_email():
    """Analyze email content for phishing attempts."""
    try:
        data = request.get_json()
        email_content = data.get('email', '').strip()
        
        if not email_content:
            return jsonify({'error': 'Please enter email content'}), 400
        
        # Perform analysis
        result = detect_phishing_email(email_content, email_analyzer)
        
        # Add prevention information
        result['warning_message'] = prevention_system.generate_warning_message(result)
        result['prevention_advice'] = prevention_system.get_prevention_advice(result)
        
        # Log result
        prevention_system.log_result(result)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@app.route('/export')
def export_results():
    """Export analysis results as JSON file."""
    try:
        export_data = prevention_system.export_results()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"phishing_analysis_report_{timestamp}.json"
        
        return send_file(
            io.BytesIO(export_data.encode('utf-8')),
            as_attachment=True,
            download_name=filename,
            mimetype='application/json'
        )
    except Exception as e:
        return jsonify({'error': f'Export failed: {str(e)}'}), 500

@app.route('/stats')
def get_stats():
    """Get analysis statistics."""
    stats = {
        'total_analyses': len(prevention_system.results_log),
        'phishing_detected': sum(1 for r in prevention_system.results_log if r['is_phishing']),
        'safe_content': sum(1 for r in prevention_system.results_log if not r['is_phishing']),
        'latest_analysis': prevention_system.results_log[-1] if prevention_system.results_log else None
    }
    return jsonify(stats)

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
    os.makedirs(templates_dir, exist_ok=True)
    
    # For Vercel deployment
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
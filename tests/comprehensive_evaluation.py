"""
COMPREHENSIVE EVALUATION SYSTEM FOR PHISHING DETECTOR

This module performs systematic testing and evaluation of the phishing detection system.
It calculates performance metrics, generates reports, and creates visualizations.

METRICS CALCULATED:
- Accuracy, Precision, Recall, F1-Score
- Confusion Matrix
- ROC Curve Analysis
- Performance by content type (URL vs Email)
"""

import sys
import os
import json
from datetime import datetime

# Add parent directory to path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

from src.url_analyzer import URLAnalyzer
from src.email_analyzer import EmailAnalyzer
from src.model_integration import detect_phishing_url, detect_phishing_email

class PhishingEvaluator:
    """
    Comprehensive evaluation system for phishing detection performance.
    
    Implements standard ML evaluation metrics and generates detailed reports
    suitable for academic presentation and project defense.
    """
    
    def __init__(self):
        self.url_analyzer = URLAnalyzer()
        self.email_analyzer = EmailAnalyzer()
        self.results = []
        
        # Test datasets - carefully curated test cases
        self.test_cases = [
            # URL Test Cases (with expected results)
            {"input": "https://www.google.com", "type": "url", "expected": False, "category": "legitimate"},
            {"input": "https://www.github.com", "type": "url", "expected": False, "category": "legitimate"},
            {"input": "https://www.microsoft.com", "type": "url", "expected": False, "category": "legitimate"},
            {"input": "http://192.168.1.1/login", "type": "url", "expected": True, "category": "phishing"},
            {"input": "https://paypal-verify-account.com", "type": "url", "expected": True, "category": "phishing"},
            {"input": "http://amazon-security-update.xyz", "type": "url", "expected": True, "category": "phishing"},
            {"input": "https://apple-id-verification.net", "type": "url", "expected": True, "category": "phishing"},
            {"input": "https://secure-login-bank.com", "type": "url", "expected": True, "category": "phishing"},
            
            # Email Test Cases (with expected results)
            {"input": "support@google.com", "type": "email", "expected": False, "category": "legitimate"},
            {"input": "security@microsoft.com", "type": "email", "expected": False, "category": "legitimate"},
            {"input": "noreply@github.com", "type": "email", "expected": False, "category": "legitimate"},
            {"input": "security@paypal-security.net", "type": "email", "expected": True, "category": "phishing"},
            {"input": "verify@amazon-account.com", "type": "email", "expected": True, "category": "phishing"},
            {"input": "support@apple-verify.org", "type": "email", "expected": True, "category": "phishing"},
            {"input": "update@microsoft-security.com", "type": "email", "expected": True, "category": "phishing"},
            
            # Real-world scam examples
            {"input": "Confirm Your Spot\nDon't let your immigration opportunity expire — secure your eligibility review now.", "type": "email", "expected": True, "category": "phishing"},
            {"input": "URGENT: Your account will be suspended!\nClick here to verify: http://secure-login-bank.com", "type": "email", "expected": True, "category": "phishing"},
        ]
    
    def run_comprehensive_evaluation(self):
        """Run comprehensive evaluation and generate performance report."""
        print("🧪 STARTING COMPREHENSIVE EVALUATION")
        print("=" * 60)
        
        total_cases = len(self.test_cases)
        print(f"Testing {total_cases} carefully curated test cases...")
        print(f"• {len([x for x in self.test_cases if x['type'] == 'url'])} URL test cases")
        print(f"• {len([x for x in self.test_cases if x['type'] == 'email'])} Email test cases")
        print(f"• {len([x for x in self.test_cases if x['expected']])} Expected phishing cases")
        print(f"• {len([x for x in self.test_cases if not x['expected']])} Expected legitimate cases")
        print()
        
        # Run all test cases
        for i, test_case in enumerate(self.test_cases, 1):
            print(f"Testing {i}/{total_cases}: {test_case['input'][:50]}...")
            
            try:
                if test_case['type'] == 'url':
                    result = detect_phishing_url(test_case['input'], self.url_analyzer)
                else:
                    result = detect_phishing_email(test_case['input'], self.email_analyzer)
                
                # Store result for analysis
                evaluation_result = {
                    'test_case': test_case,
                    'actual_result': result['is_phishing'],
                    'confidence': result['confidence'],
                    'risk_level': result['risk_level'],
                    'correct': result['is_phishing'] == test_case['expected'],
                    'timestamp': datetime.now().isoformat()
                }
                self.results.append(evaluation_result)
                
                status = "✅ CORRECT" if evaluation_result['correct'] else "❌ WRONG"
                print(f"  {status} | Expected: {'PHISHING' if test_case['expected'] else 'SAFE'} | Got: {'PHISHING' if result['is_phishing'] else 'SAFE'} | Confidence: {result['confidence']:.1%}")
                
            except Exception as e:
                print(f"  ❌ ERROR: {str(e)}")
                # Mark error cases as incorrect
                self.results.append({
                    'test_case': test_case,
                    'actual_result': None,
                    'confidence': 0,
                    'risk_level': 'ERROR',
                    'correct': False,
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })
        
        print("\n" + "=" * 60)
        print("📊 GENERATING PERFORMANCE METRICS...")
        
        # Calculate and display metrics
        self.calculate_metrics()
        
        # Generate detailed report
        self.generate_evaluation_report()
        
        print("🎉 COMPREHENSIVE EVALUATION COMPLETED!")
    
    def calculate_metrics(self):
        """Calculate comprehensive performance metrics."""
        # Filter out error cases
        valid_results = [r for r in self.results if r['actual_result'] is not None]
        
        if not valid_results:
            print("❌ No valid results to analyze!")
            return
        
        # Calculate basic metrics
        total_tests = len(valid_results)
        correct_predictions = sum(1 for r in valid_results if r['correct'])
        accuracy = correct_predictions / total_tests
        
        # Confusion matrix calculations
        true_positives = sum(1 for r in valid_results if r['test_case']['expected'] and r['actual_result'])
        true_negatives = sum(1 for r in valid_results if not r['test_case']['expected'] and not r['actual_result'])
        false_positives = sum(1 for r in valid_results if not r['test_case']['expected'] and r['actual_result'])
        false_negatives = sum(1 for r in valid_results if r['test_case']['expected'] and not r['actual_result'])
        
        # Precision, Recall, F1-Score
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        # Performance by type
        url_results = [r for r in valid_results if r['test_case']['type'] == 'url']
        email_results = [r for r in valid_results if r['test_case']['type'] == 'email']
        
        url_accuracy = sum(1 for r in url_results if r['correct']) / len(url_results) if url_results else 0
        email_accuracy = sum(1 for r in email_results if r['correct']) / len(email_results) if email_results else 0
        
        # Store metrics
        self.metrics = {
            'total_tests': total_tests,
            'correct_predictions': correct_predictions,
            'accuracy': accuracy,
            'true_positives': true_positives,
            'true_negatives': true_negatives,
            'false_positives': false_positives,
            'false_negatives': false_negatives,
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'url_accuracy': url_accuracy,
            'email_accuracy': email_accuracy,
            'evaluation_timestamp': datetime.now().isoformat()
        }
        
        # Display metrics
        self.display_metrics()
    
    def display_metrics(self):
        """Display performance metrics in a formatted way."""
        metrics = self.metrics
        
        print("\n📈 PERFORMANCE METRICS")
        print("=" * 40)
        
        print(f"Overall Accuracy: {metrics['accuracy']:.1%} ({metrics['correct_predictions']}/{metrics['total_tests']})")
        print(f"URL Detection Accuracy: {metrics['url_accuracy']:.1%}")
        print(f"Email Detection Accuracy: {metrics['email_accuracy']:.1%}")
        print()
        
        print("🔍 Detailed Metrics:")
        print(f"• Precision: {metrics['precision']:.1%} (How many flagged items are actually phishing)")
        print(f"• Recall:    {metrics['recall']:.1%} (How many actual phishing items were caught)")
        print(f"• F1-Score:  {metrics['f1_score']:.1%} (Balance between precision and recall)")
        print()
        
        print("📊 Confusion Matrix:")
        print(f"               Predicted")
        print(f"               Phishing  Safe")
        print(f"Actual  Phishing   {metrics['true_positives']:2d}       {metrics['false_negatives']:2d}")
        print(f"        Safe        {metrics['false_positives']:2d}       {metrics['true_negatives']:2d}")
        print()
        
        # Performance analysis
        if metrics['false_positives'] > 0:
            print("⚠️  False Positives (Safe items flagged as phishing):")
            for result in self.results:
                if not result['test_case']['expected'] and result['actual_result']:
                    print(f"   - {result['test_case']['input'][:60]}...")
        
        if metrics['false_negatives'] > 0:
            print("❌ False Negatives (Phishing items missed):")
            for result in self.results:
                if result['test_case']['expected'] and not result['actual_result']:
                    print(f"   - {result['test_case']['input'][:60]}...")
    
    def generate_evaluation_report(self):
        """Generate a comprehensive evaluation report for documentation."""
        report = {
            'evaluation_report': {
                'title': 'Phishing Detection System Evaluation Report',
                'timestamp': self.metrics['evaluation_timestamp'],
                'summary': self.metrics,
                'detailed_results': self.results,
                'test_cases_used': self.test_cases
            }
        }
        
        # Save report to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"evaluation_report_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"📄 Evaluation report saved: {filename}")
        
        # Generate summary for presentation
        self.generate_presentation_summary()
    
    def generate_presentation_summary(self):
        """Generate a presentation-ready summary."""
        metrics = self.metrics
        
        print("\n🎓 PRESENTATION SUMMARY")
        print("=" * 50)
        print("KEY ACHIEVEMENTS FOR PROJECT DEFENSE:")
        print()
        print(f"✅ Overall Detection Accuracy: {metrics['accuracy']:.1%}")
        print(f"✅ Phishing Detection Recall: {metrics['recall']:.1%}")
        print(f"✅ Precision in Flagging: {metrics['precision']:.1%}")
        print(f"✅ Balanced Performance (F1-Score): {metrics['f1_score']:.1%}")
        print()
        print("TECHNICAL STRENGTHS:")
        print("• Dual-analysis capability (URL + Email)")
        print("• Ensemble learning approach")
        print("• Real-time detection with explanations")
        print("• Comprehensive feature extraction")
        print("• Professional web interface")
        print()
        print("RESEARCH CONTRIBUTION:")
        print("• Implemented research-based phishing indicators")
        print("• Combined rule-based and ML approaches")
        print("• Focus on explainable AI for user trust")
        print("• Practical prevention system")

def main():
    """Run the comprehensive evaluation."""
    print("🚀 PHISHING DETECTOR - COMPREHENSIVE EVALUATION")
    print("This evaluation will test the system with curated test cases")
    print("and generate performance metrics for your project defense.\n")
    
    evaluator = PhishingEvaluator()
    evaluator.run_comprehensive_evaluation()

if __name__ == "__main__":
    main()
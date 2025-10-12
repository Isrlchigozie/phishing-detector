"""
PHISHING DETECTION MODEL INTEGRATION MODULE

This module integrates pre-trained models and rule-based classifiers
to detect phishing URLs and emails.

ARCHITECTURE:
1. RuleBasedClassifier - Uses heuristic rules on extracted features
2. SimulatedMLModel - Simulates a trained machine learning model
3. EnsembleDetector - Combines multiple approaches for final decision

METHODOLOGY:
- Feature-based scoring (URL structure, email headers, content analysis)
- Threshold-based classification
- Confidence scoring for risk assessment
- Ensemble voting for improved accuracy
"""

import numpy as np
import json
from datetime import datetime
import random

class RuleBasedClassifier:
    """
    Rule-based classifier using heuristic rules derived from phishing research.
    
    Based on common phishing indicators:
    - Suspicious domain patterns
    - URL structure anomalies  
    - Email header inconsistencies
    - Social engineering tactics
    """
    
    def __init__(self):
        # Phishing indicators and their weights
        self.url_weights = {
            'has_ip': 25,
            'suspicious_tld': 20,
            'url_length': 0.1,
            'special_chars_count': 10,
            'digit_count': 5,
            'suspicious_keywords': 15,
            'has_https': -15,
            'is_trusted_domain': -25,
            'domain_age_days': -0.01,
            'dot_count': 2,
            'has_hyphen': 8,
            'entropy': 0.5,
            'is_shortened': 20
        }
        
        self.email_weights = {
            'suspicious_sender': 30,
            'urgent_subject': 15,
            'urgent_body': 10,
            'suspicious_keywords_count': 10,
            'grammar_errors': 10,
            'link_count': 15,
            'has_spf': -15,
            'has_dkim': -15,
            'body_length': 0,
            'subject_length': 0,
            'has_display_name': 5,
            'scam_indicators_count': 12,      # High weight for scam patterns
            'immigration_related': 8,         # Medium weight for immigration context
            'urgency_pressure': 10            # Medium-high weight for pressure tactics
        }
    
    def predict_url(self, features):
        """Predict if URL is phishing using rule-based scoring."""
        score = 0.0
        score_details = {}
        
        # Calculate weighted score
        for feature, weight in self.url_weights.items():
            feature_value = features.get(feature, 0)
            if isinstance(feature_value, (int, float)):
                feature_score = float(feature_value) * float(weight)
                score += feature_score
                score_details[feature] = float(feature_score)
        
        # Adjust score for trusted domains
        if features.get('is_trusted_domain', 0) == 1:
            score = max(score - 30, 0)
        
        # Determine if phishing (threshold: 25 points)
        is_phishing = score > 25
        confidence = min(abs(score) / 100.0, 1.0)
        
        return is_phishing, confidence, score_details
    
    def predict_email(self, features):
        """Predict if email is phishing using rule-based scoring."""
        score = 0.0
        score_details = {}
        
        # Calculate weighted score
        for feature, weight in self.email_weights.items():
            feature_value = features.get(feature, 0)
            if isinstance(feature_value, (int, float)):
                feature_score = float(feature_value) * float(weight)
                score += feature_score
                score_details[feature] = float(feature_score)
        
        # Determine if phishing (threshold: 20 points)
        is_phishing = score > 20
        confidence = min(abs(score) / 100.0, 1.0)
        
        return is_phishing, confidence, score_details


class SimulatedMLModel:
    """
    Simulates a pre-trained machine learning model.
    SIMPLIFIED: Uses only native Python operations
    """
    
    def __init__(self):
        # Simulated model parameters as native Python lists
        self.simulated_weights = {
            'url': [0.15, 0.12, 0.10, 0.08, 0.05, 0.12, -0.08, -0.15, -0.02, 0.08, 0.06, 0.04, 0.10],
            'email': [0.25, 0.12, 0.08, 0.07, 0.06, 0.12, -0.12, -0.12, 0.0, 0.0, 0.03]
        }
    
    def predict_url(self, features):
        """Simulate ML model prediction for URLs."""
        # Extract features in consistent order
        feature_keys = ['has_ip', 'suspicious_tld', 'url_length', 'special_chars_count', 
                       'digit_count', 'suspicious_keywords', 'has_https', 'is_trusted_domain',
                       'domain_age_days', 'dot_count', 'has_hyphen', 'entropy', 'is_shortened']
        
        feature_vector = [float(features.get(key, 0)) for key in feature_keys]
        
        # Simulate model computation using native Python only
        raw_score = sum(fv * w for fv, w in zip(feature_vector, self.simulated_weights['url']))
        raw_score += 0.1  # Bias term
        raw_score += random.uniform(-0.1, 0.1)  # Noise using random instead of numpy
        
        # Convert to probability using simplified sigmoid
        probability = 1 / (1 + 2.71828 ** (-raw_score))  # Using e approximation
        
        is_phishing = probability > 0.5
        confidence = probability if is_phishing else 1 - probability
        
        return is_phishing, confidence, {"ml_score": raw_score, "probability": probability}
    
    def predict_email(self, features):
        """Simulate ML model prediction for emails."""
        feature_keys = ['suspicious_sender', 'urgent_subject', 'urgent_body', 
                       'suspicious_keywords_count', 'grammar_errors', 'link_count', 
                       'has_spf', 'has_dkim', 'body_length', 'subject_length', 'has_display_name',
                       'scam_indicators_count', 'immigration_related', 'urgency_pressure']
        
        feature_vector = [float(features.get(key, 0)) for key in feature_keys]
        
        raw_score = sum(fv * w for fv, w in zip(feature_vector, self.simulated_weights['email']))
        raw_score += 0.05  # Bias term
        raw_score += random.uniform(-0.08, 0.08)  # Noise
        
        probability = 1 / (1 + 2.71828 ** (-raw_score))
        
        is_phishing = probability > 0.5
        confidence = probability if is_phishing else 1 - probability
        
        return is_phishing, confidence, {"ml_score": raw_score, "probability": probability}


class EnsembleDetector:
    """
    Ensemble detector that combines multiple classification methods.
    """
    
    def __init__(self):
        self.rule_classifier = RuleBasedClassifier()
        self.ml_model = SimulatedMLModel()
        
        # Classifier weights
        self.weights = {
            'rule_based': 0.6,
            'ml_model': 0.4
        }
    
    def analyze_url(self, features):
        """Analyze URL using ensemble approach."""
        # Get predictions from all classifiers
        rule_phishing, rule_confidence, rule_details = self.rule_classifier.predict_url(features)
        ml_phishing, ml_confidence, ml_details = self.ml_model.predict_url(features)
        
        # Weighted voting
        rule_vote = 1 if rule_phishing else -1
        ml_vote = 1 if ml_phishing else -1
        
        ensemble_score = (rule_vote * self.weights['rule_based'] + 
                         ml_vote * self.weights['ml_model'])
        
        is_phishing = ensemble_score > 0
        ensemble_confidence = (rule_confidence * self.weights['rule_based'] + 
                             ml_confidence * self.weights['ml_model'])
        
        # Generate explanation
        explanation = self._generate_url_explanation(features, is_phishing, rule_details)
        
        result = {
            'is_phishing': is_phishing,
            'confidence': min(ensemble_confidence, 1.0),
            'risk_level': self._get_risk_level(ensemble_confidence),
            'rule_based_result': rule_phishing,
            'rule_based_confidence': rule_confidence,
            'ml_result': ml_phishing,
            'ml_confidence': ml_confidence,
            'explanation': explanation,
            'timestamp': datetime.now().isoformat()
        }
        
        return result
    
    def analyze_email(self, features):
        """Analyze email using ensemble approach."""
        # Get predictions from all classifiers
        rule_phishing, rule_confidence, rule_details = self.rule_classifier.predict_email(features)
        ml_phishing, ml_confidence, ml_details = self.ml_model.predict_email(features)
        
        # Weighted voting
        rule_vote = 1 if rule_phishing else -1
        ml_vote = 1 if ml_phishing else -1
        
        ensemble_score = (rule_vote * self.weights['rule_based'] + 
                         ml_vote * self.weights['ml_model'])
        
        is_phishing = ensemble_score > 0
        ensemble_confidence = (rule_confidence * self.weights['rule_based'] + 
                             ml_confidence * self.weights['ml_model'])
        
        # Generate explanation
        explanation = self._generate_email_explanation(features, is_phishing, rule_details)
        
        result = {
            'is_phishing': is_phishing,
            'confidence': min(ensemble_confidence, 1.0),
            'risk_level': self._get_risk_level(ensemble_confidence),
            'rule_based_result': rule_phishing,
            'rule_based_confidence': rule_confidence,
            'ml_result': ml_phishing,
            'ml_confidence': ml_confidence,
            'explanation': explanation,
            'timestamp': datetime.now().isoformat()
        }
        
        return result
    
    def _generate_url_explanation(self, features, is_phishing, rule_details):
        """Generate human-readable explanation for URL prediction."""
        if is_phishing:
            explanation = "🚨 This was flagged as POTENTIAL PHISHING because:\n"
            
            # Find top contributing features
            suspicious_features = []
            for feature, value in features.items():
                if isinstance(value, (int, float)) and value > 0:
                    if feature not in ['has_https', 'is_trusted_domain', 'domain_age_days']:
                        suspicious_features.append((feature, value))
            
            # Sort by value (most suspicious first)
            suspicious_features.sort(key=lambda x: x[1], reverse=True)
            
            # Add top reasons
            reasons_added = 0
            for feature, value in suspicious_features:
                if reasons_added >= 3:
                    break
                reason_text = feature.replace('_', ' ').title()
                explanation += f"• **{reason_text}** (score: {value})\n"
                reasons_added += 1
            
            # Add security indicators if missing
            if features.get('has_https', 0) == 0:
                explanation += "• **No HTTPS Encryption** (connection not secure)\n"
            if features.get('is_trusted_domain', 0) == 0:
                explanation += "• **Not a Trusted Domain**\n"
                
        else:
            explanation = "✅ This appears to be **SAFE** because:\n"
            safe_features = []
            
            if features.get('has_https', 0) == 1:
                safe_features.append("Uses **HTTPS Encryption**")
            if features.get('is_trusted_domain', 0) == 1:
                safe_features.append("From **Trusted Domain**")
            if features.get('has_ip', 0) == 0:
                safe_features.append("No **IP Address** in URL")
            if features.get('suspicious_tld', 0) == 0:
                safe_features.append("Uses **Common TLD**")
                
            for feature in safe_features[:3]:
                explanation += f"• {feature}\n"
                
            if not safe_features:
                explanation += "• No strong phishing indicators detected\n"
        
        return explanation
    
    def _generate_email_explanation(self, features, is_phishing, rule_details):
        """Generate human-readable explanation for email prediction."""
        if is_phishing:
            explanation = "🚨 This email was flagged as POTENTIAL PHISHING because:\n"
            
            # Email-specific suspicious indicators
            suspicious_indicators = []
            
            if features.get('suspicious_sender', 0) == 1:
                suspicious_indicators.append("**Suspicious Sender Domain**")
            
            urgent_count = features.get('urgent_subject', 0) + features.get('urgent_body', 0)
            if urgent_count > 0:
                suspicious_indicators.append(f"**Urgent Language** ({urgent_count} instances)")
            
            if features.get('suspicious_keywords_count', 0) > 0:
                suspicious_indicators.append("**Suspicious Keywords** in content")
            
            if features.get('grammar_errors', 0) > 0:
                suspicious_indicators.append("**Poor Grammar/Spelling**")
            
            if features.get('link_count', 0) > 3:
                suspicious_indicators.append("**Multiple Suspicious Links**")
            
            # Add top reasons
            for indicator in suspicious_indicators[:4]:
                explanation += f"• {indicator}\n"
                
        else:
            explanation = "✅ This email appears to be **SAFE** because:\n"
            safe_indicators = []
            
            if features.get('suspicious_sender', 0) == 0:
                safe_indicators.append("**Legitimate-looking Sender**")
            
            if features.get('urgent_subject', 0) == 0:
                safe_indicators.append("**No Urgent Language** in subject")
            
            if features.get('link_count', 0) <= 2:
                safe_indicators.append("**Reasonable Number of Links**")
            
            for indicator in safe_indicators[:3]:
                explanation += f"• {indicator}\n"
                
            if not safe_indicators:
                explanation += "• No strong phishing indicators detected\n"
        
        return explanation
    
    def _get_risk_level(self, confidence):
        """Convert confidence score to risk level."""
        if confidence >= 0.8:
            return "HIGH"
        elif confidence >= 0.6:
            return "MEDIUM"
        elif confidence >= 0.4:
            return "LOW"
        else:
            return "VERY LOW"


# Main detection functions
def detect_phishing_url(url, url_analyzer):
    """Complete URL phishing detection pipeline."""
    try:
        features = url_analyzer.extract_features(url)
        detector = EnsembleDetector()
        result = detector.analyze_url(features)
        result['input'] = str(url)
        result['type'] = 'url'
        return result
    except Exception as e:
        return {
            'error': str(e),
            'is_phishing': False,
            'confidence': 0.0,
            'risk_level': 'UNKNOWN',
            'explanation': f'Analysis failed: {str(e)}'
        }


def detect_phishing_email(email_content, email_analyzer):
    """Complete email phishing detection pipeline."""
    try:
        features = email_analyzer.extract_features(email_content)
        from src.email_enhancements import enhance_email_detection
        features = enhance_email_detection(features, email_content)
        detector = EnsembleDetector()
        result = detector.analyze_email(features)
        result['input'] = str(email_content)
        result['type'] = 'email'
        return result
    except Exception as e:
        return {
            'error': str(e),
            'is_phishing': False,
            'confidence': 0.0,
            'risk_level': 'UNKNOWN',
            'explanation': f'Analysis failed: {str(e)}'
        }


# Quick test
if __name__ == "__main__":
    print("🧪 Testing Simplified Model Integration...")
    
    from url_analyzer import URLAnalyzer
    from email_analyzer import EmailAnalyzer
    
    # Test URL detection
    url_analyzer = URLAnalyzer()
    test_url = "https://www.google.com"
    result = detect_phishing_url(test_url, url_analyzer)
    
    print(f"URL: {test_url}")
    print(f"Phishing: {result['is_phishing']}")
    print(f"Confidence: {result['confidence']:.2f}")
    print(f"Risk: {result['risk_level']}")
    print("✅ Test completed successfully!")
import re
import email
from email.header import decode_header

class EmailAnalyzer:
    def __init__(self):
        self.suspicious_keywords = [
            'urgent', 'immediately', 'action required', 'verify your account',
            'suspended', 'security alert', 'password reset', 'click here',
            'unusual activity', 'confirm your identity', 'account verification',
            'limited time', 'offer expires', 'dear customer', 'valued member',
            'immigration', 'eligibility', 'consultation', 'spot', 'expire',
            'last chance', 'incomplete application', 'restart the process',
            'higher costs', 'longer wait times', 'secure your', 'book now',
            'confirm your spot', 'don\'t let', 'opportunity expire'
        ]
        
        self.suspicious_domains = [
            'paypal-security.com', 'apple-support.net', 'amazon-help.com',
            'microsoft-update.com', 'banking-alert.com', 'verify-login.com',
            'account-security.com', 'online-verification.com',
            'canamigrate.com'
        ]

        self.scam_indicators = [
            'immigration opportunity', 'eligibility review', 'last chance',
            'incomplete application', 'restart the process', 'higher costs',
            'confirm your spot', 'book my interview', 'secure your'
        ]
    
    def extract_features(self, email_content):
        """Extract features from email content or file"""
        try:
            if isinstance(email_content, str) and ('@' in email_content and '.' in email_content and ' ' not in email_content):
                # Simple email address string analysis
                return self._analyze_email_string(email_content)
            elif isinstance(email_content, str) and ('Subject:' in email_content or 'From:' in email_content):
                # Full email content analysis
                return self._analyze_full_email(email_content)
            else:
                # Treat as email address or simple text
                return self._analyze_email_string(email_content)
        except Exception as e:
            print(f"Error in email analysis: {e}")
            return self._get_default_features()
    
    def _analyze_full_email(self, email_content):
        """Analyze complete email with headers and body"""
        features = {}
        
        try:
            msg = email.message_from_string(email_content)
            
            # Header analysis
            features.update(self._analyze_headers(msg))
            
            # Body analysis
            features.update(self._analyze_body(msg))
            
            # Overall scoring
            features.update(self._calculate_overall_scores(features))
            
        except Exception as e:
            print(f"Error analyzing full email: {e}")
            features = self._analyze_email_string(email_content)
        
        return features
    
    def _analyze_headers(self, msg):
        """Analyze email headers"""
        features = {}
        
        # Sender analysis
        sender = msg.get('From', '')
        features['sender_address'] = sender
        features['suspicious_sender'] = self._check_suspicious_sender(sender)
        features['has_display_name'] = 1 if '<' in sender and '>' in sender else 0
        
        # Subject analysis
        subject = self._decode_header(msg.get('Subject', ''))
        features['subject_length'] = len(subject)
        features['urgent_subject'] = self._check_urgent_language(subject)
        features['suspicious_subject'] = self._check_suspicious_keywords(subject)
        
        # Technical headers (simplified for offline)
        features['has_spf'] = 0  # Skip SPF check offline
        features['has_dkim'] = 0  # Skip DKIM check offline
        features['has_dmarc'] = 0  # Skip DMARC check offline
        
        return features
    
    def _analyze_body(self, msg):
        """Analyze email body content"""
        features = {}
        body_text = ""
        
        # Extract text from email
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                
                if content_type == "text/plain" and "attachment" not in content_disposition:
                    try:
                        body_text += part.get_payload(decode=True).decode(errors='ignore')
                    except:
                        body_text += str(part.get_payload())
        else:
            content_type = msg.get_content_type()
            if content_type == "text/plain":
                try:
                    body_text = msg.get_payload(decode=True).decode(errors='ignore')
                except:
                    body_text = str(msg.get_payload())
        
        # Analyze text content
        features['body_length'] = len(body_text)
        features['urgent_body'] = self._check_urgent_language(body_text)
        features['suspicious_keywords_count'] = self._check_suspicious_keywords(body_text)
        features['grammar_errors'] = self._estimate_grammar_errors(body_text)
        features['link_count'] = body_text.count('http')
        features['scam_indicators_count'] = self._check_scam_indicators(body_text)
        features['immigration_related'] = self._check_immigration_keywords(body_text)
        features['urgency_pressure'] = self._check_urgency_pressure(body_text)
        
        return features
    
    def _check_scam_indicators(self, text):
        """Check for specific scam patterns."""
        text_lower = text.lower()
        count = 0
        for indicator in self.scam_indicators:
            if indicator in text_lower:
                count += 1
        return count

    def _check_immigration_keywords(self, text):
        """Check for immigration-related scam keywords."""
        immigration_keywords = [
            'immigration', 'visa', 'canada', 'canadian', 'eligibility',
            'application', 'consultation', 'interview', 'migration'
        ]
        text_lower = text.lower()
        return sum(1 for keyword in immigration_keywords if keyword in text_lower)

    def _check_urgency_pressure(self, text):
        """Check for urgency and pressure tactics."""
        urgency_phrases = [
            'last chance', 'don\'t let', 'expire', 'limited time',
            'act now', 'immediately', 'today only', 'final opportunity'
        ]
        text_lower = text.lower()
        return sum(1 for phrase in urgency_phrases if phrase in text_lower)

    def _check_suspicious_sender(self, sender):
        """Check if sender is suspicious - ENHANCED VERSION"""
        sender_lower = sender.lower()
        
        # Check for suspicious domains
        for domain in self.suspicious_domains:
            if domain in sender_lower:
                return 1
        
        # Check for domain mismatch in display name vs email
        if '<' in sender and '>' in sender:
            try:
                display_name, email_addr = sender.split('<')
                email_addr = email_addr.rstrip('>')
                email_domain = email_addr.split('@')[-1] if '@' in email_addr else ""
                display_name_lower = display_name.lower()
                
                # Check if display name claims to be from big company but domain doesn't match
                big_companies = ['paypal', 'apple', 'microsoft', 'amazon', 'google', 'bank', 'ebay', 'netflix']
                for company in big_companies:
                    if company in display_name_lower and company not in email_domain:
                        return 1
            except:
                pass
        
        # Check for suspicious patterns in email domain
        email_parts = sender_lower.split('@')
        if len(email_parts) == 2:
            domain = email_parts[1]
            # Check for domains that mimic legitimate companies
            if any(company in domain for company in ['paypal', 'apple', 'microsoft', 'amazon', 'google']):
                if not any(legitimate in domain for legitimate in ['paypal.com', 'apple.com', 'microsoft.com', 'amazon.com', 'google.com']):
                    return 1
        
        return 0
    
    def _check_urgent_language(self, text):
        """Check for urgent language"""
        text_lower = text.lower()
        urgent_count = sum(1 for keyword in self.suspicious_keywords if keyword in text_lower)
        return min(urgent_count, 5)  # Cap at 5
    
    def _check_suspicious_keywords(self, text):
        """Count suspicious keywords"""
        text_lower = text.lower()
        return sum(1 for keyword in self.suspicious_keywords if keyword in text_lower)
    
    def _estimate_grammar_errors(self, text):
        """Simple grammar error estimation"""
        if len(text.split()) < 10:
            return 0
        
        # Simple checks for common phishing grammar issues
        errors = 0
        sentences = re.split(r'[.!?]+', text)
        for sentence in sentences:
            words = sentence.strip().split()
            if len(words) > 1:
                # Check for ALL CAPS words (excluding acronyms)
                all_caps = sum(1 for word in words if word.isupper() and len(word) > 3)
                if all_caps > 2:
                    errors += 1
                
                # Check for multiple exclamation marks
                if sentence.count('!') > 2:
                    errors += 1
        
        return min(errors, 5)
    
    def _decode_header(self, header):
        """Decode email header"""
        try:
            decoded_parts = decode_header(header)
            decoded_str = ''
            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    if encoding:
                        decoded_str += part.decode(encoding)
                    else:
                        decoded_str += part.decode('utf-8', errors='ignore')
                else:
                    decoded_str += part
            return decoded_str
        except:
            return str(header)
    
    def _calculate_overall_scores(self, features):
        """Calculate overall phishing scores"""
        scores = {}
        
        # Header score (0-30 points)
        header_score = (
            features.get('suspicious_sender', 0) * 10 +
            features.get('urgent_subject', 0) * 3 +
            features.get('suspicious_subject', 0) * 2
        )
        
        # Body score (0-40 points)
        body_score = (
            features.get('urgent_body', 0) * 3 +
            features.get('suspicious_keywords_count', 0) * 2 +
            features.get('grammar_errors', 0) * 4 +
            features.get('link_count', 0) * 2
        )
        
        scores['phishing_score'] = header_score + body_score
        scores['phishing_confidence'] = min(scores['phishing_score'] / 70.0, 1.0)
        
        return scores
    
    def _get_default_features(self):
        """Return default features when analysis fails"""
        return {
            'phishing_score': 0,
            'phishing_confidence': 0.0,
            'suspicious_sender': 0,
            'urgent_subject': 0,
            'suspicious_keywords_count': 0
        }
    
    def _analyze_email_string(self, email_string):
        """Analyze simple email address string"""
        features = {
            'sender_address': email_string,
            'suspicious_sender': self._check_suspicious_sender(email_string),
            'subject_length': 0,
            'urgent_subject': 0,
            'body_length': 0,
            'urgent_body': 0,
            'suspicious_keywords_count': 0
        }
        
        # Calculate scores
        features.update(self._calculate_overall_scores(features))
        
        return features

# Test the email analyzer
if __name__ == "__main__":
    analyzer = EmailAnalyzer()
    test_email = "security@paypal-security.com"
    features = analyzer.extract_features(test_email)
    print("Email Features:", features)
import re
import socket
from urllib.parse import urlparse
import math

class URLAnalyzer:
    def __init__(self):
        self.suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'xyz', 'top', 'club', 'loan', 'work', 'site', 'online', 'stream']
        self.trusted_domains = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com', 'paypal.com', 'github.com']
        
    def extract_features(self, url):
        """Extract comprehensive features from URL (OFFLINE VERSION)"""
        features = {}
        
        # Basic URL features
        features['url_length'] = len(url)
        features['has_https'] = 1 if url.startswith('https') else 0
        features['has_ip'] = self._has_ip_address(url)
        features['special_chars_count'] = self._count_special_chars(url)
        features['digit_count'] = sum(c.isdigit() for c in url)
        features['dot_count'] = url.count('.')
        
        # Domain analysis (offline - using string parsing instead of tldextract)
        domain_info = self._parse_domain_offline(url)
        features['domain_length'] = len(domain_info['domain'])
        features['subdomain_count'] = domain_info['subdomain_count']
        features['suspicious_tld'] = 1 if domain_info['tld'] in self.suspicious_tlds else 0
        features['has_hyphen'] = 1 if '-' in domain_info['domain'] else 0
        
        # Advanced features (offline versions)
        features['domain_age_days'] = self._get_domain_age_offline(domain_info['full_domain'])
        features['is_trusted_domain'] = 1 if self._is_trusted_domain(domain_info) else 0
        features['redirect_count'] = 0  # Skip redirect checking in offline mode
        
        # Content-based features
        features['suspicious_keywords'] = self._check_suspicious_keywords(url)
        features['entropy'] = self._calculate_entropy(url)
        features['is_shortened'] = self._is_shortened_url(url)
        
        return features
    
    def _parse_domain_offline(self, url):
        """Parse domain without external dependencies"""
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc or parsed.path.split('/')[0]
            
            # Simple domain parsing
            parts = hostname.split('.')
            if len(parts) >= 2:
                domain = parts[-2] if len(parts) > 1 else parts[0]
                tld = parts[-1]
                subdomain_count = max(0, len(parts) - 2)
            else:
                domain = hostname
                tld = ''
                subdomain_count = 0
                
            return {
                'domain': domain,
                'tld': tld,
                'subdomain_count': subdomain_count,
                'full_domain': hostname
            }
        except:
            return {'domain': '', 'tld': '', 'subdomain_count': 0, 'full_domain': ''}
    
    def _has_ip_address(self, url):
        """Check if URL contains IP address instead of domain"""
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc or parsed.path.split('/')[0]
            
            # Check for IP address patterns
            ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
            if ip_pattern.search(hostname):
                return 1
            
            # Check if it's a valid IP
            try:
                socket.inet_aton(hostname)
                return 1
            except socket.error:
                return 0
        except:
            return 0
    
    def _count_special_chars(self, url):
        """Count special characters in URL"""
        special_chars = ['@', '!', '$', '%', '&', '*', '+', '=', ';', '?', '-', '_']
        return sum(url.count(char) for char in special_chars)
    
    def _get_domain_age_offline(self, domain):
        """Simulate domain age detection (offline)"""
        # In offline mode, we'll use heuristic based on domain characteristics
        if any(trusted in domain for trusted in self.trusted_domains):
            return 1000  # Trusted domains are considered old
        elif any(tld in domain for tld in self.suspicious_tlds):
            return 5     # Suspicious TLDs are considered new
        else:
            return 100   # Default moderate age
    
    def _is_trusted_domain(self, domain_info):
        """Check if domain is in trusted list"""
        full_domain = domain_info['full_domain']
        return any(trusted in full_domain for trusted in self.trusted_domains)
    
    def _check_suspicious_keywords(self, url):
        """Check for suspicious keywords in URL"""
        suspicious_words = ['login', 'verify', 'account', 'secure', 'update', 'banking', 
                           'paypal', 'ebay', 'amazon', 'apple', 'microsoft', 'confirm',
                           'password', 'validation', 'authenticate', 'security']
        url_lower = url.lower()
        return sum(1 for word in suspicious_words if word in url_lower)
    
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of the URL"""
        if not text:
            return 0
        
        entropy = 0
        for x in set(text):
            p_x = float(text.count(x)) / len(text)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy
    
    def _is_shortened_url(self, url):
        """Check if URL is from a URL shortener"""
        shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly']
        return any(shortener in url for shortener in shorteners)

# Test the URL analyzer
if __name__ == "__main__":
    analyzer = URLAnalyzer()
    test_url = "https://www.google.com/login"
    features = analyzer.extract_features(test_url)
    print("URL Features:", features)
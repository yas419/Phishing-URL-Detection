import re
import urllib.parse
import tldextract
import socket
import ssl
from datetime import datetime
from urllib.request import urlopen
from sklearn.ensemble import RandomForestClassifier
import numpy as np
import joblib
import os

class SimplePhishingDetector:
    def __init__(self):
        """Initialize the phishing detector with a pre-trained model or a basic rule-based system"""
        # Try to load a pre-trained model if available
        self.model_file = "phishing_model.joblib"
        if os.path.exists(self.model_file):
            self.model = joblib.load(self.model_file)
            self.use_ml = True
            print("Loaded pre-trained model")
        else:
            # No model available, use rule-based detection
            self.use_ml = False
            print("Using rule-based detection (no model found)")

    def analyze_url(self, url):
        """Analyze a URL and determine if it's likely a phishing attempt"""
        # Ensure URL has a scheme
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        # Extract features
        features = self._extract_basic_features(url)

        if self.use_ml:
            # Use the model for prediction
            feature_vector = self._convert_features_to_vector(features)
            prediction = self.model.predict([feature_vector])[0]
            probability = self.model.predict_proba([feature_vector])[0][1]

            return {
                'url': url,
                'is_phishing': bool(prediction),
                'confidence': probability,
                'reasons': self._get_risk_factors(features)
            }
        else:
            # Use rule-based system
            is_phishing, score, reasons = self._rule_based_detection(features)

            return {
                'url': url,
                'is_phishing': is_phishing,
                'confidence': score,
                'reasons': reasons
            }

    def _extract_basic_features(self, url):
        """Extract basic features from a URL"""
        features = {}

        # Parse the URL
        parsed_url = urllib.parse.urlparse(url)
        extract_result = tldextract.extract(url)

        # Basic URL information
        features['url'] = url
        features['domain'] = parsed_url.netloc
        features['scheme'] = parsed_url.scheme
        features['path'] = parsed_url.path
        features['query'] = parsed_url.query
        features['subdomain'] = extract_result.subdomain
        features['registered_domain'] = extract_result.registered_domain
        features['tld'] = extract_result.suffix

        # Basic URL properties
        features['url_length'] = len(url)
        features['domain_length'] = len(parsed_url.netloc)
        features['path_length'] = len(parsed_url.path)
        features['query_length'] = len(parsed_url.query)
        features['subdomain_count'] = len(extract_result.subdomain.split('.')) if extract_result.subdomain else 0

        # Suspicious character patterns
        features['has_ip_address'] = 1 if self._has_ip_address(url) else 0
        features['has_at_symbol'] = 1 if '@' in url else 0
        features['has_double_slash'] = 1 if '//' in parsed_url.path else 0
        features['has_hex_chars'] = 1 if re.search(r'%[0-9a-fA-F]{2}', url) else 0
        features['has_https'] = 1 if parsed_url.scheme == 'https' else 0

        # Count special characters
        features['hyphen_count'] = url.count('-')
        features['underscore_count'] = url.count('_')
        features['slash_count'] = url.count('/')
        features['dot_count'] = url.count('.')
        features['equal_count'] = url.count('=')
        features['question_mark_count'] = url.count('?')
        features['ampersand_count'] = url.count('&')
        features['percent_count'] = url.count('%')

        # Check for brand names in domain (common in phishing)
        common_brands = ['paypal', 'apple', 'amazon', 'microsoft', 'google', 'facebook',
                         'ebay', 'instagram', 'chase', 'bank', 'netflix', 'linkedin',
                         'twitter', 'yahoo', 'blockchain', 'coinbase', 'gmail']

        for brand in common_brands:
            if brand in parsed_url.netloc.lower() and brand not in extract_result.domain.lower():
                features['brand_in_subdomain'] = 1
                features['targeted_brand'] = brand
                break
        else:
            features['brand_in_subdomain'] = 0
            features['targeted_brand'] = None

        # Try to check domain age (simplified)
        features['domain_exists'] = self._check_domain_exists(parsed_url.netloc)

        # Check for SSL certificate (simplified)
        if parsed_url.scheme == 'https':
            features['ssl_valid'] = self._check_ssl(parsed_url.netloc)
        else:
            features['ssl_valid'] = 0

        return features

    def _has_ip_address(self, url):
        """Check if the URL contains an IP address"""
        pattern = re.compile(r'(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])')
        return bool(pattern.search(url))

    def _check_domain_exists(self, domain):
        """Check if a domain resolves to an IP address"""
        try:
            socket.gethostbyname(domain)
            return 1
        except:
            return 0

    def _check_ssl(self, domain):
        """Check if SSL certificate is valid"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    return 1
        except:
            return 0

    def _rule_based_detection(self, features):
        """Simple rule-based phishing detection"""
        risk_score = 0
        reasons = []

        # Check URL length (phishing URLs are often long)
        if features['url_length'] > 100:
            risk_score += 0.1
            reasons.append("Unusually long URL")

        # Check for IP address in URL
        if features['has_ip_address']:
            risk_score += 0.2
            reasons.append("Contains IP address instead of domain name")

        # Check for @, // symbols
        if features['has_at_symbol']:
            risk_score += 0.2
            reasons.append("Contains @ symbol")

        if features['has_double_slash']:
            risk_score += 0.1
            reasons.append("Contains // in the path")

        # Check for hexadecimal characters
        if features['has_hex_chars']:
            risk_score += 0.1
            reasons.append("Contains hexadecimal character codes")

        # Check for HTTPS
        if not features['has_https']:
            risk_score += 0.15
            reasons.append("Not using HTTPS")

        # Check domain
        if not features['domain_exists']:
            risk_score += 0.2
            reasons.append("Domain does not resolve to an IP address")

        # Check SSL certificate
        if features['has_https'] and not features['ssl_valid']:
            risk_score += 0.2
            reasons.append("Invalid SSL certificate")

        # Check for brand names in domain
        if features['brand_in_subdomain']:
            risk_score += 0.2
            reasons.append(f"Contains brand name '{features['targeted_brand']}' but not in main domain")

        # Check for suspicious TLD
        suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz']
        if features['tld'] in suspicious_tlds:
            risk_score += 0.1
            reasons.append(f"Uses suspicious TLD: .{features['tld']}")

        # Too many subdomains
        if features['subdomain_count'] > 3:
            risk_score += 0.1
            reasons.append("Excessive number of subdomains")

        # Too many special characters
        special_char_count = (features['hyphen_count'] + features['underscore_count'] +
                              features['percent_count'])
        if special_char_count > 10:
            risk_score += 0.1
            reasons.append("Excessive special characters")

        # Determine if it's likely phishing based on score
        is_phishing = risk_score >= 0.3

        return is_phishing, risk_score, reasons

    def _convert_features_to_vector(self, features):
        """Convert features dictionary to a vector for ML model input"""
        # This is a simplified version - a real implementation would match the training features
        return [
            features['url_length'],
            features['domain_length'],
            features['path_length'],
            features['query_length'],
            features['subdomain_count'],
            features['has_ip_address'],
            features['has_at_symbol'],
            features['has_double_slash'],
            features['has_hex_chars'],
            features['has_https'],
            features['hyphen_count'],
            features['underscore_count'],
            features['slash_count'],
            features['dot_count'],
            features['equal_count'],
            features['question_mark_count'],
            features['ampersand_count'],
            features['percent_count'],
            features['brand_in_subdomain'],
            features['domain_exists'],
            features['ssl_valid']
        ]

    def _get_risk_factors(self, features):
        """Get risk factors based on features (for ML-based detection)"""
        reasons = []

        if features['has_ip_address']:
            reasons.append("Contains IP address instead of domain name")

        if features['has_at_symbol']:
            reasons.append("Contains @ symbol")

        if features['has_double_slash']:
            reasons.append("Contains // in the path")

        if features['has_hex_chars']:
            reasons.append("Contains hexadecimal character codes")

        if not features['has_https']:
            reasons.append("Not using HTTPS")

        if not features['domain_exists']:
            reasons.append("Domain does not resolve to an IP address")

        if features['has_https'] and not features['ssl_valid']:
            reasons.append("Invalid SSL certificate")

        if features['brand_in_subdomain']:
            reasons.append(f"Contains brand name '{features['targeted_brand']}' but not in main domain")

        if features['url_length'] > 100:
            reasons.append("Unusually long URL")

        return reasons

def main():
    """Main function to run the phishing detector from command line"""
    print("\n===== Simple Phishing URL Detector =====\n")

    detector = SimplePhishingDetector()

    while True:
        url = input("\nEnter a URL to check (or 'exit' to quit): ")

        if url.lower() in ['exit', 'quit', 'q']:
            break

        if not url:
            continue

        print("\nAnalyzing URL...")
        result = detector.analyze_url(url)

        print("\n----- Analysis Results -----")
        print(f"URL: {result['url']}")

        if result['is_phishing']:
            print("\n⚠️  WARNING: This URL appears to be FRAUDULENT ⚠️")
            print(f"Confidence: {result['confidence']:.2f}")

            if result['reasons']:
                print("\nSuspicious characteristics:")
                for i, reason in enumerate(result['reasons'], 1):
                    print(f"  {i}. {reason}")
        else:
            print("\n✓ This URL appears to be LEGITIMATE")
            print(f"Confidence: {1-result['confidence']:.2f}")

            if result['reasons']:
                print("\nNote: The following minor issues were detected:")
                for i, reason in enumerate(result['reasons'], 1):
                    print(f"  {i}. {reason}")

        print("\n-----------------------------")

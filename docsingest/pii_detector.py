import re
import spacy

class PIIDetector:
    def __init__(self):
        try:
            self.nlp = spacy.load("en_core_web_sm")
        except OSError:
            raise ImportError("SpaCy English model not found. Install with 'python -m spacy download en_core_web_sm'")

    def detect_pii(self, text):
        """
        Detect Personally Identifiable Information (PII) in text
        
        Args:
            text (str): Input text to scan for PII
        
        Returns:
            dict: Detected PII categories and their matches
        """
        doc = self.nlp(text)
        pii_results = {
            'names': [],
            'emails': [],
            'phone_numbers': [],
            'ssn': [],
            'credit_cards': []
        }

        # Named Entities
        for ent in doc.ents:
            if ent.label_ in ['PERSON']:
                pii_results['names'].append(ent.text)

        # Email Regex
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        pii_results['emails'] = re.findall(email_pattern, text)

        # Phone Number Regex
        phone_pattern = r'\b(\+\d{1,2}\s?)?(\d{3}[-.]?)?\s?\d{3}[-.]?\d{4}\b'
        pii_results['phone_numbers'] = re.findall(phone_pattern, text)

        # SSN Regex
        ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
        pii_results['ssn'] = re.findall(ssn_pattern, text)

        # Credit Card Regex
        cc_pattern = r'\b(?:\d{4}[-\s]?){3}\d{4}\b'
        pii_results['credit_cards'] = re.findall(cc_pattern, text)

        return {k: v for k, v in pii_results.items() if v}

    def redact_pii(self, text):
        """
        Redact detected PII from text
        
        Args:
            text (str): Input text to redact
        
        Returns:
            str: Text with PII redacted
        """
        pii_matches = self.detect_pii(text)
        
        for category, matches in pii_matches.items():
            for match in matches:
                text = text.replace(match, f'[{category.upper()} REDACTED]')
        
        return text

def analyze_document_compliance(document_path):
    """
    Comprehensive document compliance analysis
    
    Args:
        document_path (str): Path to document for compliance check
    
    Returns:
        dict: Compliance analysis results
    """
    with open(document_path, 'r', encoding='utf-8') as f:
        text = f.read()
    
    detector = PIIDetector()
    pii_detection = detector.detect_pii(text)
    
    compliance_report = {
        'pii_detected': bool(pii_detection),
        'pii_details': pii_detection,
        'risk_score': len(pii_detection) * 10,  # Basic risk scoring
        'recommended_actions': []
    }
    
    if pii_detection:
        compliance_report['recommended_actions'] = [
            'Review document for sensitive information',
            'Consider data anonymization',
            'Ensure GDPR and CCPA compliance'
        ]
    
    return compliance_report

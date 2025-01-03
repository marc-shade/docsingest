import pytest
from docsingest.pii_detector import PIIDetector, analyze_document_compliance
import os
import tempfile

class TestPIIDetector:
    @pytest.fixture
    def pii_detector(self):
        return PIIDetector()

    def test_detect_email(self, pii_detector):
        text = "Contact John at john.doe@example.com for details."
        results = pii_detector.detect_pii(text)
        assert 'emails' in results
        assert 'john.doe@example.com' in results['emails']

    def test_detect_phone_number(self, pii_detector):
        text = "Call me at 555-123-4567 or 1-800-EXAMPLE."
        results = pii_detector.detect_pii(text)
        assert 'phone_numbers' in results
        assert any('555-123-4567' in num for num in results['phone_numbers'])

    def test_detect_ssn(self, pii_detector):
        text = "SSN: 123-45-6789 is confidential."
        results = pii_detector.detect_pii(text)
        assert 'ssn' in results
        assert '123-45-6789' in results['ssn']

    def test_detect_credit_card(self, pii_detector):
        text = "Credit card: 4111-1111-1111-1111 for payment."
        results = pii_detector.detect_pii(text)
        assert 'credit_cards' in results
        assert '4111-1111-1111-1111' in results['credit_cards']

    def test_redact_pii(self, pii_detector):
        text = "John Doe's email is john.doe@example.com and SSN is 123-45-6789."
        redacted_text = pii_detector.redact_pii(text)
        assert '[EMAILS REDACTED]' in redacted_text
        assert '[SSN REDACTED]' in redacted_text

    def test_analyze_document_compliance():
        # Create a temporary file with PII
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            temp_file.write("John Doe's email is john.doe@example.com and SSN is 123-45-6789.")
            temp_file_path = temp_file.name

        try:
            # Analyze the document
            compliance_report = analyze_document_compliance(temp_file_path)

            # Assertions
            assert 'pii_detected' in compliance_report
            assert compliance_report['pii_detected'] is True
            assert 'pii_details' in compliance_report
            assert 'risk_score' in compliance_report
            assert 'recommended_actions' in compliance_report
            assert len(compliance_report['recommended_actions']) > 0

        finally:
            # Clean up the temporary file
            os.unlink(temp_file_path)

    def test_no_pii_detection(self, pii_detector):
        text = "This is a document with no personal information."
        results = pii_detector.detect_pii(text)
        assert len(results) == 0

# Ensure SpaCy model is loaded
def test_spacy_model_loaded():
    try:
        import spacy
        nlp = spacy.load("en_core_web_sm")
        assert nlp is not None
    except Exception as e:
        pytest.fail(f"Failed to load SpaCy model: {e}")

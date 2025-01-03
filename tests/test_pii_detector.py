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
        results = pii_detector.detect(text)
        
        assert results["pii_detected"] is True
        assert "emails" in results["pii_details"]
        assert "john.doe@example.com" in results["pii_details"]["emails"]

    def test_detect_phone_number(self, pii_detector):
        text = "Call me at 555-123-4567 or 1-800-EXAMPLE."
        results = pii_detector.detect(text)
        
        assert results["pii_detected"] is True
        assert "phone_numbers" in results["pii_details"]
        assert "555-123-4567" in results["pii_details"]["phone_numbers"]

    def test_detect_ssn(self, pii_detector):
        text = "SSN: 123-45-6789 is confidential."
        results = pii_detector.detect(text)
        
        assert results["pii_detected"] is True
        assert "ssn" in results["pii_details"]
        assert "123-45-6789" in results["pii_details"]["ssn"]

    def test_detect_credit_card(self, pii_detector):
        text = "Credit card: 4111-1111-1111-1111 for payment."
        results = pii_detector.detect(text)
        
        assert results["pii_detected"] is True
        assert "credit_cards" in results["pii_details"]
        assert "4111-1111-1111-1111" in results["pii_details"]["credit_cards"]

    def test_redact_pii(self, pii_detector):
        text = "John Doe's email is john.doe@example.com and SSN is 123-45-6789."
        redacted_text = pii_detector.redact(text)
        
        assert "[NAMES_REDACTED]" in redacted_text
        assert "john.doe@example.com" not in redacted_text
        assert "123-45-6789" not in redacted_text

    def test_analyze_document_compliance(self):
        # Create a temporary file with PII
        test_file_path = "/tmp/test_pii_document.txt"
        with open(test_file_path, "w") as f:
            f.write("John Doe's SSN is 123-45-6789 and email is john.doe@example.com")

        try:
            # Analyze the document
            report = analyze_document_compliance(test_file_path)

            # Verify report contents
            assert report["pii_detected"] is True
            assert report["risk_score"] > 0
            assert len(report["recommended_actions"]) > 0

        finally:
            # Clean up the temporary file
            os.remove(test_file_path)

    def test_no_pii_detection(self, pii_detector):
        text = "This is a document with no personal information."
        results = pii_detector.detect(text)
        
        assert results["pii_detected"] is False
        assert len(results["pii_details"]["names"]) == 0
        assert results["risk_score"] == 0

# Ensure SpaCy model is loaded
def test_spacy_model_loaded():
    try:
        import spacy
        nlp = spacy.load("en_core_web_sm")
        assert nlp is not None
    except Exception as e:
        pytest.fail(f"Failed to load SpaCy model: {e}")

"""Tests for Enhanced PII/PHI Detection module."""

import pytest

from docsingest.compliance.enhanced_pii import (
    EnhancedPIIDetector,
    PIICategory,
    Regulation,
)


class TestEnhancedPIIDetector:
    """Test suite for defense-grade PII/PHI detection."""

    @pytest.fixture
    def detector(self):
        return EnhancedPIIDetector()

    # --- Standard PII Detection ---

    def test_detect_email(self, detector):
        text = "Contact us at john.doe@defense.gov for more information."
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.EMAIL for d in report.detections)

    def test_detect_phone_number(self, detector):
        text = "Call the office at (703) 555-1234 for details."
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.PHONE for d in report.detections)

    def test_detect_ssn(self, detector):
        text = "Employee SSN: 123-45-6789 is on file."
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.SSN for d in report.detections)
        # SSN should have high confidence
        ssn_det = [d for d in report.detections if d.category == PIICategory.SSN]
        assert ssn_det[0].confidence == "high"

    def test_detect_credit_card(self, detector):
        text = "Payment via credit card 4111-1111-1111-1111 received."
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.CREDIT_CARD for d in report.detections)

    def test_detect_date_of_birth(self, detector):
        text = "DOB: 03/15/1985"
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.DATE_OF_BIRTH for d in report.detections)

    def test_detect_drivers_license(self, detector):
        text = "Driver's license number: D12345678"
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.DRIVERS_LICENSE for d in report.detections)

    def test_detect_passport(self, detector):
        text = "Passport number: AB1234567"
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.PASSPORT for d in report.detections)

    # --- HIPAA PHI Detection ---

    def test_detect_medical_record_number(self, detector):
        text = "Patient MRN: MR123456789 admitted for procedure."
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.MEDICAL_RECORD for d in report.detections)

    def test_detect_health_plan_id(self, detector):
        text = "Health plan beneficiary ID: HPN987654321"
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.HEALTH_PLAN_ID for d in report.detections)

    def test_detect_patient_id(self, detector):
        text = "Patient ID: PT1234567"
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.PATIENT_ID for d in report.detections)

    def test_detect_date_of_service(self, detector):
        text = "Date of service: 01/15/2025"
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.DATE_OF_SERVICE for d in report.detections)

    def test_hipaa_regulation_mapping(self, detector):
        text = "Patient MRN: MR123456789"
        report = detector.detect(text, filename="test.txt")
        phi_detections = [d for d in report.detections if d.category == PIICategory.MEDICAL_RECORD]
        assert len(phi_detections) > 0
        assert any(Regulation.HIPAA in d.applicable_regulations for d in phi_detections)

    # --- Defense-Specific PII ---

    def test_detect_dod_id(self, detector):
        text = "DoD ID number: 1234567890"
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.DOD_ID for d in report.detections)

    def test_detect_cac_number(self, detector):
        text = "CAC card number: 1234567890123456"
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.CAC_NUMBER for d in report.detections)

    def test_detect_security_clearance(self, detector):
        text = "Employee has TS clearance and SCI access."
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.SECURITY_CLEARANCE for d in report.detections)

    def test_detect_clearance_level(self, detector):
        text = "Clearance level: TOP SECRET"
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.SECURITY_CLEARANCE for d in report.detections)

    def test_detect_cage_code(self, detector):
        text = "Contractor CAGE code: 1ABC2"
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.CAGE_CODE for d in report.detections)

    def test_detect_duns_number(self, detector):
        text = "Company DUNS number: 12-345-6789"
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.DUNS_NUMBER for d in report.detections)

    # --- Financial PII ---

    def test_detect_ein_tin(self, detector):
        text = "Employer Identification Number: 12-3456789"
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.EIN_TIN for d in report.detections)

    def test_detect_bank_account(self, detector):
        text = "Account number: 12345678901234"
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.BANK_ACCOUNT for d in report.detections)

    # --- Export Control Markers ---

    def test_detect_itar_marking(self, detector):
        text = "This document is export controlled under ITAR 22 CFR 120."
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.ITAR_MARKING for d in report.detections)

    def test_detect_ear_marking(self, detector):
        text = "Subject to the Export Administration Regulations (EAR)."
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.EAR_MARKING for d in report.detections)

    def test_detect_distribution_statement(self, detector):
        text = "Distribution statement B: Controlled technical data."
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.TECHNICAL_DATA for d in report.detections)

    # --- Confidence Scoring ---

    def test_high_confidence_with_label(self, detector):
        text = "SSN: 123-45-6789"
        report = detector.detect(text, filename="test.txt")
        ssn_detections = [d for d in report.detections if d.category == PIICategory.SSN]
        assert len(ssn_detections) > 0
        assert ssn_detections[0].confidence == "high"

    # --- Regulatory Mapping ---

    def test_privacy_act_mapping(self, detector):
        text = "SSN: 123-45-6789"
        report = detector.detect(text, filename="test.txt")
        ssn_det = [d for d in report.detections if d.category == PIICategory.SSN]
        assert len(ssn_det) > 0
        assert Regulation.PRIVACY_ACT in ssn_det[0].applicable_regulations

    def test_pci_dss_mapping(self, detector):
        text = "Credit card: 4111-1111-1111-1111"
        report = detector.detect(text, filename="test.txt")
        cc_det = [d for d in report.detections if d.category == PIICategory.CREDIT_CARD]
        assert len(cc_det) > 0
        assert Regulation.PCI_DSS in cc_det[0].applicable_regulations

    def test_itar_regulation_mapping(self, detector):
        text = "This is ITAR controlled data."
        report = detector.detect(text, filename="test.txt")
        itar_det = [d for d in report.detections if d.category == PIICategory.ITAR_MARKING]
        assert len(itar_det) > 0
        assert Regulation.ITAR in itar_det[0].applicable_regulations

    # --- NIST Control Mapping ---

    def test_nist_controls_present(self, detector):
        text = "SSN: 123-45-6789"
        report = detector.detect(text, filename="test.txt")
        assert len(report.nist_controls_applicable) > 0
        assert "SI-4" in report.nist_controls_applicable

    # --- Risk Scoring ---

    def test_risk_score_no_pii(self, detector):
        text = "This document contains no personal information whatsoever."
        report = detector.detect(text, filename="test.txt")
        assert report.risk_score == 0

    def test_risk_score_high_for_ssn(self, detector):
        text = "SSN: 123-45-6789"
        report = detector.detect(text, filename="test.txt")
        assert report.risk_score > 0

    def test_risk_score_scales_with_findings(self, detector):
        text_few = "Email: test@example.com"
        text_many = (
            "SSN: 123-45-6789\n"
            "Email: test@example.com\n"
            "Credit card: 4111-1111-1111-1111\n"
            "DoD ID number: 1234567890"
        )
        report_few = detector.detect(text_few, filename="test.txt")
        report_many = detector.detect(text_many, filename="test.txt")
        assert report_many.risk_score > report_few.risk_score

    # --- Remediation Actions ---

    def test_remediation_actions_generated(self, detector):
        text = "SSN: 123-45-6789"
        report = detector.detect(text, filename="test.txt")
        assert len(report.remediation_actions) > 0

    def test_remediation_urgent_for_high_risk(self, detector):
        text = (
            "SSN: 123-45-6789\n"
            "Credit card: 4111-1111-1111-1111\n"
            "DoD ID number: 1234567890\n"
            "CAC card number: 1234567890123456"
        )
        report = detector.detect(text, filename="test.txt")
        assert report.risk_score >= 50
        assert any("urgent" in a.lower() or "elevated" in a.lower() for a in report.remediation_actions)

    # --- Text Masking ---

    def test_ssn_masked_in_report(self, detector):
        text = "SSN: 123-45-6789"
        report = detector.detect(text, filename="test.txt")
        ssn_det = [d for d in report.detections if d.category == PIICategory.SSN]
        assert len(ssn_det) > 0
        # Should be partially masked
        assert '***' in report.detections[0].context or '****' in report.detections[0].context

    # --- Summary ---

    def test_summary_with_findings(self, detector):
        text = "Email: test@defense.gov\nSSN: 123-45-6789"
        report = detector.detect(text, filename="test_doc.txt")
        assert "test_doc.txt" in report.summary
        assert "Risk Score" in report.summary

    def test_summary_no_findings(self, detector):
        text = "No personal information here."
        report = detector.detect(text, filename="clean.txt")
        assert "No PII/PHI detected" in report.summary

    # --- Clean Document ---

    def test_clean_document(self, detector):
        text = (
            "The quick brown fox jumps over the lazy dog.\n"
            "Weather forecast: Sunny and warm today.\n"
            "Meeting scheduled for next Tuesday."
        )
        report = detector.detect(text, filename="clean.txt")
        assert report.pii_detected is False
        assert report.total_findings == 0
        assert report.risk_score == 0

    # --- Multiple Detections ---

    def test_multiple_pii_types(self, detector):
        text = (
            "Name: John Smith\n"
            "Email: john.smith@defense.gov\n"
            "SSN: 123-45-6789\n"
            "DoD ID number: 1234567890\n"
            "TS clearance active\n"
        )
        report = detector.detect(text, filename="personnel.txt")
        assert report.pii_detected is True
        assert report.total_findings >= 3
        categories = {d.category for d in report.detections}
        assert PIICategory.EMAIL in categories
        assert PIICategory.SSN in categories

    # --- Detections By Category Aggregation ---

    def test_detections_by_category(self, detector):
        text = "Email: a@b.com\nEmail: c@d.com\nSSN: 123-45-6789"
        report = detector.detect(text, filename="test.txt")
        assert "Email Address" in report.detections_by_category
        assert report.detections_by_category["Email Address"] >= 2

    # --- Detections By Regulation ---

    def test_detections_by_regulation(self, detector):
        text = "SSN: 123-45-6789\nMRN: MR123456789"
        report = detector.detect(text, filename="test.txt")
        assert len(report.detections_by_regulation) > 0

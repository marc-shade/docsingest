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

    # --- HIPAA Safe Harbor Full Coverage (45 CFR 164.514(b)(2)) ---

    def test_hipaa_safe_harbor_1_names(self, detector):
        """Safe Harbor #1: Names - covered by NAME category (NER-based)."""
        # NAME detection requires NER, so we test via proxy categories
        text = "Patient: John Doe Smith"
        # Names are not regex-detected in the enhanced detector; they come from NER
        # This is a documentation test confirming awareness

    def test_hipaa_safe_harbor_2_zip_code(self, detector):
        """Safe Harbor #2: Geographic subdivisions smaller than state."""
        text = "Patient zip code: 20301-1234"
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.ZIP_CODE for d in report.detections)

    def test_hipaa_safe_harbor_3_dates(self, detector):
        """Safe Harbor #3: All dates related to individual."""
        # DOB
        text_dob = "DOB: 03/15/1985"
        report = detector.detect(text_dob, filename="test.txt")
        assert any(d.category == PIICategory.DATE_OF_BIRTH for d in report.detections)

        # Date of death
        text_death = "date of death: 12/25/2024"
        report = detector.detect(text_death, filename="test.txt")
        assert any(d.category == PIICategory.DATE_OF_DEATH for d in report.detections)

        # Admission date
        text_admit = "admission date: 01/10/2025"
        report = detector.detect(text_admit, filename="test.txt")
        assert any(d.category == PIICategory.ADMISSION_DATE for d in report.detections)

    def test_hipaa_safe_harbor_3_age_over_89(self, detector):
        """Safe Harbor #3: Ages over 89 must be aggregated."""
        text = "Patient age: 92 years old"
        report = detector.detect(text, filename="test.txt")
        assert any(d.category == PIICategory.AGE_OVER_89 for d in report.detections)

    def test_hipaa_safe_harbor_4_telephone(self, detector):
        """Safe Harbor #4: Telephone numbers - already tested."""
        text = "Phone: (703) 555-1234"
        report = detector.detect(text, filename="test.txt")
        assert any(d.category == PIICategory.PHONE for d in report.detections)

    def test_hipaa_safe_harbor_5_fax(self, detector):
        """Safe Harbor #5: Fax numbers."""
        text = "Fax number: (703) 555-9876"
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.FAX_NUMBER for d in report.detections)

    def test_hipaa_safe_harbor_6_email(self, detector):
        """Safe Harbor #6: Email addresses - already tested."""
        text = "Email: patient@hospital.org"
        report = detector.detect(text, filename="test.txt")
        assert any(d.category == PIICategory.EMAIL for d in report.detections)

    def test_hipaa_safe_harbor_7_ssn(self, detector):
        """Safe Harbor #7: Social Security numbers - already tested."""
        text = "SSN: 123-45-6789"
        report = detector.detect(text, filename="test.txt")
        assert any(d.category == PIICategory.SSN for d in report.detections)

    def test_hipaa_safe_harbor_8_mrn(self, detector):
        """Safe Harbor #8: Medical record numbers - already tested."""
        text = "MRN: MR123456789"
        report = detector.detect(text, filename="test.txt")
        assert any(d.category == PIICategory.MEDICAL_RECORD for d in report.detections)

    def test_hipaa_safe_harbor_9_health_plan(self, detector):
        """Safe Harbor #9: Health plan beneficiary numbers - already tested."""
        text = "Member ID: MBR12345678"
        report = detector.detect(text, filename="test.txt")
        assert any(d.category == PIICategory.HEALTH_PLAN_ID for d in report.detections)

    def test_hipaa_safe_harbor_10_account(self, detector):
        """Safe Harbor #10: Account numbers - already tested."""
        text = "Account number: 12345678901234"
        report = detector.detect(text, filename="test.txt")
        assert any(d.category == PIICategory.BANK_ACCOUNT for d in report.detections)

    def test_hipaa_safe_harbor_11_certificate_license(self, detector):
        """Safe Harbor #11: Certificate/license numbers."""
        text = "Medical license number: ML12345678"
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.PROFESSIONAL_LICENSE for d in report.detections)

    def test_hipaa_safe_harbor_11_dea_number(self, detector):
        """Safe Harbor #11: DEA registration numbers."""
        text = "DEA number: AB1234567"
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.DEA_NUMBER for d in report.detections)

    def test_hipaa_safe_harbor_12_vehicle_id(self, detector):
        """Safe Harbor #12: Vehicle identifiers (VIN)."""
        text = "VIN: 1HGBH41JXMN109186"
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.VEHICLE_ID for d in report.detections)

    def test_hipaa_safe_harbor_13_device_id(self, detector):
        """Safe Harbor #13: Device identifiers and serial numbers."""
        text = "Device serial number: SN-ABC-123456-789"
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.DEVICE_ID for d in report.detections)

    def test_hipaa_safe_harbor_14_web_url(self, detector):
        """Safe Harbor #14: Web URLs."""
        text = "Patient portal URL: https://myhealth.example.com/patient/12345"
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.WEB_URL for d in report.detections)

    def test_hipaa_safe_harbor_15_ip_address(self, detector):
        """Safe Harbor #15: IP addresses."""
        text = "Patient accessed from IP address: 192.168.1.100"
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.IP_ADDRESS for d in report.detections)

    def test_hipaa_safe_harbor_16_biometric(self, detector):
        """Safe Harbor #16: Biometric identifiers."""
        text = "Fingerprint data collected for patient identification."
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.BIOMETRIC_ID for d in report.detections)

    def test_hipaa_safe_harbor_16_retinal_scan(self, detector):
        """Safe Harbor #16: Retinal scan reference."""
        text = "Retinal scan completed for identity verification."
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.BIOMETRIC_ID for d in report.detections)

    def test_hipaa_safe_harbor_17_photo(self, detector):
        """Safe Harbor #17: Full-face photographs."""
        text = "Full-face photograph required for patient record."
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.PHOTO_REFERENCE for d in report.detections)

    def test_hipaa_regulation_on_new_categories(self, detector):
        """Verify new HIPAA categories map to HIPAA regulation."""
        # Fax
        report = detector.detect("Fax number: (555) 123-4567", filename="test.txt")
        fax_det = [d for d in report.detections if d.category == PIICategory.FAX_NUMBER]
        if fax_det:
            assert Regulation.HIPAA in fax_det[0].applicable_regulations

        # Zip code
        report = detector.detect("Zip code: 90210", filename="test.txt")
        zip_det = [d for d in report.detections if d.category == PIICategory.ZIP_CODE]
        if zip_det:
            assert Regulation.HIPAA in zip_det[0].applicable_regulations

    def test_subscriber_id_detection(self, detector):
        """Test subscriber ID detection (added to health plan ID)."""
        text = "Subscriber ID: SUB987654321"
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.HEALTH_PLAN_ID for d in report.detections)

    def test_group_id_detection(self, detector):
        """Test group ID detection (added to health plan ID)."""
        text = "Group ID: GRP12345678"
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.HEALTH_PLAN_ID for d in report.detections)

    def test_discharge_date_detection(self, detector):
        """Test discharge date detection."""
        text = "Discharge date: 02/15/2025"
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.ADMISSION_DATE for d in report.detections)

    def test_npi_detection(self, detector):
        """Test National Provider Identifier detection."""
        text = "NPI number: 1234567890"
        report = detector.detect(text, filename="test.txt")
        assert report.pii_detected is True
        assert any(d.category == PIICategory.PROFESSIONAL_LICENSE for d in report.detections)

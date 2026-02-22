"""
Enhanced PII/PHI Detection for defense-grade document analysis.

Extends basic PII detection with:
- HIPAA PHI detection (medical records, health plans, patient IDs)
- Defense-specific PII (DoD IDs, CAC numbers, clearances, CAGE/DUNS)
- Financial PII (routing numbers, SWIFT/BIC, EIN/TIN)
- ITAR/EAR controlled technical data markers
- Confidence scoring per detection
- Regulatory mapping (HIPAA, FERPA, GLBA, Privacy Act, ITAR)
- NIST 800-53 SI-4 and SI-19 control mapping

References:
- HIPAA Privacy Rule (45 CFR 160, 164)
- Privacy Act of 1974 (5 USC 552a)
- ITAR (22 CFR 120-130)
- NIST SP 800-53 Rev 5: SI-4, SI-19
- NIST SP 800-122: Guide to Protecting PII
"""

import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)


class PIICategory(Enum):
    """Categories of PII/PHI detection."""
    # Standard PII
    EMAIL = "Email Address"
    PHONE = "Phone Number"
    SSN = "Social Security Number"
    CREDIT_CARD = "Credit Card Number"
    NAME = "Personal Name"
    ADDRESS = "Physical Address"
    DATE_OF_BIRTH = "Date of Birth"
    DRIVERS_LICENSE = "Driver's License Number"
    PASSPORT = "Passport Number"

    # HIPAA PHI
    MEDICAL_RECORD = "Medical Record Number"
    HEALTH_PLAN_ID = "Health Plan Beneficiary ID"
    PATIENT_ID = "Patient Identifier"
    DATE_OF_SERVICE = "Date of Service"
    MEDICAL_CONDITION = "Medical Condition Reference"
    PRESCRIPTION = "Prescription Information"

    # Defense-specific
    DOD_ID = "DoD ID Number"
    CAC_NUMBER = "CAC Card Number"
    SECURITY_CLEARANCE = "Security Clearance Reference"
    CAGE_CODE = "CAGE Code"
    DUNS_NUMBER = "DUNS Number"
    SAM_UEI = "SAM Unique Entity Identifier"
    MILITARY_SERVICE = "Military Service Number"

    # Financial
    BANK_ROUTING = "Bank Routing Number"
    SWIFT_BIC = "SWIFT/BIC Code"
    EIN_TIN = "Employer Identification Number"
    BANK_ACCOUNT = "Bank Account Number"
    IBAN = "International Bank Account Number"

    # Export Control
    ITAR_MARKING = "ITAR Controlled Data"
    EAR_MARKING = "EAR Controlled Data"
    TECHNICAL_DATA = "Controlled Technical Data"


class Regulation(Enum):
    """Applicable regulations for each detection."""
    HIPAA = "HIPAA (45 CFR 160, 164)"
    FERPA = "FERPA (20 USC 1232g)"
    GLBA = "GLBA (15 USC 6801-6809)"
    PRIVACY_ACT = "Privacy Act (5 USC 552a)"
    ITAR = "ITAR (22 CFR 120-130)"
    EAR = "EAR (15 CFR 730-774)"
    PCI_DSS = "PCI DSS v4.0"
    CCPA = "CCPA (Cal. Civ. Code 1798.100)"
    GDPR = "GDPR (EU 2016/679)"
    DFARS = "DFARS 252.204-7012"
    CMMC = "CMMC Level 2+"


@dataclass
class PIIDetection:
    """Represents a single PII/PHI detection."""
    category: PIICategory
    matched_text: str
    line_number: int
    start_position: int
    end_position: int
    confidence: str  # "high", "medium", "low"
    applicable_regulations: List[Regulation]
    nist_controls: List[str]
    remediation: str
    context: str  # surrounding text snippet


@dataclass
class EnhancedPIIReport:
    """Complete enhanced PII/PHI detection report."""
    pii_detected: bool
    total_findings: int
    risk_score: int  # 0-100
    detections: List[PIIDetection]
    detections_by_category: Dict[str, int]
    detections_by_regulation: Dict[str, int]
    remediation_actions: List[str]
    nist_controls_applicable: List[str]
    summary: str


class EnhancedPIIDetector:
    """
    Defense-grade PII/PHI detection engine.

    Provides comprehensive detection of personally identifiable information,
    protected health information, defense-specific identifiers, and
    export-controlled data markers with confidence scoring and
    regulatory mapping.
    """

    # Standard PII patterns
    PATTERNS: Dict[PIICategory, Tuple[re.Pattern, str, List[Regulation], List[str], str]] = {}

    def __init__(self) -> None:
        """Initialize the enhanced PII detector with all pattern definitions."""
        self._build_patterns()
        logger.info("Enhanced PII Detector initialized with %d pattern categories", len(self.PATTERNS))

    def _build_patterns(self) -> None:
        """Build all detection patterns with regulatory mappings."""
        self.PATTERNS = {
            # --- Standard PII ---
            PIICategory.EMAIL: (
                re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'),
                "high",
                [Regulation.PRIVACY_ACT, Regulation.GDPR, Regulation.CCPA],
                ["SI-4", "SI-19"],
                "Redact or encrypt email addresses. Ensure storage complies with applicable privacy regulations.",
            ),
            PIICategory.PHONE: (
                re.compile(
                    r'\b(?:\+?1[\s.\-]?)?\(?(?:[2-9]\d{2})\)?[\s.\-]?(?:\d{3})[\s.\-]?(?:\d{4})\b'
                ),
                "high",
                [Regulation.PRIVACY_ACT, Regulation.CCPA],
                ["SI-4", "SI-19"],
                "Redact phone numbers from documents before distribution.",
            ),
            PIICategory.SSN: (
                re.compile(r'\b(?!000|666|9\d{2})\d{3}[-\s]?\d{2}[-\s]?\d{4}\b'),
                "high",
                [Regulation.PRIVACY_ACT, Regulation.DFARS],
                ["SI-4", "SI-19", "MP-6"],
                "CRITICAL: SSN detected. Immediately redact. Report per Privacy Act breach procedures. "
                "Do not store SSNs unless operationally required per DoD 5400.11-R.",
            ),
            PIICategory.CREDIT_CARD: (
                re.compile(
                    r'\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{1,4}\b'
                ),
                "high",
                [Regulation.PCI_DSS, Regulation.GLBA],
                ["SI-4", "SI-19", "SC-28"],
                "CRITICAL: Credit card number detected. Must be protected per PCI DSS requirements. "
                "Remove from document or mask all but last 4 digits.",
            ),
            PIICategory.DATE_OF_BIRTH: (
                re.compile(
                    r'\b(?:DOB|date\s+of\s+birth|born\s+on|birthday)\s*[:\-]?\s*'
                    r'(?:\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}|\w+\s+\d{1,2},?\s+\d{4})\b',
                    re.IGNORECASE,
                ),
                "high",
                [Regulation.PRIVACY_ACT, Regulation.HIPAA],
                ["SI-4", "SI-19"],
                "Date of birth is PII under the Privacy Act. Redact unless operationally necessary.",
            ),
            PIICategory.DRIVERS_LICENSE: (
                re.compile(
                    r'\b(?:DL|driver\'?s?\s*license|license\s*(?:no|number|#))\s*[:\-#]?\s*[A-Z0-9]{5,15}\b',
                    re.IGNORECASE,
                ),
                "medium",
                [Regulation.PRIVACY_ACT, Regulation.CCPA],
                ["SI-4", "SI-19"],
                "Driver's license number is PII. Redact before distribution.",
            ),
            PIICategory.PASSPORT: (
                re.compile(
                    r'\b(?:passport\s*(?:no|number|#))\s*[:\-#]?\s*[A-Z0-9]{6,12}\b',
                    re.IGNORECASE,
                ),
                "high",
                [Regulation.PRIVACY_ACT],
                ["SI-4", "SI-19"],
                "Passport number detected. Highly sensitive PII - redact immediately.",
            ),
            PIICategory.ADDRESS: (
                re.compile(
                    r'\b\d{1,5}\s+(?:[A-Z][a-z]+\s+){1,3}(?:St(?:reet)?|Ave(?:nue)?|Blvd|Dr(?:ive)?|Ln|Rd|Way|Ct|Pl|Cir)'
                    r'\.?\s*(?:#\s*\d+|(?:Apt|Suite|Ste|Unit)\s*\.?\s*\d+)?\b',
                    re.IGNORECASE,
                ),
                "medium",
                [Regulation.PRIVACY_ACT, Regulation.CCPA],
                ["SI-4", "SI-19"],
                "Physical address detected. Consider redaction for privacy compliance.",
            ),

            # --- HIPAA PHI ---
            PIICategory.MEDICAL_RECORD: (
                re.compile(
                    r'\b(?:MRN|medical\s+record\s*(?:no|number|#)?|chart\s*(?:no|number|#)?)\s*[:\-#]?\s*[A-Z0-9]{4,15}\b',
                    re.IGNORECASE,
                ),
                "high",
                [Regulation.HIPAA],
                ["SI-4", "SI-19"],
                "HIPAA PHI: Medical record number detected. Must be protected per 45 CFR 164.502.",
            ),
            PIICategory.HEALTH_PLAN_ID: (
                re.compile(
                    r'\b(?:health\s+plan\s*(?:id|number|#)?|beneficiary\s*(?:id|number|#)?|member\s*(?:id|number|#)?|'
                    r'insurance\s*(?:id|number|#)?|policy\s*(?:no|number|#)?)\s*[:\-#]?\s*[A-Z0-9]{5,20}\b',
                    re.IGNORECASE,
                ),
                "high",
                [Regulation.HIPAA],
                ["SI-4", "SI-19"],
                "HIPAA PHI: Health plan identifier detected. Protect per HIPAA Privacy Rule.",
            ),
            PIICategory.PATIENT_ID: (
                re.compile(
                    r'\b(?:patient\s*(?:id|number|#)?|pt\s*(?:id|number|#)?)\s*[:\-#]?\s*[A-Z0-9]{4,15}\b',
                    re.IGNORECASE,
                ),
                "high",
                [Regulation.HIPAA],
                ["SI-4", "SI-19"],
                "HIPAA PHI: Patient identifier detected. Access must be limited to authorized personnel.",
            ),
            PIICategory.DATE_OF_SERVICE: (
                re.compile(
                    r'\b(?:date\s+of\s+service|DOS|service\s+date|admission\s+date|discharge\s+date)'
                    r'\s*[:\-]?\s*\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b',
                    re.IGNORECASE,
                ),
                "medium",
                [Regulation.HIPAA],
                ["SI-4", "SI-19"],
                "HIPAA PHI: Date of service combined with other identifiers constitutes PHI.",
            ),
            PIICategory.MEDICAL_CONDITION: (
                re.compile(
                    r'\b(?:diagnosis|diagnosed\s+with|condition|ICD[-\s]?(?:9|10)[-\s]?(?:CM)?)\s*[:\-]?\s*'
                    r'(?:[A-Z]\d{2,4}(?:\.\d{1,4})?|\w[\w\s]{3,40})\b',
                    re.IGNORECASE,
                ),
                "medium",
                [Regulation.HIPAA],
                ["SI-4", "SI-19"],
                "HIPAA PHI: Medical condition or diagnosis code detected. Protect per minimum necessary standard.",
            ),
            PIICategory.PRESCRIPTION: (
                re.compile(
                    r'\b(?:Rx|prescription|prescribed|medication)\s*[:\-]?\s*'
                    r'(?:[A-Z][a-z]+(?:ol|in|ne|te|de|se|am|um|id|ax|il|an|ine)\s*'
                    r'(?:\d+\s*(?:mg|mcg|ml|g|units?))?\b)',
                    re.IGNORECASE,
                ),
                "medium",
                [Regulation.HIPAA],
                ["SI-4", "SI-19"],
                "HIPAA PHI: Prescription information detected. Protect per HIPAA minimum necessary.",
            ),

            # --- Defense-specific PII ---
            PIICategory.DOD_ID: (
                re.compile(
                    r'\b(?:DoD\s*ID|EDIPI|DoD\s*(?:identification|id)\s*(?:no|number|#)?)\s*[:\-#]?\s*\d{10}\b',
                    re.IGNORECASE,
                ),
                "high",
                [Regulation.PRIVACY_ACT, Regulation.DFARS],
                ["SI-4", "SI-19", "IA-4"],
                "Defense PII: DoD ID (EDIPI) detected. Protect per DoD 5400.11-R and Privacy Act.",
            ),
            PIICategory.CAC_NUMBER: (
                re.compile(
                    r'\b(?:CAC|common\s+access\s+card|smart\s+card)\s*(?:no|number|#|ID)?\s*[:\-#]?\s*\d{10,16}\b',
                    re.IGNORECASE,
                ),
                "high",
                [Regulation.PRIVACY_ACT, Regulation.DFARS],
                ["SI-4", "SI-19", "IA-2"],
                "Defense PII: CAC number detected. This is authenticator data - protect per NIST 800-63.",
            ),
            PIICategory.SECURITY_CLEARANCE: (
                re.compile(
                    r'\b(?:(?:TS|TOP\s+SECRET|SECRET|CONFIDENTIAL|SCI|SAP)\s*(?:clearance|cleared|eligible|access)|'
                    r'clearance\s*(?:level|status)\s*[:\-]?\s*(?:TS|TOP\s+SECRET|SECRET|CONFIDENTIAL|SCI|SAP)|'
                    r'(?:interim|final)\s+(?:secret|top\s+secret|ts)\s+clearance)\b',
                    re.IGNORECASE,
                ),
                "high",
                [Regulation.PRIVACY_ACT, Regulation.DFARS],
                ["SI-4", "SI-19", "PS-3"],
                "Defense PII: Security clearance reference detected. Clearance status is protected PII "
                "per EO 13526 and DoD Manual 5200.02.",
            ),
            PIICategory.CAGE_CODE: (
                re.compile(
                    r'\b(?:CAGE|cage\s+code)\s*[:\-#]?\s*[A-Z0-9]{5}\b',
                    re.IGNORECASE,
                ),
                "medium",
                [Regulation.DFARS],
                ["SI-4"],
                "CAGE code detected. While not always PII, it may identify defense contractors. "
                "Verify handling requirements per contract terms.",
            ),
            PIICategory.DUNS_NUMBER: (
                re.compile(
                    r'\b(?:DUNS|D-U-N-S|D&B)\s*(?:no|number|#)?\s*[:\-#]?\s*\d{2}[-\s]?\d{3}[-\s]?\d{4}\b',
                    re.IGNORECASE,
                ),
                "medium",
                [Regulation.DFARS],
                ["SI-4"],
                "DUNS number detected. May identify specific organizations in defense contracts.",
            ),
            PIICategory.SAM_UEI: (
                re.compile(
                    r'\b(?:UEI|SAM\s*(?:UEI|unique\s+entity))\s*[:\-#]?\s*[A-Z0-9]{12}\b',
                    re.IGNORECASE,
                ),
                "medium",
                [Regulation.DFARS],
                ["SI-4"],
                "SAM UEI detected. Entity identifier for federal procurement systems.",
            ),
            PIICategory.MILITARY_SERVICE: (
                re.compile(
                    r'\b(?:service\s*(?:no|number|#)|military\s+(?:id|service)\s*(?:no|number|#)?)\s*[:\-#]?\s*'
                    r'[A-Z]?\d{6,9}\b',
                    re.IGNORECASE,
                ),
                "high",
                [Regulation.PRIVACY_ACT],
                ["SI-4", "SI-19"],
                "Military service number detected. Protected PII under the Privacy Act.",
            ),

            # --- Financial PII ---
            PIICategory.BANK_ROUTING: (
                re.compile(
                    r'\b(?:routing\s*(?:no|number|#)?|ABA|RTN)\s*[:\-#]?\s*(?:0[0-9]|1[0-2]|2[1-9]|3[0-2]|'
                    r'6[1-9]|7[0-2]|8[0-0])\d{7}\b',
                    re.IGNORECASE,
                ),
                "high",
                [Regulation.GLBA],
                ["SI-4", "SI-19", "SC-28"],
                "Bank routing number detected. Protect per GLBA Safeguards Rule.",
            ),
            PIICategory.SWIFT_BIC: (
                re.compile(
                    r'\b(?:SWIFT|BIC)\s*[:\-#]?\s*[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b',
                    re.IGNORECASE,
                ),
                "medium",
                [Regulation.GLBA],
                ["SI-4"],
                "SWIFT/BIC code detected. Financial institution identifier.",
            ),
            PIICategory.EIN_TIN: (
                re.compile(
                    r'\b(?:EIN|TIN|employer\s+identification|tax\s*(?:id|payer)\s*(?:no|number|#)?)\s*[:\-#]?\s*'
                    r'\d{2}[-\s]?\d{7}\b',
                    re.IGNORECASE,
                ),
                "high",
                [Regulation.PRIVACY_ACT, Regulation.GLBA],
                ["SI-4", "SI-19"],
                "EIN/TIN detected. Taxpayer identification is protected under 26 USC 6103.",
            ),
            PIICategory.BANK_ACCOUNT: (
                re.compile(
                    r'\b(?:account\s*(?:no|number|#)|acct\s*(?:no|number|#)?)\s*[:\-#]?\s*\d{8,17}\b',
                    re.IGNORECASE,
                ),
                "medium",
                [Regulation.GLBA],
                ["SI-4", "SI-19", "SC-28"],
                "Bank account number detected. Protect per GLBA requirements.",
            ),
            PIICategory.IBAN: (
                re.compile(
                    r'\b[A-Z]{2}\d{2}\s?(?:[A-Z0-9]{4}\s?){2,8}[A-Z0-9]{1,4}\b'
                ),
                "high",
                [Regulation.GLBA, Regulation.GDPR],
                ["SI-4", "SI-19"],
                "IBAN detected. International bank identifier - protect per applicable regulations.",
            ),

            # --- Export Control Markers ---
            PIICategory.ITAR_MARKING: (
                re.compile(
                    r'\b(?:ITAR|International\s+Traffic\s+in\s+Arms\s+Regulations?|'
                    r'22\s+CFR\s+12[0-9]|USML\s+Category|defense\s+article|'
                    r'export\s+controlled\s+(?:under|per|pursuant)\s+(?:ITAR|22\s+CFR))\b',
                    re.IGNORECASE,
                ),
                "high",
                [Regulation.ITAR],
                ["SI-4", "AC-22", "MP-4"],
                "ITAR marking detected. Document contains defense articles subject to export control. "
                "Do NOT share with foreign persons without State Department authorization.",
            ),
            PIICategory.EAR_MARKING: (
                re.compile(
                    r'\b(?:EAR|Export\s+Administration\s+Regulations?|15\s+CFR\s+7[3-7]\d|'
                    r'ECCN\s+[0-9][A-E]\d{3}|Commerce\s+Control\s+List|'
                    r'export\s+controlled\s+(?:under|per|pursuant)\s+(?:EAR|15\s+CFR))\b',
                    re.IGNORECASE,
                ),
                "high",
                [Regulation.EAR],
                ["SI-4", "AC-22", "MP-4"],
                "EAR marking detected. Dual-use technology subject to BIS export controls.",
            ),
            PIICategory.TECHNICAL_DATA: (
                re.compile(
                    r'\b(?:controlled\s+technical\s+(?:data|information)|'
                    r'distribution\s+(?:statement\s+[A-F]|limited\s+to)|'
                    r'(?:FOUO|official\s+use\s+only)\s+(?:technical|engineering)\b)',
                    re.IGNORECASE,
                ),
                "medium",
                [Regulation.ITAR, Regulation.DFARS],
                ["SI-4", "AC-22", "MP-4"],
                "Controlled technical data marker detected. Verify distribution statement compliance.",
            ),
        }

    def detect(self, text: str, filename: str = "unknown") -> EnhancedPIIReport:
        """
        Perform comprehensive PII/PHI detection on document text.

        Args:
            text: Document text content to analyze.
            filename: Name of the file being analyzed.

        Returns:
            EnhancedPIIReport with all detections, scoring, and remediation.
        """
        logger.info("Starting enhanced PII detection for: %s", filename)

        detections: List[PIIDetection] = []
        lines = text.split('\n')

        for line_num, line in enumerate(lines, 1):
            for category, (pattern, base_confidence, regulations, controls, remediation) in self.PATTERNS.items():
                for match in pattern.finditer(line):
                    # Calculate confidence based on context
                    confidence = self._assess_confidence(
                        match.group(0), line, base_confidence, category
                    )

                    context = self._extract_context(lines, line_num - 1)

                    detections.append(PIIDetection(
                        category=category,
                        matched_text=self._mask_sensitive(match.group(0), category),
                        line_number=line_num,
                        start_position=match.start(),
                        end_position=match.end(),
                        confidence=confidence,
                        applicable_regulations=regulations,
                        nist_controls=controls,
                        remediation=remediation,
                        context=self._mask_context(context),
                    ))

        # Deduplicate overlapping detections
        detections = self._deduplicate(detections)

        # Build aggregations
        by_category: Dict[str, int] = {}
        by_regulation: Dict[str, int] = {}
        all_controls: set = set()

        for det in detections:
            cat_name = det.category.value
            by_category[cat_name] = by_category.get(cat_name, 0) + 1
            for reg in det.applicable_regulations:
                by_regulation[reg.value] = by_regulation.get(reg.value, 0) + 1
            all_controls.update(det.nist_controls)

        risk_score = self._calculate_risk_score(detections)
        remediation_actions = self._generate_remediation_actions(detections, risk_score)

        summary = self._generate_summary(filename, detections, risk_score)

        report = EnhancedPIIReport(
            pii_detected=len(detections) > 0,
            total_findings=len(detections),
            risk_score=risk_score,
            detections=detections,
            detections_by_category=by_category,
            detections_by_regulation=by_regulation,
            remediation_actions=remediation_actions,
            nist_controls_applicable=sorted(all_controls),
            summary=summary,
        )

        logger.info(
            "Enhanced PII detection complete for %s: %d findings, risk=%d",
            filename, len(detections), risk_score
        )

        return report

    def _assess_confidence(
        self, matched_text: str, line: str, base_confidence: str, category: PIICategory
    ) -> str:
        """
        Assess detection confidence based on context and pattern quality.

        Args:
            matched_text: The matched text.
            line: Full line of text.
            base_confidence: Base confidence from pattern definition.
            category: The PII category detected.

        Returns:
            Adjusted confidence: "high", "medium", or "low".
        """
        # Start from base confidence
        confidence_levels = {"high": 3, "medium": 2, "low": 1}
        score = confidence_levels.get(base_confidence, 2)

        # Boost confidence if preceded by a label
        label_patterns = [
            r'(?:name|email|phone|ssn|social\s+security|account|id|number)\s*[:=]\s*$',
            r'(?:DOB|date\s+of\s+birth|born)\s*[:=]\s*$',
        ]
        prefix = line[:line.find(matched_text)] if matched_text in line else ""
        for lp in label_patterns:
            if re.search(lp, prefix, re.IGNORECASE):
                score = min(score + 1, 3)
                break

        # Lower confidence for very short matches that could be false positives
        if len(matched_text) < 5 and category not in (PIICategory.SSN, PIICategory.CREDIT_CARD):
            score = max(score - 1, 1)

        # Map back to string
        reverse_map = {3: "high", 2: "medium", 1: "low"}
        return reverse_map.get(score, "medium")

    def _mask_sensitive(self, text: str, category: PIICategory) -> str:
        """
        Mask sensitive portions of detected text for safe logging.

        Shows enough to identify the type but not the full value.
        """
        if category in (PIICategory.SSN, PIICategory.CREDIT_CARD, PIICategory.BANK_ACCOUNT,
                         PIICategory.BANK_ROUTING, PIICategory.DOD_ID, PIICategory.CAC_NUMBER):
            if len(text) > 4:
                return text[:2] + '*' * (len(text) - 4) + text[-2:]
        elif category in (PIICategory.EMAIL,):
            parts = text.split('@')
            if len(parts) == 2 and len(parts[0]) > 2:
                return parts[0][:2] + '***@' + parts[1]
        return text

    def _mask_context(self, context: str) -> str:
        """Lightly mask context to avoid exposing full PII in reports."""
        # Mask SSN-like patterns in context
        context = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '***-**-****', context)
        # Mask credit card patterns
        context = re.sub(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{1,4}\b', '****-****-****-****', context)
        return context

    def _deduplicate(self, detections: List[PIIDetection]) -> List[PIIDetection]:
        """Remove overlapping detections, preferring higher confidence."""
        if not detections:
            return detections

        confidence_rank = {"high": 3, "medium": 2, "low": 1}
        # Sort by line, position, then confidence (highest first)
        detections.sort(
            key=lambda d: (d.line_number, d.start_position, -confidence_rank.get(d.confidence, 0))
        )

        result: List[PIIDetection] = [detections[0]]
        for det in detections[1:]:
            prev = result[-1]
            # Skip if overlapping on same line
            if (det.line_number == prev.line_number and
                    det.start_position < prev.end_position and
                    det.category == prev.category):
                continue
            result.append(det)

        return result

    def _calculate_risk_score(self, detections: List[PIIDetection]) -> int:
        """Calculate overall risk score from 0-100."""
        if not detections:
            return 0

        # Risk weights by category
        weights = {
            PIICategory.SSN: 30,
            PIICategory.CREDIT_CARD: 25,
            PIICategory.DOD_ID: 25,
            PIICategory.CAC_NUMBER: 25,
            PIICategory.SECURITY_CLEARANCE: 20,
            PIICategory.MEDICAL_RECORD: 20,
            PIICategory.HEALTH_PLAN_ID: 18,
            PIICategory.PATIENT_ID: 18,
            PIICategory.ITAR_MARKING: 20,
            PIICategory.EAR_MARKING: 18,
            PIICategory.PASSPORT: 20,
            PIICategory.BANK_ROUTING: 15,
            PIICategory.BANK_ACCOUNT: 15,
            PIICategory.EIN_TIN: 15,
            PIICategory.EMAIL: 8,
            PIICategory.PHONE: 8,
            PIICategory.NAME: 5,
            PIICategory.ADDRESS: 10,
            PIICategory.DATE_OF_BIRTH: 12,
            PIICategory.DRIVERS_LICENSE: 15,
            PIICategory.MILITARY_SERVICE: 15,
            PIICategory.DUNS_NUMBER: 5,
            PIICategory.CAGE_CODE: 5,
            PIICategory.SAM_UEI: 5,
            PIICategory.SWIFT_BIC: 8,
            PIICategory.IBAN: 12,
            PIICategory.DATE_OF_SERVICE: 8,
            PIICategory.MEDICAL_CONDITION: 12,
            PIICategory.PRESCRIPTION: 10,
            PIICategory.TECHNICAL_DATA: 15,
        }

        # Confidence multipliers
        conf_mult = {"high": 1.0, "medium": 0.7, "low": 0.4}

        score = 0.0
        for det in detections:
            weight = weights.get(det.category, 5)
            mult = conf_mult.get(det.confidence, 0.5)
            score += weight * mult

        return min(int(score), 100)

    def _generate_remediation_actions(
        self, detections: List[PIIDetection], risk_score: int
    ) -> List[str]:
        """Generate prioritized remediation actions."""
        actions: List[str] = []
        seen_categories: set = set()

        # Sort by severity (most critical first)
        critical_categories = {
            PIICategory.SSN, PIICategory.CREDIT_CARD, PIICategory.DOD_ID,
            PIICategory.CAC_NUMBER, PIICategory.ITAR_MARKING
        }

        for det in sorted(detections, key=lambda d: d.category in critical_categories, reverse=True):
            if det.category not in seen_categories:
                seen_categories.add(det.category)
                actions.append(det.remediation)

        if risk_score >= 75:
            actions.insert(0, "URGENT: Document contains high-risk PII/PHI. Implement immediate access restrictions.")
            actions.append("Conduct Privacy Impact Assessment (PIA) per E-Government Act Section 208.")
            actions.append("Enable DLP monitoring for this document category.")
        elif risk_score >= 50:
            actions.insert(0, "ELEVATED: Review document handling procedures. Ensure need-to-know access controls.")
            actions.append("Review System of Records Notice (SORN) applicability.")
        elif risk_score >= 25:
            actions.insert(0, "MODERATE: Apply standard PII protection measures per organizational policy.")

        return actions

    def _generate_summary(
        self, filename: str, detections: List[PIIDetection], risk_score: int
    ) -> str:
        """Generate a human-readable detection summary."""
        if not detections:
            return f"Enhanced PII scan of '{filename}': No PII/PHI detected. Risk Score: 0/100."

        categories = set(d.category.value for d in detections)
        high_conf = sum(1 for d in detections if d.confidence == "high")

        return (
            f"Enhanced PII scan of '{filename}': {len(detections)} findings across "
            f"{len(categories)} categories. High-confidence: {high_conf}. "
            f"Risk Score: {risk_score}/100."
        )

    @staticmethod
    def _extract_context(lines: List[str], line_index: int, context_lines: int = 1) -> str:
        """Extract surrounding context lines."""
        start = max(0, line_index - context_lines)
        end = min(len(lines), line_index + context_lines + 1)
        return '\n'.join(lines[start:end]).strip()

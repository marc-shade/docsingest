"""
CUI (Controlled Unclassified Information) Detection and Classification.

Implements detection per 32 CFR Part 2002 and NIST SP 800-171.
Identifies CUI markings, classification banners, dissemination controls,
and validates marking compliance against the CUI Registry.

References:
- 32 CFR Part 2002: Controlled Unclassified Information
- NIST SP 800-171: Protecting CUI in Nonfederal Systems
- CUI Registry: https://www.archives.gov/cui/registry/category-list
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

logger = logging.getLogger(__name__)


class CUICategory(Enum):
    """CUI Registry categories per 32 CFR Part 2002."""
    CTI = "Controlled Technical Information"
    PRVCY = "Privacy"
    INTEL = "Intelligence"
    EXPT = "Export Controlled"
    ITAR = "International Traffic in Arms Regulations"
    PROPIN = "Proprietary Business Information"
    LES = "Law Enforcement Sensitive"
    FOUO = "For Official Use Only"
    SBU = "Sensitive But Unclassified"
    SSI = "Sensitive Security Information"
    PCII = "Protected Critical Infrastructure Information"
    PHLTH = "Public Health"
    TAX = "Federal Taxpayer Information"
    LEGAL = "Legal Privilege"
    OPSEC = "Operations Security"
    PHYS = "Physical Security"
    INFOSEC = "Information Systems Vulnerability Information"
    BUDGT = "Budget"
    CENSUS = "Census"
    DCRIT = "Critical Infrastructure"
    FISA = "Foreign Intelligence Surveillance Act"
    GENE = "Genetic Information"
    GEO = "Geospatial"
    PII = "Personally Identifiable Information"
    SAMI = "Controlled Technical Information - Space"


class ClassificationLevel(Enum):
    """Standard classification levels."""
    UNCLASSIFIED = "UNCLASSIFIED"
    UNCLASSIFIED_FOUO = "UNCLASSIFIED//FOUO"
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET = "SECRET"
    TOP_SECRET = "TOP SECRET"
    TOP_SECRET_SCI = "TOP SECRET//SCI"


class DisseminationControl(Enum):
    """Dissemination control markings."""
    NOFORN = "Not Releasable to Foreign Nationals"
    REL_TO = "Authorized for Release To"
    ORCON = "Originator Controlled"
    PROPIN = "Caution - Proprietary Information Involved"
    FISA = "Foreign Intelligence Surveillance Act"
    IMCON = "Controlled Imagery"
    RELIDO = "Releasable by Information Disclosure Official"
    FOUO = "For Official Use Only"
    DEA_SENSITIVE = "Drug Enforcement Administration Sensitive"


@dataclass
class CUIMarking:
    """Represents a detected CUI marking in a document."""
    marking_text: str
    category: Optional[CUICategory]
    line_number: int
    start_position: int
    end_position: int
    confidence: str  # "high", "medium", "low"
    context: str  # surrounding text for review


@dataclass
class ClassificationBanner:
    """Represents a detected classification banner."""
    banner_text: str
    level: ClassificationLevel
    line_number: int
    position_in_document: str  # "header", "footer", "body"
    confidence: str


@dataclass
class DisseminationMarking:
    """Represents a detected dissemination control marking."""
    marking_text: str
    control: DisseminationControl
    line_number: int
    associated_countries: List[str] = field(default_factory=list)


@dataclass
class CUIFinding:
    """Complete finding for a CUI-related detection."""
    finding_type: str  # "cui_marking", "classification_banner", "dissemination_control", "marking_deficiency"
    severity: str  # "critical", "high", "medium", "low"
    description: str
    line_number: int
    marking_text: str
    nist_controls: List[str]
    remediation: str


@dataclass
class CUIReport:
    """Complete CUI detection report for a document."""
    cui_detected: bool
    classification_detected: bool
    risk_score: int  # 0-100
    findings: List[CUIFinding]
    cui_markings: List[CUIMarking]
    classification_banners: List[ClassificationBanner]
    dissemination_controls: List[DisseminationMarking]
    marking_deficiencies: List[str]
    handling_recommendations: List[str]
    nist_800_171_controls: List[str]
    summary: str


class CUIDetector:
    """
    Detects and classifies Controlled Unclassified Information markings
    per 32 CFR Part 2002 and NIST SP 800-171.
    """

    # CUI marking patterns
    CUI_BASIC_PATTERN = re.compile(
        r'\b(CUI)\b(?:\s*//\s*([A-Z\-]+(?:\s*,\s*[A-Z\-]+)*))?',
        re.IGNORECASE
    )

    CUI_SPECIFIED_PATTERN = re.compile(
        r'\bCUI\s*//\s*SP[-\s]*((?:' + '|'.join(c.name for c in CUICategory) + r')(?:\s*,\s*(?:' + '|'.join(c.name for c in CUICategory) + r'))*)',
        re.IGNORECASE
    )

    CUI_REL_TO_PATTERN = re.compile(
        r'\bCUI\s*//\s*REL\s+TO\s+([A-Z]{2,3}(?:\s*,\s*[A-Z]{2,3})*)',
        re.IGNORECASE
    )

    CUI_CATEGORY_PATTERN = re.compile(
        r'\b(' + '|'.join(c.name for c in CUICategory) + r')\b',
        re.IGNORECASE
    )

    # Legacy/common marking patterns
    LEGACY_MARKINGS = {
        re.compile(r'\b(FOUO|FOR\s+OFFICIAL\s+USE\s+ONLY)\b', re.IGNORECASE): CUICategory.FOUO,
        re.compile(r'\b(SBU|SENSITIVE\s+BUT\s+UNCLASSIFIED)\b', re.IGNORECASE): CUICategory.SBU,
        re.compile(r'\b(LES|LAW\s+ENFORCEMENT\s+SENSITIVE)\b', re.IGNORECASE): CUICategory.LES,
        re.compile(r'\b(SSI|SENSITIVE\s+SECURITY\s+INFORMATION)\b', re.IGNORECASE): CUICategory.SSI,
        re.compile(r'\b(PCII|PROTECTED\s+CRITICAL\s+INFRASTRUCTURE\s+INFORMATION)\b', re.IGNORECASE): CUICategory.PCII,
    }

    # Classification banner patterns
    CLASSIFICATION_PATTERNS = {
        re.compile(r'\b(TOP\s+SECRET\s*//\s*SCI)\b', re.IGNORECASE): ClassificationLevel.TOP_SECRET_SCI,
        re.compile(r'\b(TOP\s+SECRET)\b(?!\s*//\s*SCI)', re.IGNORECASE): ClassificationLevel.TOP_SECRET,
        re.compile(r'\b(SECRET)\b(?!\s+BUT)', re.IGNORECASE): ClassificationLevel.SECRET,
        re.compile(r'\b(CONFIDENTIAL)\b', re.IGNORECASE): ClassificationLevel.CONFIDENTIAL,
        re.compile(r'\b(UNCLASSIFIED\s*//\s*FOUO)\b', re.IGNORECASE): ClassificationLevel.UNCLASSIFIED_FOUO,
        re.compile(r'\b(UNCLASSIFIED)\b(?!\s*//)', re.IGNORECASE): ClassificationLevel.UNCLASSIFIED,
    }

    # Dissemination control patterns
    DISSEMINATION_PATTERNS = {
        re.compile(r'\b(NOFORN|NOT\s+RELEASABLE\s+TO\s+FOREIGN\s+NATIONALS)\b', re.IGNORECASE): DisseminationControl.NOFORN,
        re.compile(r'\b(REL\s+TO\s+([A-Z]{2,3}(?:\s*,\s*[A-Z]{2,3})*))\b', re.IGNORECASE): DisseminationControl.REL_TO,
        re.compile(r'\b(ORCON|ORIGINATOR\s+CONTROLLED)\b', re.IGNORECASE): DisseminationControl.ORCON,
        re.compile(r'\b(PROPIN|PROPRIETARY\s+INFORMATION\s+INVOLVED)\b', re.IGNORECASE): DisseminationControl.PROPIN,
        re.compile(r'\b(FISA)\b', re.IGNORECASE): DisseminationControl.FISA,
        re.compile(r'\b(IMCON|CONTROLLED\s+IMAGERY)\b', re.IGNORECASE): DisseminationControl.IMCON,
        re.compile(r'\b(RELIDO)\b', re.IGNORECASE): DisseminationControl.RELIDO,
    }

    # NIST 800-171 control mappings for CUI handling
    NIST_800_171_CUI_CONTROLS = {
        "3.1.1": "Limit system access to authorized users",
        "3.1.2": "Limit system access to authorized functions",
        "3.1.3": "Control the flow of CUI",
        "3.1.22": "Control CUI posted to publicly accessible systems",
        "3.3.1": "Create and retain system audit logs",
        "3.3.2": "Ensure actions can be traced to individual users",
        "3.4.1": "Establish and maintain baseline configurations",
        "3.5.1": "Identify system users and processes",
        "3.5.2": "Authenticate users and processes",
        "3.8.1": "Protect system media containing CUI",
        "3.8.2": "Limit access to CUI on system media",
        "3.8.3": "Sanitize or destroy system media before disposal",
        "3.8.4": "Mark media with necessary CUI markings",
        "3.8.5": "Control access to media containing CUI during transport",
        "3.8.9": "Protect the confidentiality of backup CUI",
        "3.10.1": "Limit physical access to systems and equipment",
        "3.10.3": "Escort visitors and monitor visitor activity",
        "3.13.1": "Monitor, control, and protect communications",
        "3.13.8": "Implement cryptographic mechanisms for CUI in transit",
        "3.13.16": "Protect CUI at rest",
    }

    def __init__(self) -> None:
        """Initialize the CUI detector."""
        logger.info("CUI Detector initialized")

    def detect(self, text: str, filename: str = "unknown") -> CUIReport:
        """
        Perform comprehensive CUI detection on document text.

        Args:
            text: Document text content to analyze.
            filename: Name of the file being analyzed.

        Returns:
            CUIReport with all findings, markings, and recommendations.
        """
        logger.info("Starting CUI detection for: %s", filename)

        cui_markings = self._detect_cui_markings(text)
        classification_banners = self._detect_classification_banners(text)
        dissemination_controls = self._detect_dissemination_controls(text)
        marking_deficiencies = self._check_marking_compliance(
            text, cui_markings, classification_banners, dissemination_controls
        )

        findings = self._compile_findings(
            cui_markings, classification_banners, dissemination_controls, marking_deficiencies
        )

        cui_detected = len(cui_markings) > 0
        classification_detected = any(
            b.level != ClassificationLevel.UNCLASSIFIED for b in classification_banners
        )

        risk_score = self._calculate_risk_score(
            cui_markings, classification_banners, dissemination_controls, marking_deficiencies
        )

        handling_recommendations = self._generate_handling_recommendations(
            cui_markings, classification_banners, risk_score
        )

        applicable_controls = self._get_applicable_controls(
            cui_detected, classification_detected, risk_score
        )

        summary = self._generate_summary(
            filename, cui_detected, classification_detected, risk_score,
            len(findings), len(marking_deficiencies)
        )

        report = CUIReport(
            cui_detected=cui_detected,
            classification_detected=classification_detected,
            risk_score=risk_score,
            findings=findings,
            cui_markings=cui_markings,
            classification_banners=classification_banners,
            dissemination_controls=dissemination_controls,
            marking_deficiencies=marking_deficiencies,
            handling_recommendations=handling_recommendations,
            nist_800_171_controls=applicable_controls,
            summary=summary,
        )

        logger.info(
            "CUI detection complete for %s: cui=%s, risk=%d, findings=%d",
            filename, cui_detected, risk_score, len(findings)
        )

        return report

    def _detect_cui_markings(self, text: str) -> List[CUIMarking]:
        """Detect all CUI markings in the text."""
        markings: List[CUIMarking] = []
        lines = text.split('\n')

        for line_num, line in enumerate(lines, 1):
            # Check CUI//SP-xxx pattern
            for match in self.CUI_SPECIFIED_PATTERN.finditer(line):
                category_str = match.group(1).upper().strip()
                category = self._resolve_category(category_str)
                context = self._extract_context(lines, line_num - 1)
                markings.append(CUIMarking(
                    marking_text=match.group(0),
                    category=category,
                    line_number=line_num,
                    start_position=match.start(),
                    end_position=match.end(),
                    confidence="high",
                    context=context,
                ))

            # Check CUI//REL TO pattern
            for match in self.CUI_REL_TO_PATTERN.finditer(line):
                context = self._extract_context(lines, line_num - 1)
                markings.append(CUIMarking(
                    marking_text=match.group(0),
                    category=None,
                    line_number=line_num,
                    start_position=match.start(),
                    end_position=match.end(),
                    confidence="high",
                    context=context,
                ))

            # Check basic CUI marking (only if not already matched as specified)
            already_matched_positions = {(m.start_position, m.end_position) for m in markings if m.line_number == line_num}
            for match in self.CUI_BASIC_PATTERN.finditer(line):
                if (match.start(), match.end()) not in already_matched_positions:
                    # Check if this is part of a larger CUI marking already captured
                    overlap = False
                    for existing in markings:
                        if existing.line_number == line_num and match.start() >= existing.start_position and match.end() <= existing.end_position:
                            overlap = True
                            break
                    if not overlap:
                        category_str = match.group(2)
                        category = self._resolve_category(category_str.upper().strip()) if category_str else None
                        context = self._extract_context(lines, line_num - 1)
                        markings.append(CUIMarking(
                            marking_text=match.group(0),
                            category=category,
                            line_number=line_num,
                            start_position=match.start(),
                            end_position=match.end(),
                            confidence="high" if category else "medium",
                            context=context,
                        ))

            # Check legacy markings (FOUO, SBU, LES, etc.)
            for pattern, category in self.LEGACY_MARKINGS.items():
                for match in pattern.finditer(line):
                    overlap = False
                    for existing in markings:
                        if existing.line_number == line_num and match.start() >= existing.start_position and match.end() <= existing.end_position:
                            overlap = True
                            break
                    if not overlap:
                        context = self._extract_context(lines, line_num - 1)
                        markings.append(CUIMarking(
                            marking_text=match.group(0),
                            category=category,
                            line_number=line_num,
                            start_position=match.start(),
                            end_position=match.end(),
                            confidence="medium",
                            context=context,
                        ))

        return markings

    def _detect_classification_banners(self, text: str) -> List[ClassificationBanner]:
        """Detect classification banners in the document."""
        banners: List[ClassificationBanner] = []
        lines = text.split('\n')
        total_lines = len(lines)

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped:
                continue

            for pattern, level in self.CLASSIFICATION_PATTERNS.items():
                match = pattern.search(stripped)
                if match:
                    # Determine position in document
                    if line_num <= 3:
                        position = "header"
                    elif line_num >= total_lines - 2:
                        position = "footer"
                    else:
                        position = "body"

                    # Higher confidence for standalone banner lines
                    is_standalone = stripped.upper() == match.group(0).upper() or len(stripped) < 50
                    confidence = "high" if is_standalone else "medium"

                    # Avoid duplicates for same line
                    already_found = any(
                        b.line_number == line_num and b.level == level for b in banners
                    )
                    if not already_found:
                        banners.append(ClassificationBanner(
                            banner_text=match.group(0),
                            level=level,
                            line_number=line_num,
                            position_in_document=position,
                            confidence=confidence,
                        ))

        return banners

    def _detect_dissemination_controls(self, text: str) -> List[DisseminationMarking]:
        """Detect dissemination control markings."""
        controls: List[DisseminationMarking] = []
        lines = text.split('\n')

        for line_num, line in enumerate(lines, 1):
            for pattern, control in self.DISSEMINATION_PATTERNS.items():
                for match in pattern.finditer(line):
                    countries: List[str] = []
                    if control == DisseminationControl.REL_TO and match.lastindex and match.lastindex >= 2:
                        country_str = match.group(2)
                        countries = [c.strip() for c in country_str.split(',')]

                    already_found = any(
                        d.line_number == line_num and d.control == control for d in controls
                    )
                    if not already_found:
                        controls.append(DisseminationMarking(
                            marking_text=match.group(0),
                            control=control,
                            line_number=line_num,
                            associated_countries=countries,
                        ))

        return controls

    def _check_marking_compliance(
        self,
        _text: str,
        cui_markings: List[CUIMarking],
        banners: List[ClassificationBanner],
        dissemination_controls: List[DisseminationMarking],
    ) -> List[str]:
        """
        Check document for marking compliance issues per 32 CFR Part 2002.

        Returns list of deficiency descriptions.
        """
        deficiencies: List[str] = []

        # Check 1: CUI content without proper header banner
        if cui_markings and not any(b.position_in_document == "header" for b in banners):
            deficiencies.append(
                "Document contains CUI markings but lacks a classification/CUI banner in the header. "
                "Per 32 CFR 2002.20, CUI documents must include a CUI banner marking at the top."
            )

        # Check 2: Classification banner without corresponding portion markings
        classified_banners = [b for b in banners if b.level not in (ClassificationLevel.UNCLASSIFIED, ClassificationLevel.UNCLASSIFIED_FOUO)]
        if classified_banners and not cui_markings:
            deficiencies.append(
                "Document has classification banners but no CUI/portion markings in the body. "
                "Verify that all portions are properly marked per classification guide."
            )

        # Check 3: Mixed classification levels without proper delineation
        banner_levels = {b.level for b in banners}
        conflicting_levels = banner_levels - {ClassificationLevel.UNCLASSIFIED}
        if len(conflicting_levels) > 1:
            levels_str = ', '.join(l.value for l in conflicting_levels)
            deficiencies.append(
                f"Document contains mixed classification levels ({levels_str}). "
                "Overall classification must be the highest level found. Verify proper portion marking."
            )

        # Check 4: CUI markings without category specification
        uncategorized = [m for m in cui_markings if m.category is None and "REL TO" not in m.marking_text.upper()]
        if uncategorized:
            lines_str = ', '.join(str(m.line_number) for m in uncategorized[:5])
            deficiencies.append(
                f"CUI markings without category specification found on lines: {lines_str}. "
                "Per 32 CFR 2002.20(a)(2), CUI Specified markings must include the category."
            )

        # Check 5: FOUO used post-CUI transition (legacy marking)
        fouo_markings = [m for m in cui_markings if m.category == CUICategory.FOUO]
        if fouo_markings:
            deficiencies.append(
                "Legacy 'FOUO' marking detected. The FOUO marking was superseded by the CUI program. "
                "Documents should use CUI//SP-CTI or appropriate CUI category markings instead."
            )

        # Check 6: Dissemination controls without classification context
        if dissemination_controls and not banners:
            deficiencies.append(
                "Dissemination controls found without any classification banners. "
                "Documents with dissemination controls must have proper classification markings."
            )

        # Check 7: NOFORN with REL TO is contradictory
        has_noforn = any(d.control == DisseminationControl.NOFORN for d in dissemination_controls)
        has_rel_to = any(d.control == DisseminationControl.REL_TO for d in dissemination_controls)
        if has_noforn and has_rel_to:
            deficiencies.append(
                "Contradictory markings: NOFORN and REL TO cannot coexist. "
                "NOFORN prohibits release to foreign nationals while REL TO authorizes it."
            )

        return deficiencies

    def _compile_findings(
        self,
        cui_markings: List[CUIMarking],
        banners: List[ClassificationBanner],
        dissemination_controls: List[DisseminationMarking],
        deficiencies: List[str],
    ) -> List[CUIFinding]:
        """Compile all detections into a unified findings list."""
        findings: List[CUIFinding] = []

        for marking in cui_markings:
            severity = "high"
            if marking.category in (CUICategory.ITAR, CUICategory.EXPT, CUICategory.INTEL):
                severity = "critical"

            findings.append(CUIFinding(
                finding_type="cui_marking",
                severity=severity,
                description=f"CUI marking detected: {marking.marking_text}",
                line_number=marking.line_number,
                marking_text=marking.marking_text,
                nist_controls=["3.1.3", "3.8.1", "3.8.4", "3.13.16"],
                remediation="Ensure document is handled per CUI handling requirements. "
                            "Access must be limited to authorized personnel with a lawful purpose.",
            ))

        for banner in banners:
            if banner.level in (ClassificationLevel.SECRET, ClassificationLevel.TOP_SECRET, ClassificationLevel.TOP_SECRET_SCI):
                severity = "critical"
            elif banner.level in (ClassificationLevel.CONFIDENTIAL, ClassificationLevel.UNCLASSIFIED_FOUO):
                severity = "high"
            else:
                severity = "low"

            findings.append(CUIFinding(
                finding_type="classification_banner",
                severity=severity,
                description=f"Classification banner detected: {banner.banner_text} ({banner.position_in_document})",
                line_number=banner.line_number,
                marking_text=banner.banner_text,
                nist_controls=["3.1.1", "3.1.2", "3.8.1", "3.8.2"],
                remediation=f"Document classified as {banner.level.value}. "
                            "Handle according to classification level requirements.",
            ))

        for control in dissemination_controls:
            findings.append(CUIFinding(
                finding_type="dissemination_control",
                severity="high",
                description=f"Dissemination control: {control.marking_text}",
                line_number=control.line_number,
                marking_text=control.marking_text,
                nist_controls=["3.1.3", "3.1.22", "3.8.5"],
                remediation=f"Dissemination control '{control.control.value}' applies. "
                            "Distribution must comply with stated restrictions.",
            ))

        for deficiency in deficiencies:
            findings.append(CUIFinding(
                finding_type="marking_deficiency",
                severity="medium",
                description=deficiency,
                line_number=0,
                marking_text="",
                nist_controls=["3.8.4"],
                remediation="Correct marking deficiency per 32 CFR 2002.20 requirements.",
            ))

        return findings

    def _calculate_risk_score(
        self,
        cui_markings: List[CUIMarking],
        banners: List[ClassificationBanner],
        dissemination_controls: List[DisseminationMarking],
        deficiencies: List[str],
    ) -> int:
        """Calculate risk score from 0-100."""
        score = 0

        # CUI markings contribute to risk
        for marking in cui_markings:
            if marking.category in (CUICategory.ITAR, CUICategory.EXPT):
                score += 25
            elif marking.category in (CUICategory.INTEL, CUICategory.CTI):
                score += 20
            elif marking.category in (CUICategory.PRVCY, CUICategory.PII):
                score += 15
            else:
                score += 10

        # Classification banners
        for banner in banners:
            if banner.level == ClassificationLevel.TOP_SECRET_SCI:
                score += 40
            elif banner.level == ClassificationLevel.TOP_SECRET:
                score += 35
            elif banner.level == ClassificationLevel.SECRET:
                score += 30
            elif banner.level == ClassificationLevel.CONFIDENTIAL:
                score += 20
            elif banner.level == ClassificationLevel.UNCLASSIFIED_FOUO:
                score += 10

        # Dissemination controls
        for control in dissemination_controls:
            if control.control == DisseminationControl.NOFORN:
                score += 15
            elif control.control == DisseminationControl.ORCON:
                score += 10
            else:
                score += 5

        # Marking deficiencies add risk
        score += len(deficiencies) * 5

        return min(score, 100)

    def _generate_handling_recommendations(
        self,
        cui_markings: List[CUIMarking],
        banners: List[ClassificationBanner],
        risk_score: int,
    ) -> List[str]:
        """Generate CUI handling recommendations per NIST 800-171."""
        recommendations: List[str] = []

        if not cui_markings and not any(b.level != ClassificationLevel.UNCLASSIFIED for b in banners):
            return ["No CUI or classified content detected. Standard handling procedures apply."]

        # Always applicable for CUI
        if cui_markings:
            recommendations.extend([
                "NIST 800-171 3.1.1: Limit access to authorized users with lawful government purpose.",
                "NIST 800-171 3.8.1: Protect CUI on system media (digital and physical).",
                "NIST 800-171 3.13.8: Use FIPS-validated encryption for CUI in transit.",
                "NIST 800-171 3.13.16: Protect confidentiality of CUI at rest using encryption.",
            ])

        # ITAR/Export specific
        itar_markings = [m for m in cui_markings if m.category in (CUICategory.ITAR, CUICategory.EXPT)]
        if itar_markings:
            recommendations.extend([
                "ITAR: Do not share with foreign persons without proper export authorization.",
                "NIST 800-171 3.1.3: Control the flow of CUI per export control requirements.",
                "Maintain export control logs per 22 CFR 122.5.",
            ])

        # High classification
        classified = [b for b in banners if b.level in (ClassificationLevel.SECRET, ClassificationLevel.TOP_SECRET, ClassificationLevel.TOP_SECRET_SCI)]
        if classified:
            recommendations.extend([
                "CRITICAL: Classified content detected. This document must NOT be processed on unclassified systems.",
                "Transfer to appropriate classified network (SIPRNet/JWICS) immediately.",
                "Report potential spillage per organizational incident response procedures.",
            ])

        # Risk-based recommendations
        if risk_score >= 75:
            recommendations.append(
                "HIGH RISK: Implement enhanced access controls. Consider DLP (Data Loss Prevention) monitoring."
            )
        elif risk_score >= 50:
            recommendations.append(
                "ELEVATED RISK: Review access permissions. Enable audit logging for all access events."
            )

        return recommendations

    def _get_applicable_controls(
        self, cui_detected: bool, classification_detected: bool, risk_score: int
    ) -> List[str]:
        """Determine applicable NIST 800-171 controls."""
        controls: List[str] = []

        if cui_detected or classification_detected:
            # Core CUI controls always apply
            controls.extend(["3.1.1", "3.1.2", "3.1.3", "3.3.1", "3.3.2",
                             "3.5.1", "3.5.2", "3.8.1", "3.8.2", "3.8.4",
                             "3.13.1", "3.13.8", "3.13.16"])

        if risk_score >= 50:
            controls.extend(["3.1.22", "3.8.3", "3.8.5", "3.8.9", "3.10.1", "3.10.3"])

        if classification_detected:
            controls.extend(["3.4.1", "3.8.3"])

        return sorted(set(controls))

    def _generate_summary(
        self,
        filename: str,
        cui_detected: bool,
        classification_detected: bool,
        risk_score: int,
        finding_count: int,
        deficiency_count: int,
    ) -> str:
        """Generate a human-readable summary."""
        parts = [f"CUI Analysis for '{filename}':"]

        if cui_detected:
            parts.append("CUI content DETECTED.")
        else:
            parts.append("No CUI markings found.")

        if classification_detected:
            parts.append("Classification banners DETECTED.")

        parts.append(f"Risk Score: {risk_score}/100.")
        parts.append(f"Total Findings: {finding_count}.")

        if deficiency_count > 0:
            parts.append(f"Marking Deficiencies: {deficiency_count}.")

        return ' '.join(parts)

    def _resolve_category(self, category_str: str) -> Optional[CUICategory]:
        """Resolve a category string to a CUICategory enum value."""
        category_str = category_str.strip().upper()
        # Handle comma-separated categories by taking the first one
        if ',' in category_str:
            category_str = category_str.split(',')[0].strip()

        try:
            return CUICategory[category_str]
        except KeyError:
            logger.debug("Unknown CUI category: %s", category_str)
            return None

    @staticmethod
    def _extract_context(lines: List[str], line_index: int, context_lines: int = 1) -> str:
        """Extract surrounding context lines for a finding."""
        start = max(0, line_index - context_lines)
        end = min(len(lines), line_index + context_lines + 1)
        return '\n'.join(lines[start:end]).strip()

"""
Export Control Screening for ITAR (22 CFR 120-130) and EAR (15 CFR 730-774).

Detects references to:
- USML categories (Category I through XXI)
- CCL ECCN patterns (e.g., 3A001, 5D002)
- Defense article technical data indicators
- Foreign person/entity references triggering deemed export rules
- Dual-use technology descriptions
- Controlled technology keywords (encryption, night vision, armor, etc.)

References:
- ITAR: 22 CFR Parts 120-130
- EAR: 15 CFR Parts 730-774
- NIST SP 800-53: AC-22, MP-4
- USML: United States Munitions List (22 CFR 121.1)
- CCL: Commerce Control List (15 CFR Part 774, Supplement 1)
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class ExportControlRegime(Enum):
    """Export control regulatory regime."""
    ITAR = "ITAR (22 CFR 120-130)"
    EAR = "EAR (15 CFR 730-774)"
    DUAL_USE = "Dual-Use (Both ITAR and EAR may apply)"


class USMLCategory(Enum):
    """United States Munitions List categories per 22 CFR 121.1."""
    CAT_I = ("I", "Firearms, Close Assault Weapons and Combat Shotguns")
    CAT_II = ("II", "Guns and Armament")
    CAT_III = ("III", "Ammunition/Ordnance")
    CAT_IV = ("IV", "Launch Vehicles, Guided Missiles, Ballistic Missiles, Rockets, Torpedoes, Bombs, and Mines")
    CAT_V = ("V", "Explosives and Energetic Materials, Propellants, Incendiary Agents and Their Constituents")
    CAT_VI = ("VI", "Surface Vessels of War and Special Naval Equipment")
    CAT_VII = ("VII", "Ground Vehicles")
    CAT_VIII = ("VIII", "Aircraft and Related Articles")
    CAT_IX = ("IX", "Military Training Equipment and Training")
    CAT_X = ("X", "Personal Protective Equipment")
    CAT_XI = ("XI", "Military Electronics")
    CAT_XII = ("XII", "Fire Control, Laser, Imaging, and Guidance Equipment")
    CAT_XIII = ("XIII", "Materials and Miscellaneous Articles")
    CAT_XIV = ("XIV", "Toxicological Agents, Including Chemical Agents, Biological Agents, and Associated Equipment")
    CAT_XV = ("XV", "Spacecraft and Related Articles")
    CAT_XVI = ("XVI", "Nuclear Weapons Related Articles")
    CAT_XVII = ("XVII", "Classified Articles, Technical Data, and Defense Services Not Otherwise Enumerated")
    CAT_XVIII = ("XVIII", "Directed Energy Weapons")
    CAT_XIX = ("XIX", "Gas Turbine Engines and Associated Equipment")
    CAT_XX = ("XX", "Submersible Vessels and Related Articles")
    CAT_XXI = ("XXI", "Articles, Technical Data, and Defense Services Not Otherwise Enumerated")

    def __init__(self, number: str, description: str) -> None:
        self.number = number
        self.cat_description = description


@dataclass
class ExportControlFinding:
    """A single export control finding."""
    regime: ExportControlRegime
    finding_type: str  # "usml_reference", "eccn_reference", "technical_data", "foreign_person", "controlled_technology", "dual_use"
    severity: str  # "critical", "high", "medium", "low"
    description: str
    matched_text: str
    line_number: int
    context: str
    classification_recommendation: str
    nist_controls: List[str]
    remediation: str


@dataclass
class ExportControlReport:
    """Complete export control screening report."""
    export_controlled: bool
    itar_findings: int
    ear_findings: int
    risk_score: int  # 0-100
    findings: List[ExportControlFinding]
    usml_categories_referenced: List[str]
    eccn_patterns_found: List[str]
    foreign_references: List[str]
    controlled_technologies: List[str]
    classification_recommendations: List[str]
    nist_controls_applicable: List[str]
    summary: str


class ExportControlScreener:
    """
    ITAR/EAR export control screening engine.

    Screens documents for references to controlled items, technical data,
    foreign persons/entities, and dual-use technologies. Generates
    export classification recommendations.
    """

    # USML Category reference patterns
    USML_PATTERNS = [
        re.compile(
            r'\b(?:USML|United\s+States\s+Munitions\s+List)\s*'
            r'(?:Category|Cat\.?)\s*(I{1,3}|IV|VI{0,3}|IX|X{1,3}I{0,2}|'
            r'XI{1,3}|XIV|XV|XVI|XVII|XVIII|XIX|XX|XXI)\b',
            re.IGNORECASE,
        ),
        re.compile(
            r'\bCategory\s+(I{1,3}|IV|VI{0,3}|IX|X{1,3}I{0,2}|'
            r'XI{1,3}|XIV|XV|XVI|XVII|XVIII|XIX|XX|XXI)\s+'
            r'(?:of\s+the\s+USML|defense\s+article|munitions)',
            re.IGNORECASE,
        ),
    ]

    # ECCN pattern (Commerce Control List)
    ECCN_PATTERN = re.compile(
        r'\b(?:ECCN|Export\s+Control\s+Classification\s+Number)\s*[:\-]?\s*'
        r'([0-9][A-E]\d{3}(?:\.[a-z](?:\.\d+)?)?)\b',
        re.IGNORECASE,
    )

    # Standalone ECCN format
    ECCN_STANDALONE = re.compile(
        r'\b([0-9][A-E]\d{3}(?:\.[a-z](?:\.\d+)?)?)\b'
    )

    # ECCN groups and their descriptions
    ECCN_CATEGORIES = {
        '0': 'Nuclear Materials, Facilities, and Equipment',
        '1': 'Special Materials and Related Equipment',
        '2': 'Materials Processing',
        '3': 'Electronics',
        '4': 'Computers',
        '5': 'Telecommunications and Information Security',
        '6': 'Sensors and Lasers',
        '7': 'Navigation and Avionics',
        '8': 'Marine',
        '9': 'Aerospace and Propulsion',
    }

    ECCN_PRODUCT_GROUPS = {
        'A': 'Systems, Equipment, and Components',
        'B': 'Test, Inspection, and Production Equipment',
        'C': 'Materials',
        'D': 'Software',
        'E': 'Technology',
    }

    # Controlled technology keywords - configurable
    CONTROLLED_TECHNOLOGY_KEYWORDS: Dict[str, Tuple[str, ExportControlRegime, str]] = {
        # Encryption/Cryptography
        'encryption algorithm': ('Encryption technology', ExportControlRegime.EAR, 'high'),
        'cryptographic': ('Cryptographic technology', ExportControlRegime.EAR, 'medium'),
        'AES-256': ('Strong encryption', ExportControlRegime.EAR, 'medium'),
        'RSA-2048': ('Public key cryptography', ExportControlRegime.EAR, 'medium'),
        'quantum cryptography': ('Quantum cryptographic technology', ExportControlRegime.EAR, 'high'),
        'post-quantum': ('Post-quantum cryptography', ExportControlRegime.EAR, 'medium'),

        # Night Vision / Thermal
        'night vision': ('Night vision technology', ExportControlRegime.ITAR, 'high'),
        'image intensifier': ('Image intensification', ExportControlRegime.ITAR, 'high'),
        'thermal imaging': ('Thermal imaging technology', ExportControlRegime.DUAL_USE, 'high'),
        'infrared sensor': ('IR sensor technology', ExportControlRegime.DUAL_USE, 'medium'),
        'FLIR': ('Forward-looking infrared', ExportControlRegime.ITAR, 'high'),

        # Armor / Protection
        'ballistic armor': ('Ballistic protection', ExportControlRegime.ITAR, 'high'),
        'body armor': ('Personal protective equipment', ExportControlRegime.ITAR, 'medium'),
        'reactive armor': ('Reactive armor technology', ExportControlRegime.ITAR, 'high'),
        'ceramic armor': ('Ceramic armor materials', ExportControlRegime.ITAR, 'high'),

        # Propulsion / Rockets
        'solid rocket motor': ('Solid rocket propulsion', ExportControlRegime.ITAR, 'critical'),
        'liquid propellant': ('Liquid propulsion system', ExportControlRegime.ITAR, 'high'),
        'turbofan engine': ('Gas turbine propulsion', ExportControlRegime.ITAR, 'high'),
        'scramjet': ('Hypersonic propulsion', ExportControlRegime.ITAR, 'critical'),
        'ramjet': ('Ramjet propulsion', ExportControlRegime.ITAR, 'high'),

        # Guidance / Navigation
        'inertial navigation': ('INS technology', ExportControlRegime.ITAR, 'high'),
        'GPS anti-jam': ('Anti-jam GPS', ExportControlRegime.ITAR, 'high'),
        'ring laser gyro': ('Ring laser gyroscope', ExportControlRegime.ITAR, 'high'),
        'stellar navigation': ('Stellar-inertial navigation', ExportControlRegime.ITAR, 'critical'),
        'terrain contour matching': ('TERCOM guidance', ExportControlRegime.ITAR, 'critical'),

        # Weapons Systems
        'warhead': ('Warhead technology', ExportControlRegime.ITAR, 'critical'),
        'shaped charge': ('Shaped charge ordnance', ExportControlRegime.ITAR, 'critical'),
        'fuze mechanism': ('Fuzing technology', ExportControlRegime.ITAR, 'critical'),
        'depleted uranium': ('DU munitions', ExportControlRegime.ITAR, 'critical'),
        'directed energy weapon': ('DEW technology', ExportControlRegime.ITAR, 'critical'),

        # Nuclear
        'uranium enrichment': ('Nuclear material processing', ExportControlRegime.EAR, 'critical'),
        'centrifuge cascade': ('Enrichment technology', ExportControlRegime.EAR, 'critical'),
        'nuclear weapon': ('Nuclear weapons', ExportControlRegime.ITAR, 'critical'),
        'fissile material': ('Nuclear materials', ExportControlRegime.EAR, 'critical'),

        # Stealth / Signature
        'radar cross section reduction': ('Stealth technology', ExportControlRegime.ITAR, 'critical'),
        'radar absorbing material': ('RAM technology', ExportControlRegime.ITAR, 'critical'),
        'low observable': ('Low-observable technology', ExportControlRegime.ITAR, 'critical'),
        'signature reduction': ('Signature management', ExportControlRegime.ITAR, 'high'),

        # Unmanned Systems
        'autonomous weapon': ('Autonomous weapons', ExportControlRegime.ITAR, 'critical'),
        'loitering munition': ('Loitering munition', ExportControlRegime.ITAR, 'critical'),
        'combat UAV': ('Combat unmanned aerial vehicle', ExportControlRegime.ITAR, 'high'),
        'UCAV': ('Unmanned combat aerial vehicle', ExportControlRegime.ITAR, 'high'),

        # Electronic Warfare
        'electronic countermeasure': ('ECM technology', ExportControlRegime.ITAR, 'high'),
        'signal jamming': ('Signal jamming', ExportControlRegime.ITAR, 'high'),
        'SIGINT': ('Signals intelligence', ExportControlRegime.ITAR, 'high'),
        'ELINT': ('Electronic intelligence', ExportControlRegime.ITAR, 'high'),
        'cyber weapon': ('Offensive cyber capabilities', ExportControlRegime.DUAL_USE, 'critical'),
        'zero-day exploit': ('Zero-day vulnerability', ExportControlRegime.DUAL_USE, 'critical'),

        # Biological / Chemical
        'biological agent': ('Biological warfare agent', ExportControlRegime.ITAR, 'critical'),
        'chemical weapon': ('Chemical warfare', ExportControlRegime.ITAR, 'critical'),
        'nerve agent': ('Chemical nerve agent', ExportControlRegime.ITAR, 'critical'),
        'biological weapon': ('Biological weapon', ExportControlRegime.ITAR, 'critical'),

        # Satellites / Space
        'satellite bus': ('Satellite technology', ExportControlRegime.ITAR, 'high'),
        'space launch vehicle': ('Launch vehicle technology', ExportControlRegime.ITAR, 'critical'),
        'reentry vehicle': ('Reentry technology', ExportControlRegime.ITAR, 'critical'),

        # Underwater
        'submarine hull': ('Submarine technology', ExportControlRegime.ITAR, 'high'),
        'sonar array': ('Sonar technology', ExportControlRegime.ITAR, 'high'),
        'torpedo guidance': ('Torpedo technology', ExportControlRegime.ITAR, 'critical'),
        'acoustic countermeasure': ('Acoustic CM', ExportControlRegime.ITAR, 'high'),
    }

    # Foreign person/entity indicators
    FOREIGN_INDICATORS = [
        re.compile(r'\b(?:foreign\s+(?:national|person|entity|government|military))\b', re.IGNORECASE),
        re.compile(r'\b(?:non[-\s]?U\.?S\.?\s+(?:person|citizen|entity|national))\b', re.IGNORECASE),
        re.compile(r'\b(?:deemed\s+export)\b', re.IGNORECASE),
        re.compile(r'\b(?:foreign\s+(?:disclosure|release|transfer|sale))\b', re.IGNORECASE),
        re.compile(r'\b(?:FMS|foreign\s+military\s+sale)\b', re.IGNORECASE),
        re.compile(r'\b(?:LOA|letter\s+of\s+(?:agreement|offer|acceptance))\b', re.IGNORECASE),
    ]

    # Technical data indicators
    TECHNICAL_DATA_PATTERNS = [
        re.compile(r'\b(?:technical\s+data\s+package|TDP)\b', re.IGNORECASE),
        re.compile(r'\b(?:engineering\s+drawing|blueprint|schematic)\b', re.IGNORECASE),
        re.compile(r'\b(?:manufacturing\s+(?:process|procedure|specification))\b', re.IGNORECASE),
        re.compile(r'\b(?:performance\s+(?:specification|characteristic|parameter))\b', re.IGNORECASE),
        re.compile(r'\b(?:test\s+(?:result|report|procedure)\s+(?:for|of)\s+(?:defense|military|weapon))\b', re.IGNORECASE),
        re.compile(
            r'\b(?:distribution\s+statement\s+[B-F])\b', re.IGNORECASE,
        ),
        re.compile(
            r'\b(?:DFARS|ITAR|EAR)\s+(?:controlled|restricted|limited)\b', re.IGNORECASE,
        ),
    ]

    # Dual-use indicators
    DUAL_USE_PATTERNS = [
        re.compile(r'\b(?:dual[-\s]?use\s+(?:technology|item|good|commodity))\b', re.IGNORECASE),
        re.compile(r'\b(?:military\s+and\s+(?:commercial|civilian)\s+(?:use|application))\b', re.IGNORECASE),
        re.compile(r'\b(?:Wassenaar\s+Arrangement)\b', re.IGNORECASE),
        re.compile(r'\b(?:MTCR|Missile\s+Technology\s+Control\s+Regime)\b', re.IGNORECASE),
        re.compile(r'\b(?:Australia\s+Group)\b', re.IGNORECASE),
        re.compile(r'\b(?:Nuclear\s+Suppliers\s+Group|NSG)\b', re.IGNORECASE),
    ]

    def __init__(self, additional_keywords: Optional[Dict[str, Tuple[str, str, str]]] = None) -> None:
        """
        Initialize the export control screener.

        Args:
            additional_keywords: Optional dict of additional controlled technology keywords.
                Key: keyword phrase
                Value: tuple of (description, regime_name, severity)
                regime_name must be one of: "ITAR", "EAR", "DUAL_USE"
        """
        if additional_keywords:
            for keyword, (desc, regime_name, severity) in additional_keywords.items():
                regime = ExportControlRegime[regime_name] if isinstance(regime_name, str) else regime_name
                self.CONTROLLED_TECHNOLOGY_KEYWORDS[keyword] = (desc, regime, severity)

        logger.info(
            "Export Control Screener initialized with %d controlled technology keywords",
            len(self.CONTROLLED_TECHNOLOGY_KEYWORDS)
        )

    def screen(self, text: str, filename: str = "unknown") -> ExportControlReport:
        """
        Screen document text for export control concerns.

        Args:
            text: Document text to screen.
            filename: Name of the file being screened.

        Returns:
            ExportControlReport with all findings and recommendations.
        """
        logger.info("Starting export control screening for: %s", filename)

        findings: List[ExportControlFinding] = []
        lines = text.split('\n')

        # Screen for USML references
        usml_refs = self._screen_usml_references(lines)
        findings.extend(usml_refs)

        # Screen for ECCN patterns
        eccn_refs = self._screen_eccn_patterns(lines)
        findings.extend(eccn_refs)

        # Screen for controlled technology keywords
        tech_refs = self._screen_controlled_technologies(lines)
        findings.extend(tech_refs)

        # Screen for foreign person/entity references
        foreign_refs = self._screen_foreign_references(lines)
        findings.extend(foreign_refs)

        # Screen for technical data indicators
        techdata_refs = self._screen_technical_data(lines)
        findings.extend(techdata_refs)

        # Screen for dual-use indicators
        dualuse_refs = self._screen_dual_use(lines)
        findings.extend(dualuse_refs)

        # Aggregate results
        usml_categories = sorted(set(
            f.matched_text for f in findings if f.finding_type == "usml_reference"
        ))
        eccn_patterns = sorted(set(
            f.matched_text for f in findings if f.finding_type == "eccn_reference"
        ))
        foreign_references_list = sorted(set(
            f.matched_text for f in findings if f.finding_type == "foreign_person"
        ))
        controlled_techs = sorted(set(
            f.description for f in findings if f.finding_type == "controlled_technology"
        ))

        itar_count = sum(1 for f in findings if f.regime == ExportControlRegime.ITAR)
        ear_count = sum(1 for f in findings if f.regime == ExportControlRegime.EAR)

        risk_score = self._calculate_risk_score(findings)
        classification_recs = self._generate_classification_recommendations(findings, risk_score)

        all_controls: Set[str] = set()
        for f in findings:
            all_controls.update(f.nist_controls)

        summary = self._generate_summary(
            filename, findings, itar_count, ear_count, risk_score
        )

        report = ExportControlReport(
            export_controlled=len(findings) > 0,
            itar_findings=itar_count,
            ear_findings=ear_count,
            risk_score=risk_score,
            findings=findings,
            usml_categories_referenced=usml_categories,
            eccn_patterns_found=eccn_patterns,
            foreign_references=foreign_references_list,
            controlled_technologies=controlled_techs,
            classification_recommendations=classification_recs,
            nist_controls_applicable=sorted(all_controls),
            summary=summary,
        )

        logger.info(
            "Export control screening complete for %s: ITAR=%d, EAR=%d, risk=%d",
            filename, itar_count, ear_count, risk_score
        )

        return report

    def _screen_usml_references(self, lines: List[str]) -> List[ExportControlFinding]:
        """Screen for USML category references."""
        findings: List[ExportControlFinding] = []

        for line_num, line in enumerate(lines, 1):
            for pattern in self.USML_PATTERNS:
                for match in pattern.finditer(line):
                    cat_numeral = match.group(1).upper()
                    # Look up category description
                    cat_desc = "Unknown"
                    for cat in USMLCategory:
                        if cat.number == cat_numeral:
                            cat_desc = cat.cat_description
                            break

                    context = self._extract_context(lines, line_num - 1)
                    findings.append(ExportControlFinding(
                        regime=ExportControlRegime.ITAR,
                        finding_type="usml_reference",
                        severity="critical",
                        description=f"USML Category {cat_numeral}: {cat_desc}",
                        matched_text=f"USML Category {cat_numeral}",
                        line_number=line_num,
                        context=context,
                        classification_recommendation=(
                            f"This document references USML Category {cat_numeral} ({cat_desc}). "
                            f"If it contains technical data related to this category, it is ITAR-controlled "
                            f"under 22 CFR 121.1 and requires State Department authorization for export."
                        ),
                        nist_controls=["AC-22", "MP-4", "AU-2"],
                        remediation=(
                            f"Verify ITAR jurisdiction. If document contains Category {cat_numeral} "
                            f"technical data, mark as ITAR-controlled and restrict access to U.S. persons only."
                        ),
                    ))

        return findings

    def _screen_eccn_patterns(self, lines: List[str]) -> List[ExportControlFinding]:
        """Screen for ECCN/Commerce Control List patterns."""
        findings: List[ExportControlFinding] = []

        for line_num, line in enumerate(lines, 1):
            # Check labeled ECCN references
            for match in self.ECCN_PATTERN.finditer(line):
                eccn = match.group(1).upper()
                findings.append(self._create_eccn_finding(eccn, line_num, lines))

            # Check standalone ECCN patterns in context
            for match in self.ECCN_STANDALONE.finditer(line):
                eccn = match.group(1).upper()
                # Only flag standalone ECCNs if near export control context
                surrounding = ' '.join(lines[max(0, line_num - 3):min(len(lines), line_num + 2)])
                export_context_words = ['export', 'control', 'eccn', 'ccl', 'commerce', 'ear',
                                        'license', 'classification', 'dual-use', 'bis']
                if any(w in surrounding.lower() for w in export_context_words):
                    # Avoid duplicate
                    if not any(f.matched_text == eccn and f.line_number == line_num for f in findings):
                        findings.append(self._create_eccn_finding(eccn, line_num, lines))

        return findings

    def _create_eccn_finding(
        self, eccn: str, line_num: int, lines: List[str]
    ) -> ExportControlFinding:
        """Create an ECCN finding."""
        cat_num = eccn[0]
        prod_group = eccn[1]
        cat_desc = self.ECCN_CATEGORIES.get(cat_num, "Unknown")
        group_desc = self.ECCN_PRODUCT_GROUPS.get(prod_group, "Unknown")
        context = self._extract_context(lines, line_num - 1)

        return ExportControlFinding(
            regime=ExportControlRegime.EAR,
            finding_type="eccn_reference",
            severity="high",
            description=f"ECCN {eccn}: {cat_desc} - {group_desc}",
            matched_text=eccn,
            line_number=line_num,
            context=context,
            classification_recommendation=(
                f"ECCN {eccn} identified. Category {cat_num} ({cat_desc}), "
                f"Group {prod_group} ({group_desc}). "
                f"Verify license requirements per 15 CFR Part 774 Supplement 1."
            ),
            nist_controls=["AC-22", "MP-4"],
            remediation=(
                f"Determine if ECCN {eccn} requires a BIS export license for the intended "
                f"destination/end-user. Check License Exception availability."
            ),
        )

    def _screen_controlled_technologies(self, lines: List[str]) -> List[ExportControlFinding]:
        """Screen for controlled technology keyword references."""
        findings: List[ExportControlFinding] = []
        text_lower = '\n'.join(lines).lower()

        for keyword, (desc, regime, severity) in self.CONTROLLED_TECHNOLOGY_KEYWORDS.items():
            keyword_lower = keyword.lower()
            if keyword_lower in text_lower:
                # Find specific line numbers
                for line_num, line in enumerate(lines, 1):
                    if keyword_lower in line.lower():
                        context = self._extract_context(lines, line_num - 1)
                        findings.append(ExportControlFinding(
                            regime=regime,
                            finding_type="controlled_technology",
                            severity=severity,
                            description=f"Controlled technology: {desc}",
                            matched_text=keyword,
                            line_number=line_num,
                            context=context,
                            classification_recommendation=(
                                f"Document references '{keyword}' which may be controlled under {regime.value}. "
                                f"Conduct commodity jurisdiction determination if not already classified."
                            ),
                            nist_controls=["AC-22", "MP-4"],
                            remediation=(
                                f"Review document for {desc} content. If export-controlled, apply "
                                f"appropriate markings and access restrictions."
                            ),
                        ))
                        break  # One finding per keyword is sufficient

        return findings

    def _screen_foreign_references(self, lines: List[str]) -> List[ExportControlFinding]:
        """Screen for foreign person/entity references that trigger deemed export rules."""
        findings: List[ExportControlFinding] = []

        for line_num, line in enumerate(lines, 1):
            for pattern in self.FOREIGN_INDICATORS:
                for match in pattern.finditer(line):
                    context = self._extract_context(lines, line_num - 1)
                    findings.append(ExportControlFinding(
                        regime=ExportControlRegime.DUAL_USE,
                        finding_type="foreign_person",
                        severity="high",
                        description=f"Foreign person/entity reference: {match.group(0)}",
                        matched_text=match.group(0),
                        line_number=line_num,
                        context=context,
                        classification_recommendation=(
                            "Foreign person or entity reference detected. If this document contains "
                            "controlled technical data, sharing with foreign persons constitutes a "
                            "'deemed export' under 22 CFR 120.17 (ITAR) or 15 CFR 734.13 (EAR)."
                        ),
                        nist_controls=["AC-22", "MP-4", "PS-3"],
                        remediation=(
                            "Verify that any sharing of this document with foreign persons has proper "
                            "export authorization (license, agreement, or exemption)."
                        ),
                    ))

        return findings

    def _screen_technical_data(self, lines: List[str]) -> List[ExportControlFinding]:
        """Screen for technical data indicators."""
        findings: List[ExportControlFinding] = []

        for line_num, line in enumerate(lines, 1):
            for pattern in self.TECHNICAL_DATA_PATTERNS:
                for match in pattern.finditer(line):
                    context = self._extract_context(lines, line_num - 1)
                    findings.append(ExportControlFinding(
                        regime=ExportControlRegime.ITAR,
                        finding_type="technical_data",
                        severity="high",
                        description=f"Technical data indicator: {match.group(0)}",
                        matched_text=match.group(0),
                        line_number=line_num,
                        context=context,
                        classification_recommendation=(
                            "Technical data indicator found. Under ITAR (22 CFR 120.33), 'technical data' "
                            "includes information required for design, development, production, or use of "
                            "defense articles. Determine if this constitutes ITAR-controlled technical data."
                        ),
                        nist_controls=["AC-22", "MP-4", "AU-2"],
                        remediation=(
                            "Conduct a technical data review. If the document contains defense article "
                            "technical data, apply ITAR markings and restrict to U.S. persons."
                        ),
                    ))

        return findings

    def _screen_dual_use(self, lines: List[str]) -> List[ExportControlFinding]:
        """Screen for dual-use technology indicators."""
        findings: List[ExportControlFinding] = []

        for line_num, line in enumerate(lines, 1):
            for pattern in self.DUAL_USE_PATTERNS:
                for match in pattern.finditer(line):
                    context = self._extract_context(lines, line_num - 1)
                    findings.append(ExportControlFinding(
                        regime=ExportControlRegime.DUAL_USE,
                        finding_type="dual_use",
                        severity="medium",
                        description=f"Dual-use indicator: {match.group(0)}",
                        matched_text=match.group(0),
                        line_number=line_num,
                        context=context,
                        classification_recommendation=(
                            "Dual-use technology reference detected. The item may be subject to "
                            "both ITAR and EAR. Conduct a commodity jurisdiction (CJ) determination "
                            "to establish the controlling regulation."
                        ),
                        nist_controls=["AC-22", "MP-4"],
                        remediation=(
                            "File a CJ request with DDTC if ITAR jurisdiction is uncertain. "
                            "Classify under EAR if not on the USML."
                        ),
                    ))

        return findings

    def _calculate_risk_score(self, findings: List[ExportControlFinding]) -> int:
        """Calculate export control risk score from 0-100."""
        severity_weights = {
            'critical': 25,
            'high': 15,
            'medium': 8,
            'low': 3,
        }

        score = 0
        for f in findings:
            score += severity_weights.get(f.severity, 5)

        # Bonus risk for multiple regimes
        regimes = set(f.regime for f in findings)
        if len(regimes) > 1:
            score += 10

        # Bonus risk for USML + foreign person combination
        has_usml = any(f.finding_type == "usml_reference" for f in findings)
        has_foreign = any(f.finding_type == "foreign_person" for f in findings)
        if has_usml and has_foreign:
            score += 20

        return min(score, 100)

    def _generate_classification_recommendations(
        self, findings: List[ExportControlFinding], risk_score: int
    ) -> List[str]:
        """Generate export control classification recommendations."""
        recommendations: List[str] = []

        if not findings:
            return ["No export control indicators detected. Standard handling procedures apply."]

        # USML-specific
        usml_findings = [f for f in findings if f.finding_type == "usml_reference"]
        if usml_findings:
            categories = sorted(set(f.matched_text for f in usml_findings))
            recommendations.append(
                f"ITAR REVIEW REQUIRED: Document references USML categories: {', '.join(categories)}. "
                "Conduct a commodity jurisdiction determination with DDTC."
            )

        # ECCN-specific
        eccn_findings = [f for f in findings if f.finding_type == "eccn_reference"]
        if eccn_findings:
            eccns = sorted(set(f.matched_text for f in eccn_findings))
            recommendations.append(
                f"EAR CLASSIFICATION: ECCNs referenced: {', '.join(eccns)}. "
                "Verify license requirements with BIS for intended destination."
            )

        # Foreign person risk
        foreign_findings = [f for f in findings if f.finding_type == "foreign_person"]
        if foreign_findings:
            recommendations.append(
                "DEEMED EXPORT RISK: Foreign person/entity references found. If sharing controlled "
                "technical data, ensure proper export authorization per 22 CFR 120.17 or 15 CFR 734.13."
            )

        # Controlled technology
        tech_findings = [f for f in findings if f.finding_type == "controlled_technology"]
        if tech_findings:
            critical_tech = [f for f in tech_findings if f.severity == "critical"]
            if critical_tech:
                recommendations.append(
                    "CRITICAL: Document references highly sensitive controlled technologies. "
                    "Immediate export control review required before any distribution."
                )

        # General risk-based
        if risk_score >= 75:
            recommendations.append(
                "HIGH EXPORT CONTROL RISK: Restrict document to U.S. persons with need-to-know. "
                "Consult with empowered official before any transfer."
            )
        elif risk_score >= 50:
            recommendations.append(
                "ELEVATED RISK: Apply export control markings. Maintain distribution records."
            )

        return recommendations

    def _generate_summary(
        self,
        filename: str,
        findings: List[ExportControlFinding],
        itar_count: int,
        ear_count: int,
        risk_score: int,
    ) -> str:
        """Generate human-readable summary."""
        if not findings:
            return f"Export control screening of '{filename}': No export control indicators found. Risk Score: 0/100."

        critical = sum(1 for f in findings if f.severity == "critical")
        parts = [
            f"Export control screening of '{filename}':",
            f"{len(findings)} finding(s).",
            f"ITAR: {itar_count}.",
            f"EAR: {ear_count}.",
        ]
        if critical > 0:
            parts.append(f"CRITICAL findings: {critical}.")
        parts.append(f"Risk Score: {risk_score}/100.")

        return ' '.join(parts)

    @staticmethod
    def _extract_context(lines: List[str], line_index: int, context_lines: int = 1) -> str:
        """Extract surrounding context lines."""
        start = max(0, line_index - context_lines)
        end = min(len(lines), line_index + context_lines + 1)
        return '\n'.join(lines[start:end]).strip()

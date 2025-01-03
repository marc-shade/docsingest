import logging
import re
from typing import Dict, List, Optional

import spacy


class PIIDetector:
    """PII detection and redaction tool."""

    def __init__(self, model: str = "en_core_web_sm"):
        """
        Initialize PII detector with SpaCy model.

        Args:
            model: SpaCy language model for NER
        """
        try:
            self.nlp = spacy.load(model)
        except OSError:
            logging.warning(f"SpaCy {model} load failed.")
            self.nlp = None

    def detect(self, text: str) -> Dict[str, Optional[List[str]]]:
        """
        Detect Personally Identifiable Information.

        Args:
            text: Input text to analyze for PII

        Returns:
            PII detection report
        """
        if not self.nlp:
            return {
                "pii_detected": False,
                "error": "SpaCy model not loaded",
            }

        # Named Entity Recognition for PII
        doc = self.nlp(text)

        # Regex patterns for additional PII detection
        patterns = {
            "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "phone": (
                r"\b(?:\+\d{1,2}\s?)?(?:\(\d{3}\)|\d{3})"
                r"[\s.-]?\d{3}[\s.-]?\d{4}\b"
            ),
            "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
            "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        }

        # Collect PII findings
        pii_details: Dict[str, List[str]] = {
            "names": [],
            "emails": [],
            "phone_numbers": [],
            "ssn": [],
            "credit_cards": [],
        }

        # Extract named entities
        for ent in doc.ents:
            if ent.label_ in ["PERSON", "ORG"]:
                pii_details["names"].append(ent.text)

        # Regex-based PII detection
        for pii_type, pattern in patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                if pii_type == "email":
                    pii_details["emails"].extend(matches)
                elif pii_type == "phone":
                    pii_details["phone_numbers"].extend(matches)
                elif pii_type == "ssn":
                    pii_details["ssn"].extend(matches)
                elif pii_type == "credit_card":
                    pii_details["credit_cards"].extend(matches)

        # Compute risk score
        risk_score = self._calculate_risk_score(pii_details)

        # Prepare report
        report: Dict[str, Optional[List[str]]] = {
            "pii_detected": any(pii_details.values()),
            "pii_details": pii_details,
            "risk_score": risk_score,
            "recommended_actions": self._get_recommended_actions(risk_score),
        }

        return report

    def _calculate_risk_score(
        self, pii_details: Dict[str, List[str]]
    ) -> int:
        """
        Calculate risk score based on detected PII.

        Args:
            pii_details: Dictionary of detected PII

        Returns:
            Risk score between 0 and 100
        """
        risk_factors = {
            "names": 10,
            "emails": 20,
            "phone_numbers": 15,
            "ssn": 50,
            "credit_cards": 75,
        }

        risk_score = 0
        for pii_type, matches in pii_details.items():
            if matches:
                risk_score += risk_factors.get(pii_type, 0) * len(matches)

        return min(risk_score, 100)

    def _get_recommended_actions(self, risk_score: int) -> List[str]:
        """
        Generate recommended actions based on risk score.

        Args:
            risk_score: Calculated risk score

        Returns:
            Recommended compliance actions
        """
        actions: List[str] = []

        if risk_score > 75:
            actions.extend([
                "URGENT: Immediate redaction",
                "Implement strict access controls",
                "Consider legal review",
            ])
        elif risk_score > 50:
            actions.extend([
                "Perform PII redaction",
                "Review data handling",
                "Conduct privacy assessment",
            ])
        elif risk_score > 25:
            actions.extend([
                "Apply selective PII masking",
                "Update protection policies",
                "Provide staff training",
            ])

        return actions

    def redact(
        self, 
        text: str, 
        pii_report: Optional[Dict[str, Optional[List[str]]]] = None
    ) -> str:
        """
        Redact detected PII from text.

        Args:
            text: Input text to redact
            pii_report: Optional precomputed PII report

        Returns:
            Text with PII redacted
        """
        if not pii_report:
            pii_report = self.detect(text)

        redacted_text = text
        if pii_report and pii_report.get("pii_details"):
            # Redact each PII type
            for pii_type, matches in pii_report["pii_details"].items():
                for match in matches:
                    redacted_text = re.sub(re.escape(match), f"[{pii_type.upper()}_REDACTED]", redacted_text)

        return redacted_text


def analyze_document_compliance(
    document_path: str
) -> Dict[str, Optional[List[str]]]:
    """
    Comprehensive document compliance analysis.

    Args:
        document_path: Path to document for compliance check

    Returns:
        Compliance analysis results
    """
    with open(document_path, "r", encoding="utf-8") as f:
        text = f.read()

    detector = PIIDetector()
    pii_detection = detector.detect(text)

    return {
        "pii_detected": pii_detection.get("pii_detected", False),
        "pii_details": pii_detection.get("pii_details", {}),
        "risk_score": pii_detection.get("risk_score", 0),
        "recommended_actions": pii_detection.get("recommended_actions", []),
    }

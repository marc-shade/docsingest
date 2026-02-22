"""
Defense-grade compliance modules for docsingest.

Provides CUI detection, enhanced PII/PHI detection, document sanitization,
export control screening, and FedRAMP-ready audit trail capabilities.

Compliance Frameworks Supported:
- NIST SP 800-171 (CUI Protection)
- NIST SP 800-53 (Security Controls)
- ITAR (22 CFR 120-130)
- EAR (15 CFR 730-774)
- HIPAA (Health Insurance Portability and Accountability Act)
- 32 CFR Part 2002 (CUI Program)
- FedRAMP (Federal Risk and Authorization Management Program)
"""

from docsingest.compliance.cui_detector import CUIDetector
from docsingest.compliance.enhanced_pii import EnhancedPIIDetector
from docsingest.compliance.sanitizer import DocumentSanitizer
from docsingest.compliance.export_control import ExportControlScreener
from docsingest.compliance.audit_trail import AuditTrail

__all__ = [
    "CUIDetector",
    "EnhancedPIIDetector",
    "DocumentSanitizer",
    "ExportControlScreener",
    "AuditTrail",
]

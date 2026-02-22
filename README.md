# DocsIngest

Defense-grade document ingestion with CUI detection, ITAR/EAR export control screening, PII/PHI protection, document sanitization, and FedRAMP-ready audit trails. Turns any document directory into LLM-friendly text while enforcing federal compliance standards.

## Federal Compliance Coverage

| Framework | Standard | Coverage |
|-----------|----------|----------|
| CUI Program | 32 CFR Part 2002 | CUI marking detection, 80+ category/subcategory validation, marking deficiency checks |
| NIST 800-171 | SP 800-171 Rev 2 | 20+ security controls mapped (3.1.x, 3.3.x, 3.5.x, 3.8.x, 3.13.x) |
| NIST 800-53 | SP 800-53 Rev 5 | AU, SI, AC, MP, SC control families |
| ITAR | 22 CFR 120-130 | USML category detection (I-XXI), technical data screening |
| EAR | 15 CFR 730-774 | ECCN pattern detection, CCL classification |
| HIPAA | 45 CFR 164.514(b)(2) | **All 18 Safe Harbor identifiers** -- full de-identification standard coverage |
| Privacy Act | 5 USC 552a | PII detection with regulatory mapping |
| FedRAMP | AU Family | Tamper-evident audit trail with SHA-256 hash chain, CEF export |
| DFARS | 252.204-7012 | CUI protection requirements for defense contractors |
| PCI DSS | v4.0 | Credit card number detection |
| GLBA | 15 USC 6801 | Financial PII detection (routing numbers, SWIFT/BIC, EIN/TIN) |

## Architecture

```
docsingest/
|-- cli.py                          # CLI entry point with defense compliance flags
|-- ingest.py                       # Core ingestion pipeline with compliance integration
|-- pii_detector.py                 # Basic PII detection (SpaCy NER + regex)
|-- tree_generator.py               # Directory tree generation
|-- compliance/                     # Defense compliance modules
|   |-- __init__.py                 # Module exports
|   |-- cui_detector.py             # CUI detection per 32 CFR Part 2002
|   |-- enhanced_pii.py             # Defense-grade PII/PHI (30+ categories)
|   |-- sanitizer.py                # Document sanitization engine
|   |-- export_control.py           # ITAR/EAR screening (60+ keywords)
|   |-- audit_trail.py              # FedRAMP audit trail with hash chain
|
tests/
|-- test_cui_detector.py            # CUI detection tests
|-- test_enhanced_pii.py            # Enhanced PII/PHI tests
|-- test_sanitizer.py               # Sanitization tests
|-- test_export_control.py          # Export control tests
|-- test_audit_trail.py             # Audit trail tests
```

## Features

### Document Ingestion
- Multi-format support: PDF, DOCX, XLSX, XLS, PPTX, JSON, CSV, XML, MD, TXT
- Automatic encoding detection
- Semantic compression with configurable levels
- `.docsingest_ignore` pattern support
- Comprehensive token counting and reporting

### CUI Detection (32 CFR Part 2002)
- Detects CUI markings: `CUI`, `CUI//SP-xxx`, `CUI//REL TO`
- Validates against **80+ CUI Registry categories and subcategories** from the NARA CUI Registry, including:
  - Critical Infrastructure: CTI, DCRIT, PCII, CEII, SSI
  - Defense: ITAR, EXPT, SAMI, UCNI, NNPI, TFNI
  - Intelligence: INTEL, FISA, HUMINT, SIGINT, GEOINT, OSINT, MASINT
  - Law Enforcement: LES, LESI, GRAND_JURY, INFORMANT, WITNESS, SURVEIL
  - Legal: LEGAL, ATTY_WORK, ATTY_CLIENT, DELIBERATIVE
  - Privacy: PRVCY, PII, HIPAA, GENE, SORN, EDUCATIONAL, SUBSTANCE
  - Financial: TAX, FTI, BANK_SECRECY, PROPIN, PROCUREMENT
  - Nuclear: UCNI, NNPI, NNSA, NUCLEAR
  - Science/Technology: SBIR, STTR, RESEARCH
  - Security: OPSEC, COMSEC, PHYS, INFOSEC, VULN, PENTEST, INCIDENT
- Detects 15+ legacy marking formats (FOUO, SBU, LES, SSI, PCII, CEII, UCNI, NNPI, FTI, COMSEC, etc.)
- Detects classification banners: UNCLASSIFIED, CONFIDENTIAL, SECRET, TOP SECRET, TS//SCI
- Detects dissemination controls: NOFORN, REL TO, ORCON, PROPIN, FISA, IMCON
- Identifies marking deficiencies (missing banners, contradictory markings, legacy FOUO)
- Generates handling recommendations per NIST 800-171
- Risk scoring with NIST control mapping

### Enhanced PII/PHI Detection
- **42+ detection categories** with confidence scoring (high/medium/low)
- **Full HIPAA Safe Harbor coverage** -- all 18 identifier categories per 45 CFR 164.514(b)(2):
  1. Names (via NER)
  2. Geographic subdivisions (zip codes, addresses)
  3. Dates (DOB, admission/discharge, death, ages >89)
  4. Telephone numbers
  5. Fax numbers
  6. Email addresses
  7. Social Security numbers
  8. Medical record numbers
  9. Health plan beneficiary numbers (including subscriber/group IDs)
  10. Account numbers
  11. Certificate/license numbers (driver's license, professional license, DEA)
  12. Vehicle identifiers (VIN)
  13. Device identifiers (UDI, serial numbers)
  14. Web URLs
  15. IP addresses
  16. Biometric identifiers (fingerprint, voiceprint, retinal scan)
  17. Full-face photographs (reference detection)
  18. Other unique identifiers
- Defense PII: DoD ID (EDIPI), CAC numbers, security clearance references, CAGE codes, DUNS numbers, SAM UEI
- Financial PII: bank routing numbers, SWIFT/BIC codes, EIN/TIN, bank accounts, IBAN
- Export control markers: ITAR markings, EAR markings, controlled technical data
- Maps each detection to applicable regulations (HIPAA, Privacy Act, ITAR, PCI DSS, GLBA, DFARS)
- Maps to NIST 800-53 controls (SI-4, SI-19)
- Prioritized remediation actions

### Document Sanitization
- Metadata stripping: author, comments, revision history, tracked changes
- EXIF data detection in embedded images
- Hidden text detection: zero-width characters, CSS hiding (display:none, visibility:hidden, zero-font, white-on-white, zero opacity)
- Macro/script detection and quarantine (VBA, JavaScript, iframes)
- Embedded file extraction and recursive scanning (OLE objects)
- Hyperlink analysis for data exfiltration (IP-based URLs, paste services, data URIs)
- Font fingerprint detection (custom/embedded fonts)
- Hidden Excel sheets, rows, and columns
- SHA-256 hashes before/after for integrity verification

### Export Control Screening (ITAR/EAR)
- USML category references (Category I through XXI) with descriptions
- ECCN pattern detection (e.g., 3A001, 5D002) with CCL category mapping
- **60+ controlled technology keywords**: encryption, night vision, armor, propulsion, guidance, stealth, directed energy, nuclear, biological, underwater, electronic warfare, cyber weapons
- Foreign person/entity detection triggering deemed export rules
- Technical data indicators (TDPs, engineering drawings, distribution statements)
- Dual-use technology detection (Wassenaar, MTCR, Australia Group, NSG)
- Configurable keyword lists for organization-specific screening
- Export classification recommendations

### Audit Trail (FedRAMP-Ready)
- Tamper-evident log with SHA-256 hash chain (each entry hashes the previous)
- Records every document access, transformation, and export
- Tracks who accessed what, when, from where (actor, host, IP)
- CEF (Common Event Format) export for SIEM integration (Splunk, ArcSight, QRadar)
- Chain-of-custody reports for legal/compliance review
- Integrity verification with tamper detection
- File-backed persistence with reload capability
- Maps to NIST 800-53 AU family: AU-2, AU-3, AU-6, AU-8, AU-9, AU-11, AU-12
- Maps to NIST 800-171: 3.3.1, 3.3.2

## Installation

```bash
pip install docsingest

# With compliance module dependencies
pip install docsingest[compliance]

# Development
pip install docsingest[dev]
```

### From Source

```bash
git clone https://github.com/marc-shade/docsingest.git
cd docsingest
pip install -e ".[compliance,dev]"
```

### Requirements
- Python 3.8+
- No external service dependencies -- all detection runs locally

## Usage

### Quick Start -- Defense Mode

```bash
# Full defense compliance scan (CUI + sanitization + export control + enhanced PII + audit)
docsingest /path/to/documents --defense-mode --audit-log audit.jsonl

# Generate separate compliance report
docsingest /path/to/documents --defense-mode --compliance-report compliance_report.md
```

### Individual Compliance Features

```bash
# CUI detection only
docsingest /path/to/documents --cui-scan

# Document sanitization only
docsingest /path/to/documents --sanitize

# Export control screening only
docsingest /path/to/documents --export-control

# Combined with specific output
docsingest /path/to/documents --cui-scan --export-control -o analysis.md --audit-log audit.jsonl
```

### Standard Document Ingestion

```bash
# Basic ingestion
docsingest /path/to/documents

# With compression
docsingest /path/to/documents --compress --compression-level 0.7

# Custom output path
docsingest /path/to/documents -o my_report.md

# Disable PII analysis
docsingest /path/to/documents --no-pii-analysis

# Verbose mode
docsingest /path/to/documents -v
```

### Complete CLI Reference

```
usage: docsingest [-h] [-o OUTPUT] [--agent AGENT] [-p PROMPT]
                  [--no-pii-analysis] [-v] [--compress]
                  [--compression-level COMPRESSION_LEVEL]
                  [--cui-scan] [--sanitize] [--export-control]
                  [--defense-mode] [--audit-log PATH]
                  [--compliance-report PATH]
                  directory

positional arguments:
  directory                   Path to the directory containing documents

options:
  -o, --output OUTPUT         Output markdown file path (default: document_context.md)
  --agent AGENT               Initial AI agent prompt
  -p, --prompt PROMPT         Alternate AI agent prompt
  --no-pii-analysis           Disable PII analysis
  -v, --verbose               Enable verbose output
  --compress                  Compress document content
  --compression-level LEVEL   Compression level (0-1, default: 0.5)

Defense Compliance Options:
  --cui-scan                  Enable CUI detection per 32 CFR Part 2002
  --sanitize                  Enable document sanitization
  --export-control            Enable ITAR/EAR export control screening
  --defense-mode              Enable ALL compliance features
  --audit-log PATH            Path for audit trail output (JSONL with hash chain)
  --compliance-report PATH    Path for separate compliance report (Markdown)
```

### Python API

```python
from docsingest import ingest

# Standard ingestion
summary, tree, content, pii_reports = ingest("/path/to/documents")

# Defense mode -- all compliance features enabled
summary, tree, content, pii_reports = ingest(
    "/path/to/documents",
    cui_scan=True,
    sanitize=True,
    export_control=True,
    enhanced_pii=True,
    audit_log_path="audit.jsonl",
    compliance_report_path="compliance_report.md",
)

# Individual modules
from docsingest.compliance import (
    CUIDetector,
    EnhancedPIIDetector,
    DocumentSanitizer,
    ExportControlScreener,
    AuditTrail,
)

# CUI Detection
detector = CUIDetector()
report = detector.detect(text, filename="document.docx")
print(report.summary)

# Enhanced PII
pii = EnhancedPIIDetector()
report = pii.detect(text, filename="personnel.xlsx")
for detection in report.detections:
    print(f"{detection.category.value}: {detection.confidence} confidence")
    print(f"  Regulations: {[r.value for r in detection.applicable_regulations]}")

# Document Sanitization
sanitizer = DocumentSanitizer()
report = sanitizer.analyze("/path/to/document.docx")
print(f"Macros: {report.macros_detected}")
print(f"Hidden content: {report.hidden_content_detected}")
print(f"SHA-256: {report.sha256_before}")

# Export Control
screener = ExportControlScreener()
report = screener.screen(text, filename="tech_spec.pdf")
print(f"ITAR findings: {report.itar_findings}")
print(f"ECCN patterns: {report.eccn_patterns_found}")

# Custom export control keywords
screener = ExportControlScreener(additional_keywords={
    "custom tech": ("Custom technology", "ITAR", "high"),
})

# Audit Trail
trail = AuditTrail(log_path="audit.jsonl", actor="analyst")
trail.log_document_access("/path/to/doc.txt")
trail.log_compliance_scan("/path/to/doc.txt", "pii", 5, 75)

# Verify integrity
result = trail.verify_integrity()
assert result["verified"] is True

# Export for SIEM
trail.export_cef("audit.cef")

# Chain of custody report
custody = trail.generate_chain_of_custody_report()
```

## Compliance Feature Matrix

| Feature | `--cui-scan` | `--sanitize` | `--export-control` | `--defense-mode` |
|---------|:---:|:---:|:---:|:---:|
| CUI marking detection | X | | | X |
| Classification banners | X | | | X |
| Dissemination controls | X | | | X |
| Marking compliance check | X | | | X |
| Metadata stripping | | X | | X |
| Hidden text detection | | X | | X |
| Macro detection | | X | | X |
| EXIF analysis | | X | | X |
| Font fingerprinting | | X | | X |
| USML category screening | | | X | X |
| ECCN pattern detection | | | X | X |
| Controlled tech keywords | | | X | X |
| Foreign entity detection | | | X | X |
| Enhanced PII/PHI (30+ types) | | | | X |
| Defense-specific PII | | | | X |
| Financial PII | | | | X |
| Audit trail | with `--audit-log` | with `--audit-log` | with `--audit-log` | with `--audit-log` |

## Supported File Types

- PDF (.pdf)
- Microsoft Word (.docx, .doc)
- Microsoft Excel (.xlsx, .xls)
- Microsoft PowerPoint (.pptx, .ppt)
- Markdown (.md)
- Plain Text (.txt)
- CSV (.csv)
- XML (.xml)
- JSON (.json)

## Ignore Patterns

Create a `.docsingest_ignore` file in your document directory:

```
# Ignore log files
*.log

# Ignore git directories
.git/

# Ignore dependencies
node_modules/
```

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific module tests
pytest tests/test_cui_detector.py -v
pytest tests/test_enhanced_pii.py -v
pytest tests/test_sanitizer.py -v
pytest tests/test_export_control.py -v
pytest tests/test_audit_trail.py -v
```

## Development

```bash
git clone https://github.com/marc-shade/docsingest.git
cd docsingest
python -m venv .venv
source .venv/bin/activate
pip install -e ".[compliance,dev]"
pytest tests/ -v
```

## Version History

- **0.2.1** -- Full HIPAA Safe Harbor coverage (all 18 identifiers), 80+ CUI Registry subcategories, regex bug fixes, 213 passing tests
- **0.2.0** -- Defense compliance upgrade: CUI detection, enhanced PII/PHI, document sanitization, ITAR/EAR screening, FedRAMP audit trails
- **0.1.34** -- Multi-format support, semantic compression, basic PII detection

## License

MIT License

## Disclaimer

While DocsIngest provides comprehensive compliance scanning tools, it is a screening aid and not a substitute for professional legal, compliance, or security review. Organizations handling CUI, classified information, or export-controlled data must follow their established security procedures and consult qualified compliance personnel. Always verify findings against authoritative sources and organizational policies.

# DocsIngest

Turn any document directory into a prompt-friendly text ingest for LLMs, with a focus on compliance and comprehensive context generation.

## 🚀 Features

<img src="https://github.com/user-attachments/assets/1d4ff08f-f9ca-4cf8-8164-5bfb2dacaa7e" align="right" style="width:300px;" />

- **Multi-Format Document Support**
  - Ingests PDF, DOCX, Markdown, TXT files
  - Automatic encoding detection
  - Intelligent file type handling
  - **NEW**: Extended support for `.xlsx`, `.xls`, `.pptx`, `.json`, `.csv`, `.xml`

- **Compliance-Focused Ingestion**
  - Pre-configured Compliance Officer prompt
  - Customizable AI agent context
  - Designed for compliance in mind

- **Smart File Processing**
  - Skips system and configuration files
  - Handles temporary and hidden files
  - Supports complex directory structures

- **Metadata and Reporting**
  - Generates comprehensive directory structure tree
  - Counts total files and tokens
  - Provides summary statistics

- **Semantic Compression (NEW)**
  - Intelligently reduce document size while maintaining core meaning
  - Configurable compression levels
  - Preserves full original content
  - Optional compressed view for AI processing

- **Flexible Usage**
  - Command-line interface
  - Importable as a Python package
  - Configurable output options

## 📦 Installation

### Using pip

```bash
pip install docsingest
```

### From Source

```bash
# Clone the repository
git clone https://github.com/marc-shade/docsingest.git

# Navigate to the directory
cd docsingest

# Install the package
pip install -e .
```

## 🚀 Usage

### Basic Document Ingestion
```bash
# Basic usage
docsingest /path/to/documents

# Output to a specific file
docsingest /path/to/documents -o my_report.md

# Verbose mode for detailed logging
docsingest /path/to/documents -v
```

### Advanced Features

#### Content Compression
```bash
# Enable content compression
docsingest /path/to/documents --compress

# Specify compression level (0.0 to 1.0)
docsingest /path/to/documents --compress --compression-level 0.7
```

#### Ignore Files and Directories
Create a `.docsingest_ignore` file in your document directory to exclude specific files and directories:

```bash
# Example .docsingest_ignore
*.log       # Ignore all log files
.git/       # Ignore git directories
node_modules/  # Ignore dependency directories
```

### Compliance and PII Analysis
```bash
# Disable PII analysis
docsingest /path/to/documents --no-pii-analysis

# Custom analysis prompt
docsingest /path/to/documents -p "Analyze these documents for project research"
```

## 🐛 Python Package Usage

```python
from docsingest import ingest

# Basic usage
summary, tree, content = ingest("/path/to/documents")

# Custom agent prompt
summary, tree, content = ingest(
    "/path/to/documents", 
    agent_prompt="Specialized Compliance Analyst"
)
```

## 🛠️ Supported File Types

- PDF
- Microsoft Word (.docx)
- Microsoft Excel (.xlsx, .xls)
- Microsoft PowerPoint (.pptx)
- Markdown (.md)
- Plain Text (.txt)
- CSV
- XML
- JSON

## 🚫 Automatically Skipped Files

- `.DS_Store`
- Temporary Office files (`~$`)
- Temporary files (`.tmp`)
- Log files
- Git-related files and directories
- IDE configuration directories
- Python cache and virtual environment files

## 🔍 Regulatory Compliance Framework

DocsIngest provides a robust, multi-layered approach to regulatory compliance and document risk management:

### 🛡️ Comprehensive Compliance Features

#### Regulatory Compliance Overview
- **Multi-Jurisdiction Support**: Designed to handle compliance requirements across various regulatory landscapes
- **Adaptive Compliance Scanning**: Intelligent detection of sensitive information and potential regulatory risks
- **Configurable Compliance Profiles**: Customizable settings for different industry standards and regulations

#### Risk Assessment Workflow
1. **Document Ingestion Analysis**
   - Automatic classification of document types
   - Identification of sensitive and regulated content
   - Contextual risk scoring

2. **Compliance Risk Evaluation**
   - Detect potential regulatory violations
   - Flag documents with high-risk content
   - Generate detailed compliance reports

3. **Proactive Monitoring**
   - Continuous document scanning
   - Real-time alerts for compliance breaches
   - Audit trail generation

### 🔒 Supported Compliance Domains
- GDPR (General Data Protection Regulation)
- HIPAA (Health Insurance Portability and Accountability Act)
- CCPA (California Consumer Privacy Act)
- SOX (Sarbanes-Oxley Act)
- PCI DSS (Payment Card Industry Data Security Standard)
- NIST Framework
- ISO 27001 Information Security Management

### 🚨 Key Compliance Capabilities
- **Advanced PII Detection**
  - Identify sensitive personal information
  - Support for multiple PII categories:
    * Names
    * Email addresses
    * Phone numbers
    * Social Security Numbers
    * Credit card numbers
- **Intelligent Redaction**
  - Automatic masking of sensitive information
  - Configurable redaction levels
- **Comprehensive Compliance Reporting**
  - Detailed risk assessment
  - Actionable compliance recommendations
- **Multi-Regulation Support**
  - Compliance checks for GDPR, FERPA, COPPA
  - Proactive regulatory alignment

### 🔍 Compliance Verification Process
1. Document Ingestion
2. Automated PII Scanning
3. Risk Assessment and Scoring
4. Compliance Reporting
5. Optional Redaction

**Note**: While DocsIngest provides powerful compliance tools, it is not a substitute for professional legal or compliance advice. Always consult with compliance experts for your specific regulatory requirements.

## 🔧 Development

```bash
# Clone the repository
git clone https://github.com/marc-shade/docsingest.git
cd docsingest

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
pytest tests/
```

## 🤝 Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## 📄 License

MIT License

## 🚀 Roadmap

- [ ] Support more file types
- [ ] Enhanced token estimation
- [ ] Web interface
- [ ] Cloud storage integration
- [ ] Advanced AI prompt customization

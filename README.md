# DocsIngest

Turn any document directory into a prompt-friendly text ingest for LLMs, with a focus on compliance and comprehensive context generation.

## 🚀 Features

- **Multi-Format Document Support**
  - Ingests PDF, DOCX, Markdown, TXT files
  - Automatic encoding detection
  - Intelligent file type handling

- **Compliance-Focused Ingestion**
  - Pre-configured Compliance Officer prompt
  - Customizable AI agent context
  - Designed for education technology compliance scenarios

- **Smart File Processing**
  - Skips system and configuration files
  - Handles temporary and hidden files
  - Supports complex directory structures

- **Metadata and Reporting**
  - Generates comprehensive directory structure tree
  - Counts total files and tokens
  - Provides summary statistics

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

## 💡 Command Line Usage

```bash
# Ingest documents with default Compliance Officer prompt
docsingest /path/to/documents

# Custom AI agent prompt
docsingest /path/to/documents --agent "Financial Auditor" -o financial_report.md
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

## 🔍 Compliance Context Generation

The tool provides a comprehensive compliance-focused context, including:
- Regulatory compliance overview
- Workflow for analysis and risk assessment
- Proactive monitoring recommendations

## 🔧 Development

```bash
# Clone the repository
git clone https://github.com/yourusername/docsingest.git
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

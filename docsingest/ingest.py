import logging
import os
from typing import Dict, Optional, Tuple

from .pii_detector import PIIDetector
from .tree_generator import generate_document_tree

# Default compliance-focused prompt
DEFAULT_COMPLIANCE_PROMPT = """
You are a compliance and risk management AI assistant.
Your task is to:
1. Analyze documents for sensitive information
2. Identify potential compliance risks
3. Provide actionable recommendations
4. Ensure data privacy and protection standards are met
"""


def ingest(
    directory: str,
    agent_prompt: str = DEFAULT_COMPLIANCE_PROMPT,
    output_file: Optional[str] = None,
    pii_analysis: bool = True,
) -> Tuple[str, str, Dict, Dict]:
    """
    Ingest and analyze documents from a given directory.

    Args:
        directory: Path to the directory containing documents
        agent_prompt: Initial prompt for compliance analysis
        output_file: Optional path to save the output
        pii_analysis: Enable/disable PII detection

    Returns:
        Tuple of (summary, document_tree, document_contents, pii_reports)
    """
    # Initialize logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    # Validate input directory
    if not os.path.isdir(directory):
        raise ValueError(f"Invalid directory: {directory}")

    # Track document processing
    document_contents: Dict = {}
    pii_reports: Dict = {}
    total_tokens = 0
    processed_files = 0

    # Optional PII Detector
    pii_detector = PIIDetector() if pii_analysis else None

    # Process documents
    for root, _, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)

            # Skip non-text files
            if not filename.lower().endswith((".txt", ".md", ".log", ".csv")):
                continue

            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()

                # Perform PII detection if enabled
                pii_report = None
                if pii_detector:
                    pii_report = pii_detector.detect(content)
                    pii_reports[filename] = pii_report

                # Store document content
                document_contents[filename] = {
                    "path": filepath,
                    "content": content,
                    "pii_report": pii_report,
                }

                # Update processing metrics
                processed_files += 1
                total_tokens += len(content.split())

            except Exception as e:
                logger.warning(f"Could not process {filename}: {e}")

    # Generate document tree
    document_tree = generate_document_tree(directory)

    # Create summary
    summary = f"""# Document Ingest Summary

## Metadata
- **Total Files**: {processed_files}
- **Total Tokens**: {total_tokens}

## PII Analysis
- **PII Detection**: {'Enabled' if pii_analysis else 'Disabled'}
- **Files with PII**: {sum(1 for report in pii_reports.values()
                            if report.get('pii_detected', False))}
"""

    # Optional: Write to output file
    if output_file:
        with open(output_file, "w") as f:
            f.write(summary)

    return summary, document_tree, document_contents, pii_reports

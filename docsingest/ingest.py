import sys
import os
import re
import logging
from typing import Dict, Optional, Tuple, List
import nltk
from nltk.tokenize import sent_tokenize, word_tokenize
from nltk.corpus import stopwords

# Download necessary NLTK resources
try:
    nltk.download('punkt', quiet=True)
    nltk.download('stopwords', quiet=True)
except Exception as e:
    print(f"Warning: Could not download NLTK resources: {e}", file=sys.stderr)

# Add the parent directory to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import logging
from typing import Dict, Optional, Tuple

# Try importing PIIDetector
try:
    from docsingest.pii_detector import PIIDetector
except ImportError:
    print("Warning: PIIDetector could not be imported", file=sys.stderr)
    PIIDetector = None

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
    input_directory: str,
    agent_prompt: str = None,
    output_file: Optional[str] = None,
    pii_analysis: bool = True,
    verbose: bool = False,
    compress_content: bool = False,
    compression_level: float = 0.5
) -> Tuple[str, str, Dict, Dict]:
    """
    Recursively ingest documents from the specified directory, 
    capturing full text content while protecting PII.
    
    Args:
        input_directory: Path to the directory to ingest documents from
        agent_prompt: Optional agent prompt (for backward compatibility)
        output_file: Optional path to save the output
        pii_analysis: Enable/disable PII detection
        verbose: Enable detailed logging
        compress_content: Whether to compress document content
        compression_level: Level of content compression (0.0 to 1.0)
    
    Returns:
        Tuple of (summary, document_tree, document_contents, pii_reports)
    """
    try:
        # Use default compliance prompt if not specified
        prompt = agent_prompt or DEFAULT_COMPLIANCE_PROMPT

        # Perform document ingestion
        document_context = ingest_documents(
            input_directory, 
            verbose=verbose, 
            compress_content=compress_content, 
            compression_level=compression_level
        )

        # Add output file to context for writing
        document_context['output_file'] = output_file or 'document_context.md'

        # Perform PII analysis if enabled
        pii_reports = {}
        if pii_analysis:
            from .pii_detector import PIIDetector
            pii_detector = PIIDetector()
            
            # Analyze PII for each document
            for directory, docs in document_context.get('document_groups', {}).items():
                for doc in docs:
                    content = doc.get('sanitized_content', '')
                    pii_report = pii_detector.detect(content)
                    if pii_report.get('pii_detected'):
                        pii_reports[doc.get('relative_path', 'Unknown')] = pii_report

        # Write document context to file
        write_document_context(document_context)

        # Generate document tree
        document_tree = generate_document_tree(input_directory)

        # Return comprehensive results
        return (
            document_context.get('summary', 'No summary available'), 
            document_tree, 
            document_context.get('document_groups', {}), 
            pii_reports
        )

    except Exception as e:
        print(f"Error during document analysis: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        raise


def ingest_documents(
    input_directory, 
    verbose=False, 
    compress_content=False, 
    compression_level=0.5
):
    """
    Core document ingestion function
    
    Args:
        input_directory (str): Path to the directory to ingest documents from
        verbose (bool): Enable detailed logging
        compress_content (bool): Whether to compress document content
        compression_level (float): Level of content compression (0.0 to 1.0)
    
    Returns:
        dict: Comprehensive document analysis results
    """
    # Load ignore patterns
    ignore_patterns = load_ignore_patterns(input_directory)
    
    # Setup logging
    log_file = setup_logging() if verbose else None
    
    # Prepare document tracking
    document_groups = {}
    total_tokens = 0
    
    # Walk through directory
    for root, dirs, files in os.walk(input_directory):
        # Apply ignore patterns
        dirs[:] = [d for d in dirs if not any(
            re.search(pattern, os.path.join(root, d)) 
            for pattern in ignore_patterns
        )]
        files = [f for f in files if not any(
            re.search(pattern, os.path.join(root, f)) 
            for pattern in ignore_patterns
        )]
        
        # Process files
        for filename in files:
            file_path = os.path.join(root, filename)
            relative_path = os.path.relpath(file_path, input_directory)
            
            try:
                # Extract text based on file extension
                text_extractor = _get_text_extractor(filename)
                if text_extractor:
                    content = text_extractor(file_path)
                    
                    # Optional compression
                    if compress_content:
                        content = semantic_compress_text(content, compression_level)
                    
                    # Tokenize content
                    tokens = len(content.split())
                    total_tokens += tokens
                    
                    # Group documents by directory
                    directory = os.path.dirname(relative_path) or 'Root'
                    if directory not in document_groups:
                        document_groups[directory] = []
                    
                    document_groups[directory].append({
                        'filename': filename,
                        'relative_path': relative_path,
                        'extension': os.path.splitext(filename)[1],
                        'sanitized_content': content,
                        'tokens': tokens,
                        'compression_applied': compress_content
                    })
                    
            except Exception as e:
                if verbose:
                    logging.error(f"Error processing {file_path}: {e}")
    
    # Prepare summary
    summary = f"""
## Document Ingestion Summary
- **Total Directories**: {len(document_groups)}
- **Total Files Processed**: {sum(len(docs) for docs in document_groups.values())}
- **Total Tokens**: {total_tokens}
- **Compression**: {'Enabled' if compress_content else 'Disabled'}
"""
    
    return {
        'summary': summary,
        'document_groups': document_groups,
        'total_tokens': total_tokens,
        'log_file': log_file
    }


def semantic_compress_text(text: str, compression_level: float = 0.5) -> str:
    """
    Compress text while preserving semantic meaning
    
    Args:
        text (str): Input text to compress
        compression_level (float): Compression ratio (0.0 to 1.0)
    
    Returns:
        str: Compressed text
    """
    if not text or compression_level >= 1.0:
        return text
    
    try:
        # Tokenize sentences
        sentences = sent_tokenize(text)
        
        # If fewer sentences than compression allows, return full text
        if len(sentences) <= 2:
            return text
        
        # Remove stop words and calculate sentence importance
        try:
            stop_words = set(stopwords.words('english'))
        except LookupError:
            # Fallback if stopwords are not available
            stop_words = set()
        
        def sentence_importance(sentence):
            # Tokenize and remove stop words
            words = word_tokenize(sentence.lower())
            meaningful_words = [word for word in words if word.isalnum() and word not in stop_words]
            
            # Score based on unique meaningful words and length
            unique_word_score = len(set(meaningful_words))
            length_score = len(meaningful_words)
            
            return unique_word_score * length_score
        
        # Score sentences
        sentence_scores = [(sent, sentence_importance(sent)) for sent in sentences]
        
        # Sort sentences by importance
        sorted_sentences = sorted(sentence_scores, key=lambda x: x[1], reverse=True)
        
        # Calculate number of sentences to keep
        num_sentences = max(2, int(len(sentences) * compression_level))
        
        # Select top sentences, preserving original order
        top_sentences = sorted(sorted_sentences[:num_sentences], key=lambda x: sentences.index(x[0]))
        compressed_text = ' '.join(sent for sent, _ in top_sentences)
        
        # Add ellipsis if text was compressed
        if len(top_sentences) < len(sentences):
            compressed_text += " ... [Compressed]"
        
        return compressed_text
    
    except Exception as e:
        print(f"Error in semantic compression: {e}", file=sys.stderr)
        return text


def extract_text_from_docx(file_path):
    """Extract text from .docx files"""
    try:
        import docx
        doc = docx.Document(file_path)
        return '\n'.join([para.text for para in doc.paragraphs if para.text])
    except Exception as e:
        print(f"Error extracting text from {file_path}: {e}", file=sys.stderr)
        return f"[Error extracting text from {os.path.basename(file_path)}]"

def extract_text_from_xlsx(file_path):
    """Extract text from .xlsx files"""
    try:
        import openpyxl
        wb = openpyxl.load_workbook(file_path, read_only=True)
        text_content = []
        for sheet in wb:
            for row in sheet.iter_rows(values_only=True):
                row_text = ' '.join(str(cell) for cell in row if cell is not None)
                if row_text.strip():
                    text_content.append(row_text)
        return '\n'.join(text_content)
    except Exception as e:
        print(f"Error extracting text from {file_path}: {e}", file=sys.stderr)
        return f"[Error extracting text from {os.path.basename(file_path)}]"

def extract_text_from_xls(file_path):
    """Extract text from .xls files"""
    try:
        import xlrd
        wb = xlrd.open_workbook(file_path)
        text_content = []
        for sheet in wb.sheets():
            for row in range(sheet.nrows):
                row_text = ' '.join(str(cell.value) for cell in sheet.row(row) if str(cell.value).strip())
                if row_text:
                    text_content.append(row_text)
        return '\n'.join(text_content)
    except Exception as e:
        print(f"Error extracting text from {file_path}: {e}", file=sys.stderr)
        return f"[Error extracting text from {os.path.basename(file_path)}]"

def extract_text_from_pdf(file_path):
    """Extract text from .pdf files"""
    try:
        import PyPDF2
        with open(file_path, 'rb') as file:
            reader = PyPDF2.PdfReader(file)
            text = ''
            for page in reader.pages:
                text += page.extract_text() + '\n'
            return text
    except Exception as e:
        print(f"Error extracting text from {file_path}: {e}", file=sys.stderr)
        return f"[Error extracting text from {os.path.basename(file_path)}]"

def extract_text_from_pptx(file_path):
    """Extract text from .pptx files"""
    try:
        import pptx
        prs = pptx.Presentation(file_path)
        text_content = []
        for slide in prs.slides:
            for shape in slide.shapes:
                if hasattr(shape, "text"):
                    text_content.append(shape.text)
        return '\n'.join(text_content)
    except Exception as e:
        print(f"Error extracting text from {file_path}: {e}", file=sys.stderr)
        return f"[Error extracting text from {os.path.basename(file_path)}]"

def extract_text_from_json(file_path):
    """Extract text from .json files"""
    try:
        import json
        with open(file_path, 'r') as file:
            data = json.load(file)
            return json.dumps(data, indent=2)
    except Exception as e:
        print(f"Error extracting text from {file_path}: {e}", file=sys.stderr)
        return f"[Error extracting text from {os.path.basename(file_path)}]"

def extract_text_from_csv(file_path):
    """Extract text from .csv files"""
    try:
        import csv
        with open(file_path, 'r') as file:
            reader = csv.reader(file)
            return '\n'.join([','.join(row) for row in reader])
    except Exception as e:
        print(f"Error extracting text from {file_path}: {e}", file=sys.stderr)
        return f"[Error extracting text from {os.path.basename(file_path)}]"

def extract_text_from_xml(file_path):
    """Extract text from .xml files"""
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        def extract_text(element):
            text = element.text or ''
            for child in element:
                text += ' ' + extract_text(child)
            return text.strip()
        
        return extract_text(root)
    except Exception as e:
        print(f"Error extracting text from {file_path}: {e}", file=sys.stderr)
        return f"[Error extracting text from {os.path.basename(file_path)}]"

def extract_text_from_markdown(file_path):
    """Extract text from .md files"""
    try:
        import markdown
        with open(file_path, 'r') as file:
            text = file.read()
            # Convert markdown to plain text
            return markdown.markdown(text)
    except Exception as e:
        print(f"Error extracting text from {file_path}: {e}", file=sys.stderr)
        return f"[Error extracting text from {os.path.basename(file_path)}]"


def _get_text_extractor(filename: str):
    """
    Get the appropriate text extractor based on file extension.
    
    Args:
        filename (str): Name of the file to extract text from
    
    Returns:
        Callable or None: Text extraction function or None if no extractor found
    """
    ext = os.path.splitext(filename)[1].lower()
    
    text_extractors = {
        '.docx': extract_text_from_docx,
        '.doc': extract_text_from_docx,  # Fallback for older Word docs
        '.pdf': extract_text_from_pdf,
        '.xlsx': extract_text_from_xlsx,
        '.xls': extract_text_from_xls,
        '.pptx': extract_text_from_pptx,
        '.ppt': extract_text_from_pptx,  # Fallback for older PowerPoint
        '.json': extract_text_from_json,
        '.csv': extract_text_from_csv,
        '.xml': extract_text_from_xml,
        '.md': extract_text_from_markdown,
        '.txt': lambda path: open(path, 'r', encoding='utf-8', errors='replace').read()
    }
    
    # Skip system files and hidden files
    if filename.startswith('.'):
        return None
    
    return text_extractors.get(ext)


def setup_logging():
    """
    Set up logging configuration
    
    Returns:
        str: Path to the log file
    """
    log_directory = os.path.join(os.getcwd(), 'logs')
    os.makedirs(log_directory, exist_ok=True)
    
    log_path = os.path.join(log_directory, 'docsingest.log')
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_path),
            logging.StreamHandler()  # This will also print logs to console
        ]
    )
    
    return log_path

def write_document_context(document_context):
    """
    Write document context to a markdown file with comprehensive details
    
    Args:
        document_context (dict): Comprehensive document analysis results
    """
    try:
        # Use a default output path if not specified
        output_path = document_context.get('output_file', 'document_context.md')
        
        with open(output_path, 'w', encoding='utf-8') as f:
            # Write overall summary
            f.write("# Document Ingestion Report\n\n")
            
            # Write summary from document groups
            summary = document_context.get('summary', '')
            f.write(summary + "\n\n")
            
            # Get document groups
            document_groups = document_context.get('document_groups', {})
            
            # Compute total files
            total_files = sum(len(docs) for docs in document_groups.values())
            
            # Add total files to summary if not already present
            if 'Total Files' not in summary:
                f.write(f"## Summary\n")
                f.write(f"- **Total Files**: {total_files}\n")
                f.write(f"- **Total Tokens**: {document_context.get('total_tokens', 'N/A')}\n\n")
            
            # Sort directories for consistent output
            for directory, dir_docs in sorted(document_groups.items()):
                f.write(f"### Directory: `{directory or 'Root'}`\n")
                f.write(f"**Total Files**: {len(dir_docs)}\n\n")
                
                for doc in sorted(dir_docs, key=lambda x: x['filename']):
                    f.write(f"#### {doc.get('filename', 'Unknown')}\n")
                    f.write(f"- **Path**: `{doc.get('relative_path', 'N/A')}`\n")
                    f.write(f"- **Type**: {doc.get('extension', 'N/A')}\n")
                    f.write(f"- **Tokens**: {doc.get('tokens', 'N/A')}\n")
                    f.write(f"- **Compression Applied**: {doc.get('compression_applied', False)}\n\n")
                    
                    # Full Content Section
                    f.write("##### Full Content\n")
                    f.write("```\n")
                    
                    # Retrieve the full, untruncated content
                    content = doc.get('sanitized_content', 'No content available')
                    
                    # Replace any problematic characters
                    content = content.replace('\x00', '')  # Remove null bytes
                    
                    f.write(content)
                    f.write("\n```\n\n")
                    
                    # Optional Compressed View
                    if doc.get('compression_applied'):
                        f.write("##### Compressed Content View\n")
                        f.write("```\n")
                        
                        # Use the semantic compression function to generate a compressed view
                        compressed_content = semantic_compress_text(content)
                        f.write(compressed_content)
                        f.write("\n```\n\n")

        print(f"Document context written to {output_path}", file=sys.stderr)
        
    except Exception as e:
        print(f"Error in document context writing: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


def generate_document_tree(directory):
    """
    Generate a simple document tree representation
    
    Args:
        directory (str): Root directory to generate tree for
    
    Returns:
        str: Text representation of document tree
    """
    import os
    
    tree = []
    for root, _, files in os.walk(directory):
        level = root.replace(directory, '').count(os.sep)
        indent = ' ' * 4 * level
        tree.append(f"{indent}{os.path.basename(root)}/")
        subindent = ' ' * 4 * (level + 1)
        for file in files:
            tree.append(f"{subindent}{file}")
    
    return '\n'.join(tree)


def load_ignore_patterns(directory: str) -> List[str]:
    """
    Load ignore patterns from .docsingest_ignore file.
    
    Args:
        directory (str): Base directory to search for .docsingest_ignore
    
    Returns:
        List[str]: List of ignore patterns
    """
    ignore_file = os.path.join(directory, '.docsingest_ignore')
    ignore_patterns = []
    
    if os.path.exists(ignore_file):
        with open(ignore_file, 'r') as f:
            ignore_patterns = [
                line.strip() 
                for line in f 
                if line.strip() and not line.startswith('#')
            ]
    
    return ignore_patterns


if __name__ == "__main__":
    import sys
    import argparse
    
    # Create argument parser
    parser = argparse.ArgumentParser(description="Document Ingestion Tool")
    parser.add_argument("input_directory", help="Directory to ingest documents from")
    parser.add_argument("--compress", action="store_true", 
                        help="Enable content compression")
    parser.add_argument("--compression-level", type=float, default=0.5,
                        help="Compression level (0.0 to 1.0, default: 0.5)")
    parser.add_argument("--verbose", action="store_true", 
                        help="Enable verbose logging")
    
    # Parse arguments
    args = parser.parse_args()
    
    # Call ingest function
    try:
        result = ingest(
            args.input_directory, 
            verbose=args.verbose, 
            compress_content=args.compress, 
            compression_level=args.compression_level
        )
        print("Ingest completed successfully", file=sys.stderr)
    except Exception as e:
        print(f"Ingest failed: {e}", file=sys.stderr)
        sys.exit(1)

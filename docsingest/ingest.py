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
    print(f"Starting ingest for directory: {input_directory}", file=sys.stderr)
    print(f"PII Analysis: {pii_analysis}", file=sys.stderr)
    print(f"Verbose mode: {verbose}", file=sys.stderr)
    print(f"Content Compression: {'Enabled' if compress_content else 'Disabled'}", file=sys.stderr)
    
    try:
        # Perform document ingestion
        document_context = ingest_documents(input_directory, verbose, compress_content, compression_level)
        
        # Print diagnostic information
        print("Diagnostic Information:", file=sys.stderr)
        print(f"Total Files: {document_context.get('total_files', 'N/A')}", file=sys.stderr)
        print(f"Total Tokens: {document_context.get('total_tokens', 'N/A')}", file=sys.stderr)
        print(f"Documents Found: {len(document_context.get('documents', []))}", file=sys.stderr)
        
        # Generate summary for backward compatibility
        summary = f"""# Document Ingest Summary

## Metadata
- **Total Files**: {document_context['total_files']}
- **Total Tokens**: {document_context['total_tokens']}

## PII Analysis
- **PII Detection**: {'Enabled' if pii_analysis else 'Disabled'}
- **Files with PII**: {len(document_context['documents'])}
"""

        # Optional: Write to output file
        if output_file:
            with open(output_file, "w") as f:
                f.write(summary)

        # Backward compatibility: Generate document contents and PII reports
        document_contents = {}
        pii_reports = {}
        document_tree = generate_document_tree(input_directory)

        for doc in document_context['documents']:
            document_contents[doc['filename']] = {
                'path': doc['full_path'],
                'content': doc['sanitized_content'],
                'pii_report': None  # Placeholder for future PII reporting
            }

        write_document_context(document_context)
        
        return summary, document_tree, document_contents, pii_reports
    
    except Exception as e:
        print(f"Error during ingest: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        raise


def ingest_documents(input_directory, verbose=False, compress_content=False, compression_level=0.5):
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
    print(f"Starting ingest_documents for {input_directory}", file=sys.stderr)
    print(f"Verbose mode: {verbose}", file=sys.stderr)
    print(f"Content Compression: {'Enabled' if compress_content else 'Disabled'}", file=sys.stderr)
    
    # Ensure input directory exists
    if not os.path.isdir(input_directory):
        print(f"Error: {input_directory} is not a valid directory", file=sys.stderr)
        return {
            'total_files': 0,
            'total_tokens': 0,
            'documents': []
        }
    
    # File type to text extraction mapping
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
    
    # List all files in the directory and subdirectories
    all_files = []
    for root, dirs, files in os.walk(input_directory):
        for file in files:
            # Skip .DS_Store and other system files
            if file.startswith('.'):
                continue
            
            full_path = os.path.join(root, file)
            all_files.append(full_path)
    
    print(f"Total files found: {len(all_files)}", file=sys.stderr)
    
    # Process documents
    documents = []
    total_tokens = 0
    
    for file_path in all_files:
        try:
            # Get file extension
            _, ext = os.path.splitext(file_path)
            ext = ext.lower()
            
            # Skip certain file types
            if ext in ['.ds_store']:
                continue
            
            # Extract text based on file type
            extractor = text_extractors.get(ext)
            if extractor:
                content = extractor(file_path)
            else:
                # Fallback for unsupported file types
                content = f"[Unsupported file type: {file_path}]"
            
            # Optionally compress content
            if compress_content:
                content = semantic_compress_text(content, compression_level)
            
            # Basic document info
            filename = os.path.basename(file_path)
            relative_path = os.path.relpath(file_path, input_directory)
            
            # Estimate tokens (simple approximation)
            tokens = len(content.split())
            total_tokens += tokens
            
            # Create document entry
            doc_entry = {
                'filename': filename,
                'full_path': file_path,
                'relative_path': relative_path,
                'extension': ext,
                'tokens': tokens,
                'sanitized_content': content,
                'compression_applied': compress_content
            }
            
            documents.append(doc_entry)
            
            if verbose:
                print(f"Processed: {relative_path} (Tokens: {tokens})", file=sys.stderr)
        
        except Exception as e:
            print(f"Error processing {file_path}: {e}", file=sys.stderr)
    
    # Create document context
    document_context = {
        'total_files': len(documents),
        'total_tokens': total_tokens,
        'documents': documents,
        'compression_settings': {
            'enabled': compress_content,
            'level': compression_level if compress_content else None
        }
    }
    
    print("Document context created:", file=sys.stderr)
    print(f"Total Files: {document_context['total_files']}", file=sys.stderr)
    print(f"Total Tokens: {document_context['total_tokens']}", file=sys.stderr)
    
    return document_context


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
    print("Starting write_document_context", file=sys.stderr)
    print(f"Document Context Keys: {document_context.keys()}", file=sys.stderr)
    
    try:
        # Use the current directory for output
        output_path = os.path.join(os.getcwd(), 'document_context.md')
        
        with open(output_path, 'w', encoding='utf-8', errors='replace') as f:
            # Document Summary
            f.write("# Document Ingest Analysis\n\n")
            f.write(f"## Summary\n")
            f.write(f"- **Total Files**: {document_context.get('total_files', 'N/A')}\n")
            f.write(f"- **Total Tokens**: {document_context.get('total_tokens', 'N/A')}\n")
            
            # Compression Settings
            compression_settings = document_context.get('compression_settings', {})
            f.write(f"- **Compression**: {'Enabled' if compression_settings.get('enabled') else 'Disabled'}\n")
            if compression_settings.get('enabled'):
                f.write(f"  - **Compression Level**: {compression_settings.get('level', 'N/A')}\n\n")
            
            # Detailed Document Listing
            f.write("## Detailed Document List\n\n")
            
            # Check if documents exist
            documents = document_context.get('documents', [])
            print(f"Number of documents: {len(documents)}", file=sys.stderr)
            
            # Group documents by directory
            document_groups = {}
            for doc in documents:
                directory = os.path.dirname(doc['relative_path'])
                if directory not in document_groups:
                    document_groups[directory] = []
                document_groups[directory].append(doc)
            
            # Write grouped documents
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

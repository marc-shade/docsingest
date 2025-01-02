import os
import chardet
import markdown
import tiktoken
import PyPDF2
import docx


def detect_encoding(file_path):
    """Detect the encoding of a file."""
    with open(file_path, "rb") as file:
        raw_data = file.read()
        result = chardet.detect(raw_data)
    return result["encoding"]


def should_skip_file(file_path):
    """
    Determine if a file should be skipped during ingestion.

    Args:
        file_path (str): Path to the file

    Returns:
        bool: True if file should be skipped, False otherwise
    """
    # List of file patterns to skip
    skip_patterns = [
        ".DS_Store",  # macOS system file
        "~$",  # Temporary Office files
        ".tmp",  # Temporary files
        ".log",  # Log files
        ".gitignore",  # Git ignore file
        ".git",  # Git directory
        "__MACOSX",  # macOS resource fork directory
        ".idea",  # IntelliJ IDEA directory
        ".vscode",  # VS Code directory
        ".venv",  # Python virtual environment
        "node_modules",  # Node.js dependencies
        ".pytest_cache",  # Pytest cache
        "__pycache__",  # Python cache
    ]

    filename = os.path.basename(file_path)

    # Check if filename matches any skip patterns
    return any(pattern in filename or pattern in file_path for pattern in skip_patterns)


def read_file(file_path):
    """Read file content based on its type."""
    # Skip configuration and system files
    if should_skip_file(file_path):
        return ""

    file_ext = os.path.splitext(file_path)[1].lower()

    try:
        encoding = detect_encoding(file_path)

        if file_ext == ".pdf":
            with open(file_path, "rb") as file:
                reader = PyPDF2.PdfReader(file)
                return " ".join(page.extract_text() for page in reader.pages)

        elif file_ext == ".docx":
            doc = docx.Document(file_path)
            return " ".join(para.text for para in doc.paragraphs)

        elif file_ext == ".md":
            with open(file_path, "r", encoding=encoding) as file:
                return markdown.markdown(file.read())

        elif file_ext in [".txt", ".csv", ".json", ".xml"]:
            with open(file_path, "r", encoding=encoding) as file:
                return file.read()

        else:
            return ""  # Skip unsupported file types

    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return ""


def count_tokens(text):
    """Count tokens using tiktoken."""
    encoding = tiktoken.get_encoding("cl100k_base")
    return len(encoding.encode(text))


def generate_directory_tree(root_path):
    """Generate a markdown representation of the directory structure."""
    tree = []
    for root, dirs, files in os.walk(root_path):
        # Remove skipped directories
        dirs[:] = [d for d in dirs if not should_skip_file(os.path.join(root, d))]

        level = root.replace(root_path, "").count(os.sep)
        indent = " " * 4 * level
        tree.append(f"{indent}- {os.path.basename(root)}/")
        subindent = " " * 4 * (level + 1)
        for file in files:
            file_path = os.path.join(root, file)
            if not should_skip_file(file_path):
                tree.append(f"{subindent}- {file}")
    return "\n".join(tree)


DEFAULT_COMPLIANCE_PROMPT = """You are a compliance expert AI agent, specializing in advising companies. Your primary task is to guide the user in achieving and maintaining compliance with all applicable regulations, including FERPA, COPPA, GDPR, state data privacy laws, ADA, and Title IX. You must provide clear, actionable recommendations, assess compliance risks, and offer proactive updates based on changes in relevant regulations.

### Context ###
The company handles sensitive client data through cloud platforms such as Citrix ShareFile and uses security measures like SSO and MFA. Compliance with laws like (FERPA, COPPA) and data privacy standards (GDPR, state laws) is crucial for their operations. Your advice should be aligned with their specific business model.

### Agent Workflow ###
1. **Research and Analysis**: Start by researching the latest regulations related to the query.
2. **Chain-of-Thought (CoT)**: Break down compliance queries into manageable subtasks.
3. **Reflection**: Before finalizing your response, check for accuracy and relevance.
4. **Strategic Chain-of-Thought (SCoT)**: Identify the most effective compliance strategies.
5. **Proactive Updates**: Stay updated on changes in relevant laws.

### Final Notes ###
- Ensure recommendations are tailored to company's business model
- Proactively identify compliance risks
- Maintain an up-to-date understanding of the regulatory landscape
"""


def ingest(directory_path, agent_prompt=None, output_file=None):
    """
    Ingest all documents in a directory and generate a comprehensive markdown file.
    
    Args:
        directory_path (str): Path to the directory containing documents
        agent_prompt (str, optional): Initial AI agent prompt. 
        output_file (str, optional): Path to save the output markdown file
    
    Returns:
        tuple: (summary_stats, directory_tree, document_content)
    """
    # Use the default Compliance Officer prompt if no prompt is provided
    if agent_prompt is None:
        agent_prompt = DEFAULT_COMPLIANCE_PROMPT
    
    all_content = []
    total_files = 0
    total_tokens = 0
    
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            content = read_file(file_path)
            
            if content:
                all_content.append(f"### {file}\n\n{content}\n\n")
                total_files += 1
                total_tokens += count_tokens(content)
    
    directory_tree = generate_directory_tree(directory_path)
    
    summary_stats = f"""# Document Ingest Summary

## Metadata
- **Total Files**: {total_files}
- **Total Tokens**: {total_tokens}
"""
    
    full_content = f"""# AI Agent Context

{agent_prompt}

{summary_stats}

## Directory Structure
{directory_tree}

## Document Contents

{''.join(all_content)}
"""
    
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(full_content)
    
    return summary_stats, directory_tree, full_content

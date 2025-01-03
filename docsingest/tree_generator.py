import os


def generate_document_tree(root_path: str) -> str:
    """
    Generate markdown representation of directory structure.

    Args:
        root_path: Root directory path to generate tree for

    Returns:
        Markdown-formatted directory tree
    """
    tree = []
    for root, dirs, files in os.walk(root_path):
        # Remove skipped directories
        dirs[:] = [d for d in dirs if not _is_skipped_dir(os.path.join(root, d))]

        level = root.replace(root_path, "").count(os.sep)
        indent = " " * 4 * level
        tree.append(f"{indent}- {os.path.basename(root)}/")

        subindent = " " * 4 * (level + 1)
        for file in files:
            file_path = os.path.join(root, file)
            if not _is_skipped_file(file_path):
                tree.append(f"{subindent}- {file}")

    return "\n".join(tree)


def _is_skipped_file(file_path: str) -> bool:
    """
    Determine if a file should be skipped during tree generation.

    Args:
        file_path: Path to the file

    Returns:
        True if file should be skipped, False otherwise
    """
    # List of file patterns to skip
    skip_patterns = [
        ".DS_Store",  # macOS system file
        "~$",  # Temporary Office files
        ".tmp",  # Temporary files
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


def _is_skipped_dir(dir_path: str) -> bool:
    """
    Determine if a directory should be skipped.

    Args:
        dir_path: Path to the directory

    Returns:
        True if directory should be skipped, False otherwise
    """
    skip_patterns = [
        ".git",
        ".venv",
        "node_modules",
        ".pytest_cache",
        "__pycache__",
        ".idea",
        ".vscode",
    ]

    return any(pattern in dir_path for pattern in skip_patterns)

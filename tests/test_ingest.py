import os
import pytest
from docsingest import ingest
from docsingest.tree_generator import _is_skipped_file


def test_ingest_directory():
    test_dir = "/Volumes/FILES/code/content_ingest/input"
    output_file = "/Volumes/FILES/code/content_ingest/test_output.md"

    summary, tree, content, _ = ingest(
        directory=test_dir,
        agent_prompt="Test Compliance Officer",
        output_file=output_file,
    )

    # Validate summary
    assert "**Total Files**" in summary
    assert "**Total Tokens**" in summary

    # Validate tree
    assert len(tree.split("\n")) > 0

    # Validate output file
    assert os.path.exists(output_file)

    # Optional: Clean up
    os.remove(output_file)


def test_empty_directory():
    test_dir = "/tmp/empty_test_dir"
    os.makedirs(test_dir, exist_ok=True)

    summary, tree, content, _ = ingest(directory=test_dir)

    assert "**Total Files**: 0" in summary

    # Clean up
    os.rmdir(test_dir)


def test_skip_files():
    # Test various file patterns to skip
    skip_files = [
        "/path/to/.DS_Store",
        "/path/to/~$document.docx",
        "/path/to/file.tmp",
        "/path/to/.gitignore",
        "/path/to/.git/config",
        "/path/to/__MACOSX/file",
        "/path/to/.idea/project.xml",
        "/path/to/.vscode/settings.json",
        "/path/to/.venv/bin/activate",
        "/path/to/node_modules/package/index.js",
        "/path/to/.pytest_cache/v/cache",
        "/path/to/__pycache__/module.pyc",
    ]

    # Test that these files are skipped
    for file_path in skip_files:
        assert _is_skipped_file(file_path), f"Failed to skip {file_path}"

    # Test some files that should not be skipped
    non_skip_files = [
        "/path/to/document.txt",
        "/path/to/code.py",
        "/path/to/data.csv",
    ]

    for file_path in non_skip_files:
        assert not _is_skipped_file(file_path), f"Incorrectly skipped {file_path}"

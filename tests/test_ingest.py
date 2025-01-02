import os
import pytest
from docsingest import ingest
from docsingest.ingest import should_skip_file


def test_ingest_directory():
    test_dir = "/Volumes/FILES/code/content_ingest/input"
    output_file = "/Volumes/FILES/code/content_ingest/test_output.md"

    summary, tree, content = ingest(
        directory_path=test_dir,
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

    summary, tree, content = ingest(directory_path=test_dir)

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
        "/path/to/.venv/something",
        "/path/to/node_modules/package",
        "/path/to/__pycache__/module",
    ]

    for file_path in skip_files:
        assert should_skip_file(file_path) == True, f"Failed to skip {file_path}"

    # Test files that should not be skipped
    non_skip_files = [
        "/path/to/document.docx",
        "/path/to/important.txt",
        "/path/to/data.csv",
    ]

    for file_path in non_skip_files:
        assert should_skip_file(file_path) == False, f"Incorrectly skipped {file_path}"

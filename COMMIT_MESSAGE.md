# Feature Enhancement: Compression and Ignore Support

## New Features
- Added CLI arguments for content compression
  - `--compress`: Enable content compression
  - `--compression-level`: Control compression ratio (0.0 to 1.0)

- Implemented `.docsingest_ignore` feature
  - Allow excluding specific files and directories
  - Support regex patterns for flexible ignore rules

## Improvements
- Enhanced document processing and reporting
- Updated README with new usage instructions
- Improved error handling and logging
- Added example `.docsingest_ignore` template

## Technical Details
- Modified `cli.py` to support new CLI arguments
- Updated `ingest.py` with compression and ignore pattern logic
- Created `load_ignore_patterns()` function
- Improved `write_document_context()` to handle new document structure

## Usage Examples
```bash
# Compress documents
docsingest /path/to/docs --compress
docsingest /path/to/docs --compress --compression-level 0.7

# Use .docsingest_ignore
# Create a .docsingest_ignore file with patterns like:
# *.log
# .git/
# node_modules/
```

Resolves feature request for more flexible document ingestion and processing.

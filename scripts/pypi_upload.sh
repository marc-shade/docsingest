#!/bin/bash

# Ensure we're in the correct directory
cd "$(dirname "$0")/.."

# Clean previous builds
rm -rf dist
rm -rf build

# Build distribution packages
python3 -m build

# Upload to TestPyPI
if [[ -n "$TESTPYPI_TOKEN" ]]; then
    python3 -m twine upload --repository testpypi dist/*
else
    echo "Error: TESTPYPI_TOKEN environment variable is not set."
    echo "Please set your TestPyPI token before running this script."
    exit 1
fi

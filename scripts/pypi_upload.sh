#!/bin/bash

# Ensure we're in the correct directory
cd "$(dirname "$0")/.."

# Clean previous builds
rm -rf dist
rm -rf build

# Build distribution packages
python3 -m build

# Function to upload to PyPI
upload_to_pypi() {
    local repository=$1
    local token=$2

    if [[ -n "$token" ]]; then
        echo "Uploading to $repository..."
        python3 -m twine upload --repository "$repository" --username __token__ --password "$token" dist/*
    else
        echo "Error: Token for $repository is not set."
        return 1
    fi
}

# Read PyPI token from environment variable
PYPI_TOKEN="${PYPI_API_KEY}"

# Upload to TestPyPI
if [[ -n "$PYPI_TOKEN" ]]; then
    upload_to_pypi testpypi "$PYPI_TOKEN"
fi

# If no token is set, show error
if [[ -z "$PYPI_TOKEN" ]]; then
    echo "Error: No PyPI token found."
    echo "Please set the PYPI_API_KEY environment variable"
    exit 1
fi

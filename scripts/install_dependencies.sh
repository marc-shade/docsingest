#!/bin/bash

# Ensure script is run from the project root
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Check Python version
PYTHON_VERSION=$(python3 --version | cut -d ' ' -f 2)
REQUIRED_PYTHON_VERSION="3.8.0"

# Compare Python versions
if [ "$(printf '%s\n' "$REQUIRED_PYTHON_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_PYTHON_VERSION" ]; then
    echo "Error: Python version must be $REQUIRED_PYTHON_VERSION or higher. Current version: $PYTHON_VERSION"
    exit 1
fi

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv "$PROJECT_ROOT/venv"

# Activate virtual environment
source "$PROJECT_ROOT/venv/bin/activate"

# Upgrade pip and setuptools
pip install --upgrade pip setuptools wheel

# Install production dependencies
echo "Installing production dependencies..."
pip install -r "$PROJECT_ROOT/requirements.txt"

# Install development dependencies
echo "Installing development dependencies..."
pip install -r "$PROJECT_ROOT/requirements-dev.txt"

# Download SpaCy language model
python3 -m spacy download en_core_web_sm

# Deactivate virtual environment
deactivate

echo "Dependencies installed successfully!"

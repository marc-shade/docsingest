# Contributing to DocIngest

We welcome contributions to DocIngest! This document provides guidelines for contributing to the project.

## Getting Started

1. Fork the repository on GitHub
2. Clone your forked repository
3. Create a new branch for your feature or bugfix

## Development Setup

```bash
# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install
```

## Running Tests

```bash
# Run all tests
pytest tests/

# Run with coverage
coverage run -m pytest
coverage report
```

## Code Style

- We use `black` for code formatting
- We use `flake8` for linting
- We use `mypy` for type checking

Before submitting a PR, ensure your code passes all checks:

```bash
pre-commit run --all-files
```

## Submitting a Pull Request

1. Ensure all tests pass
2. Add tests for new functionality
3. Update documentation if needed
4. Write clear, concise commit messages
5. Submit a pull request with a description of your changes

## Reporting Issues

- Use GitHub Issues to report bugs
- Provide a clear, detailed description
- Include steps to reproduce the issue
- If possible, include a minimal reproducible example

## Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Collaborate and support each other

Thank you for contributing to DocIngest!

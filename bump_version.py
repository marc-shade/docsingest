#!/usr/bin/env python3
import os
import re
import subprocess
from typing import Tuple

def get_current_version(file_path: str) -> str:
    with open(file_path, 'r') as f:
        content = f.read()
        version_match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
        return version_match.group(1) if version_match else None

def bump_version(version: str) -> str:
    major, minor, patch = map(int, version.split('.'))
    return f"{major}.{minor}.{patch + 1}"

def update_version_in_file(file_path: str, new_version: str):
    with open(file_path, 'r') as f:
        lines = f.readlines()
    
    with open(file_path, 'w') as f:
        for line in lines:
            if 'version =' in line or 'version=' in line:
                line = re.sub(r'version\s*=\s*["\'][^"\']+["\']', f'version = "{new_version}"', line)
            f.write(line)

def main():
    # Get current version from pyproject.toml
    pyproject_path = 'pyproject.toml'
    setup_path = 'setup.py'
    
    current_version = get_current_version(pyproject_path)
    if not current_version:
        print("Could not find version in pyproject.toml")
        return
    
    # Bump version
    new_version = bump_version(current_version)
    print(f"Bumping version from {current_version} to {new_version}")
    
    # Update version in both files
    update_version_in_file(pyproject_path, new_version)
    update_version_in_file(setup_path, new_version)
    
    # Git commands
    commands = [
        ['git', 'add', pyproject_path, setup_path],
        ['git', 'commit', '-m', f'Bump version to {new_version}'],
        ['git', 'push', 'origin', 'main'],
        ['python3', '-m', 'build'],
        ['python3', '-m', 'twine', 'upload', '--repository', 'testpypi', 'dist/*']
    ]
    
    for cmd in commands:
        try:
            subprocess.run(cmd, check=True)
            print(f"Successfully executed: {' '.join(cmd)}")
        except subprocess.CalledProcessError as e:
            print(f"Error executing {' '.join(cmd)}: {e}")
            return

if __name__ == "__main__":
    main()

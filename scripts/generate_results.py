#!/usr/bin/env python3
"""
Comprehensive Results Generation Script for PII Detection Project
"""

import os
import sys
import subprocess
from datetime import datetime

def run_command(command, cwd=None):
    """
    Run a shell command and capture its output.
    
    Args:
        command (str): Command to run
        cwd (str, optional): Working directory for the command
    
    Returns:
        dict: Command execution results
    """
    try:
        start_time = datetime.now()
        result = subprocess.run(
            command, 
            shell=True, 
            capture_output=True, 
            text=True, 
            cwd=cwd,
            env={**os.environ, 'PYTHONUNBUFFERED': '1'}
        )
        end_time = datetime.now()
        
        return {
            'command': command,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'return_code': result.returncode,
            'start_time': start_time,
            'end_time': end_time,
            'duration': end_time - start_time
        }
    except Exception as e:
        return {
            'command': command,
            'error': str(e),
            'return_code': -1
        }

def generate_comprehensive_report():
    """
    Generate a comprehensive project results report.
    """
    project_root = "/Volumes/FILES/code/content_ingest/docsingest"
    report_path = os.path.join(project_root, "PROJECT_RESULTS.md")
    
    # Activate virtual environment command
    venv_activate = f"source {project_root}/venv/bin/activate && "
    
    # Commands to run
    commands = [
        ("System Information", "uname -a"),
        ("Python Version", "python3 --version"),
        ("Project Dependencies", "pip freeze"),
        ("Running Tests", f"{venv_activate} python3 -m pytest"),
        ("PII Detection Demo", f"{venv_activate} python3 {project_root}/scripts/pii_demo.py")
    ]
    
    results = []
    for title, cmd in commands:
        print(f"Running: {title}")
        result = run_command(cmd, cwd=project_root)
        result['title'] = title
        results.append(result)
    
    # Generate Markdown Report
    with open(report_path, 'w') as f:
        f.write("# Comprehensive Project Results Report\n")
        f.write(f"## Report Generated: {datetime.now().isoformat()}\n\n")
        
        for result in results:
            f.write(f"## {result['title']}\n")
            f.write(f"**Command:** `{result['command']}`\n\n")
            f.write(f"**Return Code:** {result['return_code']}\n\n")
            
            if 'error' in result:
                f.write(f"**Error:** {result['error']}\n\n")
            
            if result.get('stdout'):
                f.write("### Standard Output\n")
                f.write("```\n")
                f.write(result['stdout'])
                f.write("\n```\n\n")
            
            if result.get('stderr'):
                f.write("### Standard Error\n")
                f.write("```\n")
                f.write(result['stderr'])
                f.write("\n```\n\n")
    
    print(f"Report generated at {report_path}")

if __name__ == "__main__":
    generate_comprehensive_report()

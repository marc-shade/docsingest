import argparse
import sys
from .ingest import ingest, DEFAULT_COMPLIANCE_PROMPT

def main():
    """
    Command-line interface for docsingest
    """
    parser = argparse.ArgumentParser(description='AI-powered document ingestion tool')
    
    parser.add_argument('directory', 
                        help='Directory containing documents to ingest')
    
    parser.add_argument('-o', '--output', 
                        help='Output markdown file path')
    
    parser.add_argument('-p', '--prompt', 
                        default=None,
                        help="Initial AI agent prompt (default: Comprehensive Compliance Prompt)")
    
    parser.add_argument('--no-pii-analysis', 
                        action='store_true',
                        help="Disable PII detection and compliance analysis")
    
    args = parser.parse_args()

    try:
        # Use default compliance prompt if not specified
        agent_prompt = args.prompt or DEFAULT_COMPLIANCE_PROMPT
        
        # Perform document ingestion
        summary, tree, content, pii_reports = ingest(
            args.directory, 
            agent_prompt=agent_prompt, 
            output_file=args.output,
            pii_analysis=not args.no_pii_analysis
        )
        
        # Print summary to console
        print(summary)
        
        # If PII analysis was performed, print detailed PII reports
        if not args.no_pii_analysis and pii_reports:
            print("\n## Detailed PII Analysis")
            for filename, report in pii_reports.items():
                print(f"\n### {filename}")
                print(f"- PII Detected: {'Yes' if report.get('pii_detected', False) else 'No'}")
                print(f"- Risk Score: {report.get('risk_score', 'N/A')}")
                if report.get('pii_details'):
                    print("- Detected PII Types:")
                    for pii_type, matches in report['pii_details'].items():
                        print(f"  * {pii_type.upper()}: {matches}")
                if report.get('recommended_actions'):
                    print("- Recommended Actions:")
                    for action in report['recommended_actions']:
                        print(f"  * {action}")
        
        # Indicate successful completion
        print("\nDocument ingestion completed successfully.")
        
        return 0

    except Exception as e:
        print(f"Error during document ingestion: {e}", file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())

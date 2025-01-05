import argparse
import sys
from typing import Optional

from .ingest import DEFAULT_COMPLIANCE_PROMPT, ingest


def main(argv: Optional[list[str]] = None) -> int:
    """
    Command-line interface for docsingest.

    Args:
        argv: Optional list of command-line arguments.

    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    parser = argparse.ArgumentParser(description="AI document analysis tool")

    parser.add_argument("directory", help="Path to documents for analysis")

    parser.add_argument("-o", "--output", help="Path for output markdown")

    parser.add_argument("-p", "--prompt", default=None, help="Custom analysis prompt")

    parser.add_argument(
        "--no-pii-analysis", action="store_true", help="Disable PII detection"
    )

    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )

    # Add compression arguments
    parser.add_argument(
        "--compress", action="store_true", help="Enable content compression"
    )
    parser.add_argument(
        "--compression-level", type=float, default=0.5,
        help="Compression level (0.0 to 1.0, default: 0.5)"
    )

    args = parser.parse_args(argv)

    try:
        # Use default compliance prompt if not specified
        agent_prompt = args.prompt or DEFAULT_COMPLIANCE_PROMPT

        # Set default output if not specified
        output_file = args.output or "document_context.md"

        # Perform document ingestion
        summary, tree, content, pii_reports = ingest(
            args.directory,
            agent_prompt=agent_prompt,
            output_file=output_file,
            pii_analysis=not args.no_pii_analysis,
            verbose=args.verbose,
            compress_content=args.compress,
            compression_level=args.compression_level
        )

        # Print summary to console
        print(summary)

        # If PII analysis was performed, print detailed PII reports
        if not args.no_pii_analysis and pii_reports:
            print("\n## Detailed PII Analysis")
            for filename, report in pii_reports.items():
                _print_pii_report(filename, report)

        # Indicate successful completion
        print(f"\nDocument analysis complete. Output: {output_file}")

        return 0

    except Exception as e:
        print(f"Error during document analysis: {e}", file=sys.stderr)
        return 1


def _print_pii_report(filename: str, report: dict) -> None:
    """
    Print a detailed PII report for a single file.

    Args:
        filename: Name of the file being analyzed
        report: PII detection report dictionary
    """
    print(f"\n### {filename}")
    pii_status = "Yes" if report.get("pii_detected", False) else "No"
    print(f"- PII Detected: {pii_status}")
    print(f"- Risk Score: {report.get('risk_score', 'N/A')}")

    if report.get("pii_details"):
        print("- Detected PII Types:")
        for pii_type, matches in report["pii_details"].items():
            print(f"  * {pii_type.upper()}: {matches}")

    if report.get("recommended_actions"):
        print("- Recommended Actions:")
        for action in report["recommended_actions"]:
            print(f"  * {action}")


if __name__ == "__main__":
    sys.exit(main())

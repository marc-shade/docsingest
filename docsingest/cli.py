import os
import argparse
from .ingest import ingest, DEFAULT_COMPLIANCE_PROMPT


def main():
    parser = argparse.ArgumentParser(
        description="Ingest documents from a directory for AI context."
    )
    parser.add_argument(
        "directory", type=str, help="Path to the directory containing documents"
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="document_context.md",
        help="Output markdown file path (default: document_context.md)",
    )
    parser.add_argument(
        "--agent",
        type=str,
        default=None,
        help="Initial AI agent prompt (default: Comprehensive Compliance Prompt)",
    )

    args = parser.parse_args()

    # Validate directory
    if not os.path.isdir(args.directory):
        print(f"Error: {args.directory} is not a valid directory.")
        return

    # Run ingestion
    summary, tree, content = ingest(
        directory_path=args.directory,
        agent_prompt=args.agent
        if args.agent is not None
        else DEFAULT_COMPLIANCE_PROMPT,
        output_file=args.output,
    )

    print(f"Document ingestion complete. Output saved to {args.output}")
    print("\n--- Summary ---")
    print(summary)


if __name__ == "__main__":
    main()

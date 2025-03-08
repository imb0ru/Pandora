#!/usr/bin/env python3
import argparse
import sys
import os
import json

from analysis.memory_analizer import MemoryAnalyzer

def main():
    parser = argparse.ArgumentParser(
        description="Memory analysis test (Pandora)"
    )
    parser.add_argument(
        "--memdump",
        type=str,
        required=True,
        help="Path to the memory dump file to analyze"
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="(Optional) Path to save the analysis report"
    )
    args = parser.parse_args()

    # Verify the existence of the dump file
    if not os.path.isfile(args.memdump):
        print(f"Memory dump file not found: {args.memdump}")
        sys.exit(1)

    # Initialize the memory analysis module (no need for Volatility path anymore)
    analyzer = MemoryAnalyzer()

    print("Starting memory dump analysis...")
    try:
        report = analyzer.analyze(args.memdump)
    except Exception as e:
        print(f"Error during analysis: {e}")
        sys.exit(1)

    print("Analysis report:")
    print(json.dumps(report, indent=2, ensure_ascii=False))

    if args.output:
        try:
            output_path = analyzer.save_report(report, args.output)
            print(f"Report saved at: {output_path}")
        except Exception as e:
            print(f"Error saving the report: {e}")

if __name__ == "__main__":
    main()

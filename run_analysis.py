#!/usr/bin/env python3
"""CLI entry point for Vulnify analysis."""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "backend"))

from tabulate import tabulate

from pipeline.service import run_analysis


def main() -> None:
    parser = argparse.ArgumentParser(description="Vulnify")
    parser.add_argument(
        "asset_file",
        nargs="?",
        default="data/sample_asset_list.txt",
        help="Path to asset list (default: data/sample_asset_list.txt)",
    )
    args = parser.parse_args()
    path = Path(args.asset_file)
    if not path.exists():
        print(f"File not found: {path}", file=sys.stderr)
        sys.exit(1)

    text = path.read_text(encoding="utf-8")
    result = run_analysis(text)

    if not result.get("success"):
        print("Error:", result.get("error"), file=sys.stderr)
        sys.exit(1)

    rows = result.get("results", [])
    print(f"\nMatched {len(rows)} CVEs (KEV: {result['summary']['kev_count']})\n")
    table = [
        [
            r["rank"],
            r["cve_id"],
            r["affected_asset"][:30],
            r.get("cvss") or "-",
            f"{r['epss']:.4f}",
            r["kev_flag"],
        ]
        for r in rows[:25]
    ]
    print(
        tabulate(
            table,
            headers=["#", "CVE", "Asset", "CVSS", "EPSS", "KEV"],
            tablefmt="simple",
        )
    )
    if len(rows) > 25:
        print(f"\n... and {len(rows) - 25} more (use API export for full CSV)")


if __name__ == "__main__":
    main()

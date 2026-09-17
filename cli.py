"""llm-redlab command-line entry point.

    python cli.py scan            # scan the built-in vulnerable MockTarget

By default it runs against the sandboxed MockTarget so anyone can clone the
repo and get results with no setup and no API key.
"""
from __future__ import annotations

import argparse
import sys

from core.engine import run_all
from core.target import MockTarget
from report.terminal import render


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="llm-redlab")
    sub = parser.add_subparsers(dest="command")
    scan = sub.add_parser("scan", help="run attacks against a target")
    scan.add_argument("--target", default="mock",
                      help="target to scan (default: mock)")

    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 1

    if args.target == "mock":
        target = MockTarget()
    else:
        print(f"Unknown target '{args.target}'. Only 'mock' is available in v1.")
        return 1

    findings = run_all(target)
    render(target.name, findings)

    # Exit non-zero if any attack succeeded (useful as a CI gate).
    return 2 if any(f.succeeded for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

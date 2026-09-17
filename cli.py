"""llm-redlab command-line entry point.

    python cli.py scan                 # scan the built-in LLM chatbot (default)
    python cli.py scan --target rag    # scan the built-in RAG bot

Both targets are sandboxed and ship in the repo, so anyone can clone and run
with no setup and no API key.
"""
from __future__ import annotations

import argparse
import sys

from core.engine import run_all
from core.target import MockTarget
from core.rag_target import RAGTarget
from report.terminal import render


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="llm-redlab")
    sub = parser.add_subparsers(dest="command")
    scan = sub.add_parser("scan", help="run attacks against a target")
    scan.add_argument("--target", default="mock", choices=["mock", "rag"],
                      help="target to scan: mock (LLM chat) or rag")

    args = parser.parse_args(argv)
    if args.command != "scan":
        parser.print_help()
        return 1

    target = RAGTarget() if args.target == "rag" else MockTarget()
    findings = run_all(target)
    render(target.name, findings)
    return 2 if any(f.succeeded for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

"""The engine: orchestrates attack modules against a target.

It loads each attack module, runs it, and collects all findings. Keeping the
engine tiny and module-agnostic means adding a new attack is just adding a
module to the list - the engine never changes.
"""
from __future__ import annotations

from core.finding import Finding
from core.target import Target
from attacks.llm import prompt_injection


def run_all(target: Target) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(prompt_injection.run(target))
    return findings

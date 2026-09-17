"""The engine: orchestrates attack -> score -> remediation for a target.

For every finding it: runs the attack module, scores the result, and (for
successful attacks) attaches a concrete remediation. Adding a new attack is
just adding a module to the list - the pipeline around it never changes.
"""
from __future__ import annotations

from core.finding import Finding
from core.scorer import score
from core.target import Target
from remediation.suggest import remediate
from attacks.llm import prompt_injection


def run_all(target: Target) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(prompt_injection.run(target))

    for f in findings:
        score(f)
        remediate(f)
    return findings

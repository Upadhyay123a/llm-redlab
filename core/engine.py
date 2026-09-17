"""The engine: orchestrates attack -> score -> remediation for a target.

Adding a new attack is just adding its module to the list below; the
score -> remediate -> report pipeline around it never changes.
"""
from __future__ import annotations

from core.finding import Finding
from core.scorer import score
from core.target import Target
from remediation.suggest import remediate
from attacks.llm import prompt_injection, jailbreak


def run_all(target: Target) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(prompt_injection.run(target))
    findings.extend(jailbreak.run(target))

    for f in findings:
        score(f)
        remediate(f)
    return findings

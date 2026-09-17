"""The engine: orchestrates attack -> score -> remediation for a target.

It runs the attack modules that apply to the given target type: LLM chat
attacks against MockTarget, RAG attacks against RAGTarget. Adding a new
attack is just adding its module; the score -> remediate pipeline is shared.
"""
from __future__ import annotations

from core.finding import Finding
from core.scorer import score
from core.target import Target, MockTarget
from core.rag_target import RAGTarget
from remediation.suggest import remediate
from attacks.llm import prompt_injection, jailbreak, system_prompt_leak
from attacks.rag import retrieval_poisoning


def run_all(target: Target) -> list[Finding]:
    findings: list[Finding] = []

    if isinstance(target, RAGTarget):
        findings.extend(retrieval_poisoning.run(target))
    else:
        findings.extend(prompt_injection.run(target))
        findings.extend(jailbreak.run(target))
        findings.extend(system_prompt_leak.run(target))

    for f in findings:
        score(f)
        remediate(f)
    return findings

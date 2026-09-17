"""A Finding: the result of one attack attempt against a target."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Finding:
    attack_id: str          # e.g. "prompt-injection"
    payload_id: str         # which specific payload
    category: str           # human-readable attack category
    succeeded: bool         # did the attack work?
    severity: str = "INFO"  # set later by the scorer
    risk_score: float = 0.0 # 0-10, set later by the scorer
    evidence: str = ""      # the part of the response that proves it
    payload: str = ""       # the input that was sent
    remediation: str = ""   # filled in later by the remediation engine

"""Remediation engine: maps each finding to a concrete, actionable fix.

This is llm-redlab's differentiator. Most tools stop at "you are vulnerable".
This attaches, per finding: why it matters, specific fixes, and a hardened
config the developer can drop in.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from core.finding import Finding

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _load(attack_id: str) -> dict | None:
    path = _TEMPLATE_DIR / f"{attack_id.replace('-', '_')}.yaml"
    if not path.exists():
        return None
    data = yaml.safe_load(path.read_text()) or {}
    return data.get(attack_id)


def remediate(finding: Finding) -> Finding:
    """Attach a remediation string to a successful finding."""
    if not finding.succeeded:
        return finding
    tpl = _load(finding.attack_id)
    if not tpl:
        finding.remediation = "No remediation template available."
        return finding

    lines = [tpl["title"], "", "Why it matters:", tpl["why_it_matters"].strip(), "", "Fixes:"]
    for fix in tpl.get("fixes", []):
        lines.append(f"  - {fix.strip()}")
    if "hardened_system_prompt" in tpl:
        lines += ["", "Hardened system prompt (drop-in):",
                  tpl["hardened_system_prompt"].strip()]
    finding.remediation = "\n".join(lines)
    return finding

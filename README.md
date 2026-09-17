# llm-redlab

![tests](https://github.com/Upadhyay123a/llm-redlab/actions/workflows/tests.yml/badge.svg)

**An AI security lab, plus a web-app security-scanning setup.** This repository
contains two complementary security capabilities:

1. **AI red-team lab** — attacks LLM and RAG applications against built-in
   vulnerable targets, scores each finding, and generates a concrete
   remediation for it.
2. **Web application security scanning** — an operational setup for running
   OWASP ZAP and Nuclei (DAST) against authorized web targets, with a CI
   workflow and a team runbook.

> Most AI security tools tell you *that* you're vulnerable. The AI lab here tells
> you, then **fixes it** — every finding ships with a remediation you can apply.

Everything in the AI lab runs **fully offline against sandboxed targets that ship
in the repo** — no API key, no external systems. The scanning setup is for
**authorized** targets only. For learning and research.

---

# Part 1 — AI Red-Team Lab

## Quickstart

```bash
python -m pip install pyyaml rich pytest
python cli.py scan                 # red-team the built-in LLM chatbot
python cli.py scan --target rag    # red-team the built-in RAG bot
python -m pytest -q                # run the test suite
```

## How it works

Every attack runs the same pipeline:

```
attack payload  ->  vulnerable target  ->  detector (did it work?)
                                              |
                                        score (0-10, severity)
                                              |
                                     remediation (why + how to fix)
                                              |
                                     rich terminal report
```

Concerns are separated: **targets** (the things being attacked), **attack
modules** (payloads + a success detector), a **scorer** (deterministic 0-10
risk), and a **remediation engine** (finding -> concrete fix). Adding a new
attack is just a new module plus a YAML payload file and a remediation template;
the scoring, remediation, and reporting pipeline is reused unchanged.

## Attack coverage

Two target architectures, four attack types, each mapped to the OWASP LLM Top 10.

| Attack | Target | What it does | OWASP |
|--------|--------|--------------|-------|
| **Prompt injection** | LLM chat | Overrides the bot's instructions to dump its hidden system prompt (and the secret inside it) | LLM01 |
| **Jailbreak** | LLM chat | Uses roleplay / developer-mode / emotional pretext to drop safety rules and leak the API key | LLM01 |
| **System-prompt extraction** | LLM chat | Subtle indirect probing (recap, verbatim-echo, debug framing) to leak the system prompt | LLM07 |
| **RAG retrieval poisoning** | RAG bot | A poisoned document in the knowledge base carries a hidden instruction the bot obeys — *indirect* prompt injection, no direct contact with the bot | LLM01 |

Each attack module includes a **benign control** payload that should *not*
succeed, so the tool proves it isn't just flagging everything (no false
positives).

## The two vulnerable targets

- **MockTarget** — a fake customer-service chatbot with a secret system prompt
  (containing a fake API key). It naively obeys instructions in user input, so
  it is vulnerable to injection, jailbreaks, and extraction probes.
- **RAGTarget** — a fake document-retrieval chatbot with a small knowledge base.
  One document is poisoned with a hidden instruction; because the bot treats
  retrieved content as trusted, the poison executes and exfiltrates a secret.

Both are intentionally, contained-ly vulnerable — they exist to be attacked so
the detections and remediations can be demonstrated safely.

## Scoring

Findings are scored by a **documented, deterministic** formula: a base impact
per attack type, plus extra risk when a secret or credential is exposed, mapped
to `LOW / MEDIUM / HIGH / CRITICAL`. The same finding always gets the same score.

## Remediation — the differentiator

Every successful finding is paired with a remediation: a plain-English **why it
matters**, a list of **concrete fixes**, and a **hardened system prompt you can
drop in**. This "find it **and** fix it" loop is what makes the tool genuinely
useful rather than just another vulnerability lister.

## Sample output

```
llm-redlab  -  target: mock-support-bot
10/13 attacks succeeded

  Result    Severity   Risk   Payload ID        Category
  SUCCESS   CRITICAL    9.0   pi-direct-01      Prompt Injection
  SUCCESS   CRITICAL    9.0   jb-roleplay-01    Jailbreak
  SUCCESS   MEDIUM      6.5   spl-recap-01      System Prompt Extraction
  blocked   INFO          -   pi-benign-control Prompt Injection (control)

Remediation - prompt-injection
  Why it matters: ...
  Fixes: ...
  Hardened system prompt (drop-in): ...
```

## AI lab project layout

| Path | Responsibility |
|------|----------------|
| `core/target.py` | Target interface + vulnerable MockTarget (LLM chat) |
| `core/rag_target.py` | Vulnerable RAG target (poisoned knowledge base) |
| `core/engine.py` | Orchestrates attack -> score -> remediation |
| `core/scorer.py` | Deterministic 0-10 risk score + severity band |
| `attacks/llm/` | Prompt injection, jailbreak, extraction modules + payloads |
| `attacks/rag/` | RAG retrieval-poisoning module + payloads |
| `remediation/` | Finding -> fix engine + per-attack templates |
| `report/terminal.py` | Rich colored terminal report |
| `cli.py` | Entry point (`python cli.py scan`) |
| `tests/` | 15 tests: target behavior, detection, scoring, remediation |

---

# Part 2 — Web Application Security Scanning (DAST)

Alongside the AI lab, this repo includes an operational setup for scanning web
applications with two industry-standard tools:

- **OWASP ZAP** — dynamic (DAST) scanning: crawls a running app and probes its
  behavior (missing security headers, CORS/cookie issues, injection points).
- **Nuclei** — template/signature scanning: fires a large library of checks for
  known CVEs, exposed files, and misconfigurations.

They complement each other — ZAP understands app *behavior*, Nuclei matches
*known signatures*. See **[`SECURITY_SCANNING.md`](SECURITY_SCANNING.md)** for
the full runbook: local commands, how to read the output, and how to point the
scans at your own authorized target.

## Automated scanning in CI

`.github/workflows/security-scan.yml` runs a ZAP baseline scan against a
self-contained demo target (OWASP Juice Shop) and uploads the report as a
downloadable artifact.

**Run it:** Actions tab → *security-scan (DAST)* → **Run workflow** → `main`.
When it finishes, open the run → **Artifacts** → download `zap-baseline-report`.

Scan reports are delivered as **CI artifacts** (access-controlled, auto-expiring)
and are **never committed to the repo** — vulnerability details stay out of git
history.

> **Authorization required.** Only scan applications you own or are explicitly
> authorized to test, on staging / non-production environments. Active scans
> send real attack payloads and need extra care.

---

## Framework alignment

AI attacks map to the **OWASP Top 10 for LLM Applications** (LLM01, LLM07) and
the **OWASP Top 10 for Agentic Applications**. Web scanning uses **OWASP ZAP**
and **Nuclei**, aligned with the OWASP web security guidance.

## Disclaimer

For **authorized security testing and educational purposes only.** The AI lab's
attacks run only against the intentionally-vulnerable targets that ship in this
repository. The scanning setup must only be pointed at systems you own or have
explicit written permission to test. Do not use any of this against systems you
do not own or are not authorized to test.

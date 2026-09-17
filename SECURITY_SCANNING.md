# Security Scanning Runbook (DAST)

A practical guide for running dynamic security scans against our web
applications using **OWASP ZAP** and **Nuclei**. This documents the *process*
so anyone on the team can run a scan, read the results, and automate it.

> **Reports are never committed to this repo.** They are produced as CI
> artifacts (access-controlled, auto-expiring) or kept locally. This document
> is the process only.

---

## Authorization first (read this before scanning anything)

Only scan a target you are **explicitly authorized** to test:

- Your own application, on a **staging / local** environment.
- With **written sign-off** from the app owner / security lead.
- **Never** production, and **never** a system you do not own or have
  permission to test.

Passive scans (ZAP baseline) are low-impact. **Active scans send real attack
payloads** and can alter data or cause load — those require extra care and
explicit authorization on a non-production target.

---

## The two tools, and why we use both

| Tool | Type | What it does | Finds |
|------|------|--------------|-------|
| **OWASP ZAP** | DAST (behavioral) | Crawls the running app and probes how it responds | Missing security headers, CORS/cookie issues, clickjacking, reflected inputs |
| **Nuclei** | Template / signature | Fires a large library of precise checks (templates) | Known CVEs, exposed files, tech fingerprints, misconfigurations |

They **complement** each other: ZAP understands app *behavior* by interacting
with it; Nuclei matches *known signatures*. When both flag the same issue
(e.g. missing CSP), confidence is high. Together they give broader coverage
than either alone.

**Important:** a clean automated scan does **not** mean the app is secure. These
tools find known patterns and exposures, not deep business-logic flaws. They are
a floor, not a ceiling — pair them with manual review.

---

## Prerequisites

- Docker installed and runnable without `sudo` (`docker ps` should work).
- Network access from the scanning machine to the target URL.

---

## 1. Run ZAP baseline scan (local)

The baseline scan is passive-leaning and safe for regular use.

```bash
docker run --rm --network host \
  -v "$(pwd):/zap/wrk:rw" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://localhost:3000 -r zap_report.html
```

- Replace `http://localhost:3000` with your authorized target.
- Produces `zap_report.html` in the current directory — open it in a browser.
- The command **exits non-zero when it finds issues** (expected; that is the
  CI-gate behavior, not an error).

**Reading the summary:** `PASS` = checks that found nothing; `WARN` = worth a
look; `FAIL` = crossed the fail threshold. Triage warnings into "fix"
(e.g. missing CSP, permissive CORS), "harden later" (e.g. COEP), and "noise"
(e.g. a timestamp pattern matched inside a CSS file — a common false positive).

## 2. Run ZAP full (active) scan — authorized targets only

The full scan actively sends attack payloads. **Only against an authorized,
non-production target.**

```bash
docker run --rm --network host \
  -v "$(pwd):/zap/wrk:rw" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-full-scan.py -t http://localhost:3000 -r zap_full_report.html
```

Use this deliberately, with sign-off — it is louder and higher-impact than the
baseline.

---

## 3. Run Nuclei (local)

```bash
docker run --rm --network host \
  projectdiscovery/nuclei:latest \
  -u http://localhost:3000
```

To cut noise and focus on what matters, filter by severity and save a report:

```bash
docker run --rm --network host -v "$(pwd):/out" \
  projectdiscovery/nuclei:latest \
  -u http://localhost:3000 \
  -severity low,medium,high,critical \
  -o /out/nuclei_report.txt
```

**Reading Nuclei output:** each line is
`[template-id] [protocol] [severity] URL`. Severity runs
`info < low < medium < high < critical`. `info` findings are usually recon
(tech fingerprints, exposed docs) — useful context, rarely urgent. Prioritize
`high` and `critical`.

---

## 4. Automated scanning in CI (GitHub Actions)

The repo includes `.github/workflows/security-scan.yml`, which runs a ZAP
baseline against a self-contained demo target (OWASP Juice Shop) and uploads
the report as a downloadable artifact.

**To run it:** Actions tab → *security-scan (DAST)* → **Run workflow** → `main`.
When it completes, open the run → **Artifacts** → download `zap-baseline-report`.

**To scan our own app instead of the demo target:**
1. Confirm written authorization for the target.
2. In the workflow, remove the Juice Shop `services:` block and the wait step.
3. Change the ZAP `-t` target to the authorized staging URL.
4. If the app is **internal-only** (not reachable from GitHub's hosted runners),
   register a **self-hosted runner** inside our network and set
   `runs-on: self-hosted`.

Reports are uploaded as artifacts with a retention period — they are **not**
committed to the repo. This keeps vulnerability details in access-controlled,
expiring storage rather than permanent git history.

---

## Troubleshooting notes (from setting this up)

- **`Permission denied: /zap/wrk/...` in CI** — the ZAP container runs as a
  non-root user but the runner workspace is root-owned. Fix by creating the
  report dir, `chmod`-ing it writable, and running the container with
  `--user root`.
- **`No files were found with the provided path`** on artifact upload — the
  report was not written where the upload step looked. Confirm the volume mount
  path matches the `-r` output path, and `ls -la` the report directory in the
  job to verify the file exists before uploading.
- **"Node.js 20 is deprecated"** annotation — a harmless GitHub platform notice
  about the runner, unrelated to the scan.

---

## Scope reminder

This runbook covers **defensive scanning of our own authorized applications**
using industry-standard tools. It is not for testing third-party or
unauthorized systems.

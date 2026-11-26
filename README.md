# permesso (working name)

Authorized security scan + hardening reports for websites and servers, aimed at
SMBs and web agencies. One command, a report a human can act on.

> **Non-negotiable design rule:** permesso refuses to scan a target without a
> valid, signed authorization file for that exact target. Trust is the product.

## What it does today (v0)

1. **Authorization gate** — HMAC-signed authorization files per target, with
   scope (exact host or whole domain), owner contact, and expiry. Tampering,
   expiry, or target mismatch aborts the scan before a single packet is sent.
2. **Scan pipeline** — pluggable adapters:
   - `passive` (built-in, stdlib only): HTTP security headers, HTTPS
     availability/redirect, TLS certificate validity/expiry/self-signing (via
     system `openssl`), server banner and cookie flags.
   - `nuclei` (MIT): template-based web vulnerability scanning.
   - `testssl` (GPL-2.0, invoked as an external process): deep TLS audit.
   - `ssh_audit` (MIT): SSH algorithm/CVE audit.
   - `lynis` (GPL-3.0, invoked as an external process): Linux hardening index
     and suggestions, parsed from a lynis report file.
   - Missing tools are reported as "skipped" in the report — never silently.
3. **Triage** — dedupe, severity ordering, rule-based remediation text, plus
   customer-friendly plain language (`--plain-language --lang en|it`). An LLM
   layer plugs into the `permesso.triage.enhance(llm=...)` hook.
4. **Report** — self-contained HTML (inline CSS, print-friendly) + machine
   readable JSON; brandable via `branding.json` (agency name, text logo,
   accent color, footer) and localized EN/IT.
5. **Drift** — `permesso diff old.json new.json` reports new / resolved /
   kept findings; exit code 10 when new CRITICAL/HIGH appear (wire it to
   cron or CI for alerting).
6. **Validation (`--validate`)** — non-destructive: every passive finding is
   re-confirmed by an independent second observation (or marked transient);
   tool findings carry their own match evidence. Verified findings show a ✓
   badge. No payloads are ever sent; active exploitation is out of scope.
7. **Portal (`permesso portal`)** — static client portal + agency console
   built from scan history: index of all targets, per-target severity trend,
   drift, and links to every report. Host the folder anywhere.
8. **PDF (`permesso pdf report.html`)** — export via wkhtmltopdf or headless
   Chromium when available; a clear install hint when not.

## Quickstart

Requires Python ≥ 3.10 — nothing else.

```bash
# install (from PyPI)
pip install permesso        # or: pipx install permesso (recommended for the CLI)

# one-time: create the signing key
permesso keygen

# authorize a target you own (30 days, this host only)
permesso authorize --target www.example.com --owner you@example.com --days 30

# scan (auto uses every adapter found on PATH; passive always runs)
permesso scan --target www.example.com --out report.html

# track what changed between two scans (exit 10 = new CRITICAL/HIGH)
permesso diff scan-old.json scan-new.json
```

Optional deeper checks — `permesso scan` always runs its built-in passive
checks; the deeper adapters are used automatically when found on PATH.
Run **`permesso doctor`** to see what is missing on your machine with
copy-paste install commands for your platform (user-level installs, no root
needed for the scanner itself):

```bash
permesso doctor
```

Quick reference (Linux, standard user):

```bash
pipx install ssh-audit        # SSH algorithms + CVE audit
# nuclei:     see `permesso doctor` (release binary into ~/.local/bin)
# testssl.sh: git clone --depth 1 https://github.com/drwetter/testssl.sh ~/.local/share/testssl.sh
#             ln -sf ~/.local/share/testssl.sh/testssl.sh ~/.local/bin/testssl.sh
# Lynis runs ON the target server as root: sudo apt install lynis
#             then: permesso scan --target <host> --lynis-report /path/to/lynis-report.dat
```

Development install:

```bash
git clone https://github.com/funkysys-org/permesso.git
cd permesso && pip install -e . && python3 -m unittest discover -s tests
```

Local demo (no external target):

```bash
python3 examples/local_target.py --port 8099 &   # deliberately weak demo server
permesso keygen
permesso authorize --target 127.0.0.1 --owner demo@example.com
permesso scan --target 127.0.0.1 --ports 8099 --out demo-report.html
```

## License policy (verified 2026-11-26 via GitHub API)

| Tool | License | How permesso uses it |
|---|---|---|
| nuclei, httpx, subfinder, naabu, ssh-audit | MIT | may embed |
| docker-bench-security | Apache-2.0 | may embed |
| testssl.sh | GPL-2.0 | **external process only** |
| lynis | GPL-3.0 | **external process only** |

GPL tools are orchestrated as subprocesses, never linked or copied into
permesso's own code, keeping permesso MIT-clean.

## Roadmap

- ✅ **v1 core (built, tested)** — plain-language triage, drift diff,
  branding + EN/IT localized reports
- **Drafts awaiting the owner's go (NOT published)** —
  `distribution/github-action/` (nightly scans + drift alerting) and
  `distribution/agent-skill/` (the agent-hub sales channel)
- **Next** — scheduled/continuous runner, client portal, agency console,
  white-label PDF export, validated PoC exploits (pentest-light)

## Legal

Scan only targets you are authorized to test. The authorization file exists so
that every report is backed by a signed, dated, expiring record of consent.

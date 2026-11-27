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
9. **WordPress (built-in)** — detection, plugin/theme enumeration, user/log/
   config exposure, and vulnerability matching against the CC0
   wpvulnerability.net database. No WPScan, no commercial license needed.

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
# --validate: every passive finding re-checked with an independent second
# observation (non-destructive); --plain-language: customer-facing text
permesso scan --target www.example.com --out report.html \
  --validate --plain-language --lang it

# track what changed between two scans (exit 10 = new CRITICAL/HIGH)
permesso diff scan-old.json scan-new.json

# client portal + agency console from scan history; PDF export
permesso portal
permesso pdf report.html
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

## Use it with AI agents

The skill that drives permesso ships in the open `SKILL.md` format —
[skills/permesso/SKILL.md](skills/permesso/SKILL.md) is the source of truth,
with the authorization rules baked in. The same file works across agents:

```bash
# Claude Code (project: .claude/skills/ — add -g for ~/.claude/skills/)
npx skills add funkysys-org/permesso --skill permesso -a claude-code

# OpenCode / Codex / Cursor (writes .agents/skills/, which they all read)
npx skills add funkysys-org/permesso --skill permesso -a opencode

# OpenClaw / Hermes (ClawHub registry — moderation verdict: clean)
openclaw skills install @funkysys-org/permesso
# page: https://clawhub.ai/funkysys-org/skills/permesso
```

Note: Claude Code does not read the shared `.agents/skills/` folder — for it,
the `.claude/skills/` copy is required (the `-a claude-code` install puts it
there).

## WordPress scanning (built-in)

On WordPress sites permesso adds a dedicated layer, with no external tools
and no licensing:

- **Enumeration (own code):** core version (meta/readme/feed), plugins
  (HTML references + popular-slug probe via `readme.txt`, live popular list
  from api.wordpress.org with a bundled fallback), themes, users exposed
  through the REST API, exposed `debug.log`, content-verified `wp-config`
  backups.
- **Vulnerability matching:** every detected component is checked against
  the [WPVulnerability](https://www.wpvulnerability.net/) database
  (CC0 1.0 data, aggregated from CVE, EUVD, JVN, Patchstack, Wordfence and
  WPScan). Version ranges are matched client-side with PHP
  `version_compare` semantics; more than three matches aggregate into one
  readable finding with the worst severity.
- **Deliberately not shipped: WPScan** — its scanner is dual-licensed
  (commercial use requires a paid license) and its vulnerability API is
  capped at 25 free calls/day, which does not fit agencies scanning client
  sites. The CC0 database covers the same need without either constraint.

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

- ✅ **v0.3.0 (shipped, on PyPI)** — authorization gate, passive + nuclei /
  testssl / ssh-audit / lynis adapters, plain-language triage (EN/IT),
  drift diff, `permesso monitor` (continuous mode), brandable reports,
  `permesso doctor`, non-destructive `--validate`, client portal +
  agency console, PDF export
- ✅ **Distribution live** — PyPI (Trusted Publishing, tag `v*` = release),
  GitHub Pages site, ClawHub skill (multi-agent: OpenClaw/Hermes,
  Claude Code, OpenCode, Codex/Cursor)
- **Template** — `distribution/github-action/permesso-nightly.yml`: copy to
  `.github/workflows/` after setting the 3 secrets to run nightly scans
  with drift alerting
- **Not built (deliberate)** — active exploit PoC: non-destructive
  validation ships instead; weaponized exploitation is a separate product
  decision with legal exposure, and it has not been taken

## Legal

Scan only targets you are authorized to test. The authorization file exists so
that every report is backed by a signed, dated, expiring record of consent.

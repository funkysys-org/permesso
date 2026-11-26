# Changelog

## 0.3.0 — 2026-11-26

- **`--validate`** — non-destructive finding validation: passive findings
  re-confirmed by an independent second observation (transients flagged);
  tool findings marked by source evidence; ✓ badge in reports. No payloads,
  no active exploitation — that stays a separate, deliberate decision.
- **`permesso portal`** — static client portal / agency console from scan
  history: target index, per-target trend, drift, report links (zero deps).
- **`permesso pdf report.html`** — PDF export via wkhtmltopdf or headless
  Chromium (external process); clear install hint when absent.
- `--lang` now drives the report chrome too (not just the finding text).

## 0.2.1 — 2026-11-26

- First PyPI release (Trusted Publishing via publish-pypi.yml).
- Docs: PyPI install in quickstart and landing hero terminal.

## 0.2.0 — 2026-11-26

- **`permesso monitor`** — continuous mode: scan + history
  (`~/.permesso/history/<host>/`) + automatic drift against the previous run;
  exit 10 when new CRITICAL/HIGH findings appear. Cron/CI-ready.
- **Plain-language writer v2** — per-finding meanings (HSTS, CSP, cookies,
  clickjacking, banner/CVE matching, certificate states) in EN and IT,
  replacing generic category text.
- **Release workflows** (distribution/): nightly monitor run for GitHub
  Actions; PyPI publish on tags via Trusted Publishing (inactive until the
  publisher is registered on PyPI).
- Drift fix: same-second reruns no longer overwrite the baseline they diff
  against; history pruned to the last 20 runs.

## 0.1.1 — 2026-11-26

- `permesso doctor` — environment check + copy-paste install recipes per
  adapter (linux/macos, user-level); lynis correctly flagged server-side.
- Skip reasons no longer truncated in CLI output.

## 0.1.0 — 2026-11-26

- First MVP: HMAC-signed authorization gate, passive adapter (stdlib only),
  nuclei/testssl/ssh-audit/lynis adapters (external processes), rule-based
  triage + LLM hook, brandable EN/IT HTML reports, JSON output.

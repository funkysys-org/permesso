# DRAFT agent-hub skill — NOT published. Publishing needs the owner's explicit
# go (see the project decision gate). Intended for: Hermes catalog, ClawHub,
# Claude Code skills.

---
name: permesso
description: >-
  Run authorized security scans of websites and servers with permesso and
  produce client-ready hardening reports. Use when the user asks to check a
  site's or server's security, run a vulnerability scan, or produce a security
  report — ONLY for targets the user is authorized to test.
license: MIT
metadata:
  hub: draft
---

# permesso — authorized scan + hardening report

## Hard rules (the gate is the product)

1. **Never scan a target without an in-session confirmation of ownership or
   written authorization.** Ask explicitly: "Do you own or are you authorized
   to test `<target>`?" and record the answer.
2. Never suggest bypassing, editing, or weakening the authorization gate.
3. Passive checks are still scans: the gate applies to every network touch.

## Workflow

1. Confirm the target and authorization (rule 1). Record owner email.
2. Install (once per machine):
   ```bash
   pip install permesso   # or: pip install git+<repo-url>
   permesso keygen
   ```
3. Authorize and scan:
   ```bash
   permesso authorize --target <host> --owner <user-email> [--scope domain]
   permesso scan --target <host> --plain-language --out report.html --json scan.json
   ```
   Optional depth on servers you control: `ssh-audit` (pip), testssl.sh, lynis.
   Missing tools are listed as "skipped" in the report — report them, don't
   hide them.
4. Read the JSON, then do what the offline writer cannot: rewrite
   `plain_meaning`/`remediation` for the customer's actual stack (nginx?
   WordPress? managed host?) with specific, correct fix steps.
5. Deliver `report.html`; offer `permesso diff` against a previous scan JSON
   for continuous monitoring.

## Report delivery

Reports are self-contained HTML, printable to PDF. Branding comes from
`branding.json` (agency name/logo/color, language en|it).

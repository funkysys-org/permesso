"""permesso doctor — what's installed, what's missing, exact install commands.

Recipes are kept per-platform and verified; they prefer user-level installs
(~/.local/bin, pipx) so a standard account never needs root for the scanner.
Lynis is special: it audits the TARGET server as root — from a laptop it is
expected to be missing, which is not an error.
"""
from __future__ import annotations

import shutil
import sys

from .adapters import _extended_registry

RECIPES: dict[str, dict] = {
    "nuclei": {
        "role": "template-based web vulnerability scanning (the deep web checks)",
        "linux": (
            "mkdir -p ~/.local/bin\n"
            "URL=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest "
            "| python3 -c \"import json,sys;print([a['browser_download_url'] for a in "
            "json.load(sys.stdin)['assets'] if a['name'].endswith('linux_amd64.zip')][0])\")\n"
            "curl -sL \"$URL\" -o /tmp/nuclei.zip\n"
            "python3 -m zipfile -e /tmp/nuclei.zip /tmp/nuclei-x\n"
            "install -m 755 /tmp/nuclei-x/nuclei ~/.local/bin/nuclei\n"
            "nuclei -update-templates   # first run pulls the template database"
        ),
        "macos": "brew install nuclei && nuclei -update-templates",
    },
    "ssh_audit": {
        "role": "SSH algorithms + CVE audit (target must expose SSH to you)",
        "linux": "pipx install ssh-audit",
        "macos": "brew install ssh-audit",
    },
    "testssl": {
        "role": "deep TLS/SSL configuration audit",
        "linux": (
            "git clone --depth 1 https://github.com/drwetter/testssl.sh "
            "~/.local/share/testssl.sh\n"
            "mkdir -p ~/.local/bin && ln -sf ~/.local/share/testssl.sh/testssl.sh "
            "~/.local/bin/testssl.sh"
        ),
        "macos": "brew install testssl.sh",
    },
    "lynis": {
        "role": "Linux hardening audit — runs ON the target server as root, "
                "not from your laptop; expected missing on a scanning machine",
        "linux": (
            "# on the TARGET server:\n"
            "sudo apt install lynis          # Debian 13 ships 3.1.4\n"
            "sudo lynis audit system --quick\n"
            "# then on your machine:\n"
            "permesso scan --target <host> --lynis-report /path/to/lynis-report.dat"
        ),
        "macos": "# lynis runs on the Linux server you are auditing, not on macOS",
    },
}


def base_checks() -> list[tuple[str, bool, str]]:
    def which(name: str) -> tuple[bool, str]:
        p = shutil.which(name)
        return (True, p) if p else (False, "not found")

    checks = [("python", sys.version_info >= (3, 10),
               f"{sys.version.split()[0]} (needs >= 3.10)")]
    for tool in ("openssl", "git", "pipx"):
        ok, detail = which(tool)
        checks.append((tool, ok, detail))
    return checks


def adapter_rows() -> list[dict]:
    reg = _extended_registry()
    platform = "macos" if sys.platform == "darwin" else "linux"
    rows = []
    for name in ("passive", "nuclei", "testssl", "ssh_audit", "lynis"):
        cls = reg.get(name)
        if cls is None:
            rows.append({"name": name, "status": "missing",
                         "detail": "adapter not installed"})
            continue
        instance = cls() if isinstance(cls, type) else cls
        ok, reason = instance.available()
        row = {"name": name, "ok": ok, "reason": reason,
               "role": RECIPES.get(name, {}).get("role", ""),
               "recipe": RECIPES.get(name, {}).get(platform, ""),
               "platform": platform}
        if name == "passive":
            row["status"] = "built-in"
        elif name == "lynis" and not ok:
            row["status"] = "server-side"
        elif ok:
            row["status"] = "ready"
        else:
            row["status"] = "missing"
        rows.append(row)
    return rows


def render() -> str:
    lines = ["permesso doctor — environment check", ""]
    for name, ok, detail in base_checks():
        lines.append(f"  {'✓' if ok else '✗'} {name:8} {detail}")
    lines.append("")
    lines.append(f"  {'ADAPTER':10} {'STATUS':12} ROLE")
    for r in adapter_rows():
        status = {"built-in": "✓ built-in", "ready": "✓ ready",
                  "missing": "✗ missing", "server-side": "◌ server-side"}[r["status"]]
        lines.append(f"  {r['name']:10} {status:12} {r['role']}")
        if r["status"] in ("missing", "server-side") and r.get("recipe"):
            ind = "\n             "
            lines.append(f"             → {ind.join(r['recipe'].splitlines())}")
    lines.append("")
    lines.append("Missing optional tools never break a scan: they are listed as")
    lines.append("'skipped' in the report. Re-run `permesso doctor` after installing.")
    return "\n".join(lines)

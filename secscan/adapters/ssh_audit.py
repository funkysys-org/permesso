"""ssh-audit adapter (MIT, https://github.com/jtesta/ssh-audit)."""
from __future__ import annotations

import json

from ..findings import Finding, FindingSet, Severity
from .base import Adapter


class SshAuditAdapter(Adapter):
    NAME = "ssh_audit"

    def available(self) -> tuple[bool, str]:
        if self.which("ssh-audit"):
            return True, ""
        return False, (
            "ssh-audit not found on PATH. Install: pip install ssh-audit "
            "or https://github.com/jtesta/ssh-audit/releases"
        )

    def run(self, target, opts: dict) -> FindingSet:
        out = FindingSet()
        if 22 not in target.ports:
            return out  # port 22 not in scope
        rc, stdout, stderr = self.run_cmd(
            ["ssh-audit", "-j", target.host], timeout=120,
        )
        start, end = stdout.find("{"), stdout.rfind("}")
        if start == -1 or end == -1:
            return out
        try:
            data = json.loads(stdout[start:end + 1])
        except json.JSONDecodeError:
            return out
        banner = (data.get("banner") or {}).get("raw", "")
        if banner:
            out.add(Finding(
                title="SSH service banner",
                severity=Severity.INFO, source=self.NAME,
                target=f"{target.host}:22", category="ssh",
                evidence=banner[:200],
            ))
        for cve in data.get("cves") or []:
            cid = cve.get("cve", "CVE") if isinstance(cve, dict) else str(cve)
            desc = cve.get("description", "") if isinstance(cve, dict) else ""
            out.add(Finding(
                title=f"SSH vulnerability: {cid}",
                severity=Severity.HIGH, source=self.NAME,
                target=f"{target.host}:22", category="ssh",
                evidence=str(desc)[:300],
                remediation="Update OpenSSH to a version without this CVE.",
                references=[f"https://nvd.nist.gov/vuln/detail/{cid}"],
            ))
        recs = data.get("recommendations") or {}
        for level, sev in (("critical", Severity.MEDIUM), ("warning", Severity.LOW)):
            for rec in recs.get(level) or []:
                text = rec if isinstance(rec, str) else json.dumps(rec)
                out.add(Finding(
                    title=f"SSH hardening: {level} recommendation",
                    severity=sev, source=self.NAME,
                    target=f"{target.host}:22", category="ssh",
                    evidence=text[:300],
                    remediation="Apply the ssh-audit recommendation in sshd_config.",
                ))
        return out

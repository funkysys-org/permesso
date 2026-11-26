"""Lynis adapter (GPL-3.0 — invoked as an EXTERNAL process / report parser).

Runs on the target server itself; from a remote permesso installation you
provide a `lynis-report.dat` copied from the server.
"""
from __future__ import annotations

import pathlib

from ..findings import Finding, FindingSet, Severity
from .base import Adapter

DEFAULT_REPORT_PATHS = ("/var/log/lynis-report.dat", "./lynis-report.dat")


class LynisAdapter(Adapter):
    NAME = "lynis"

    def available(self) -> tuple[bool, str]:
        if self.which("lynis"):
            return True, ""
        if any(pathlib.Path(p).exists() for p in DEFAULT_REPORT_PATHS):
            return True, ""
        return False, (
            "lynis not found on PATH and no lynis-report.dat present. Install: "
            "https://cisofy.com/download/lynis/ — then run 'lynis audit system "
            "--quick' on the server."
        )

    def run(self, target, opts: dict) -> FindingSet:
        out = FindingSet()
        report_path = opts.get("lynis_report")
        path = pathlib.Path(report_path) if report_path else None
        if path is None or not path.exists():
            for candidate in DEFAULT_REPORT_PATHS:
                if pathlib.Path(candidate).exists():
                    path = pathlib.Path(candidate)
                    break
        if path is None or not path.exists():
            return out
        hardening_index, warnings, suggestions = None, [], []
        for line in path.read_text(errors="replace").splitlines():
            if line.startswith("hardening_index="):
                hardening_index = line.split("=", 1)[1]
            elif line.startswith("warning[]="):
                warnings.append(line.split("=", 1)[1])
            elif line.startswith("suggestion[]="):
                suggestions.append(line.split("=", 1)[1])
        if hardening_index:
            idx = int(hardening_index)
            sev = Severity.LOW if idx >= 75 else (
                Severity.MEDIUM if idx >= 55 else Severity.HIGH)
            out.add(Finding(
                title=f"Linux hardening index: {idx}/100",
                severity=sev, source=self.NAME, target=target.host,
                category="hardening",
                evidence=f"lynis hardening index {idx}",
                remediation="Work through the lynis suggestions below.",
            ))
        for w in warnings[:20]:
            out.add(Finding(
                title="Lynis warning",
                severity=Severity.HIGH, source=self.NAME, target=target.host,
                category="hardening", evidence=w[:300],
                remediation="Address the warning reported by lynis.",
            ))
        for s in suggestions[:40]:
            out.add(Finding(
                title="Lynis hardening suggestion",
                severity=Severity.LOW, source=self.NAME, target=target.host,
                category="hardening", evidence=s[:300],
            ))
        return out

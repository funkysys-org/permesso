"""testssl.sh adapter (GPL-2.0 — invoked as an EXTERNAL process only)."""
from __future__ import annotations

import json
import shutil

from ..findings import Finding, FindingSet, Severity
from .base import Adapter

# severities we surface as findings (OK/INFO summaries are context, not alerts)
_REPORTABLE = {"low", "medium", "high", "critical"}


class TestsslAdapter(Adapter):
    NAME = "testssl"

    def available(self) -> tuple[bool, str]:
        tool = self.which("testssl.sh") or self.which("testssl")
        if tool:
            return True, ""
        return False, (
            "testssl.sh not found on PATH. Install: "
            "https://testssl.sh/ (git clone --depth 1 https://github.com/"
            "drwetter/testssl.sh && ./testssl.sh --help)"
        )

    def _binary(self) -> str:
        return self.which("testssl.sh") or self.which("testssl")  # type: ignore[return-value]

    def run(self, target, opts: dict) -> FindingSet:
        out = FindingSet()
        binary = self._binary()
        timeout = int(opts.get("adapter_timeout", 600))
        hostport = target.base_urls()[0].split("//", 1)[1]
        rc, stdout, stderr = self.run_cmd(
            [binary, "--quiet", "--warnings", "off", "--color", "0",
             "--jsonfile", "-", hostport],
            timeout=timeout,
        )
        # testssl writes log noise around the JSON array; find the array itself
        start, end = stdout.find("["), stdout.rfind("]")
        if start == -1 or end == -1:
            return out
        try:
            rows = json.loads(stdout[start:end + 1])
        except json.JSONDecodeError:
            return out
        for row in rows:
            sev_text = str(row.get("severity", "")).lower()
            if sev_text not in _REPORTABLE:
                continue
            finding_id = str(row.get("id", "testssl-finding"))
            out.add(Finding(
                title=f"TLS: {finding_id}",
                severity=Severity.parse(sev_text), source=self.NAME,
                target=hostport, category="tls",
                evidence=str(row.get("finding", ""))[:400],
                remediation="Fix the TLS configuration flagged by testssl.sh "
                            "and re-run the audit.",
            ))
        return out

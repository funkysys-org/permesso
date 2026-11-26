"""nuclei adapter (MIT, https://github.com/projectdiscovery/nuclei)."""
from __future__ import annotations

import json

from ..findings import Finding, FindingSet, Severity
from .base import Adapter


class NucleiAdapter(Adapter):
    NAME = "nuclei"

    def available(self) -> tuple[bool, str]:
        if self.which("nuclei"):
            return True, ""
        return False, (
            "nuclei not found on PATH. Install: "
            "go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest "
            "or download from https://github.com/projectdiscovery/nuclei/releases"
        )

    def run(self, target, opts: dict) -> FindingSet:
        out = FindingSet()
        timeout = int(opts.get("adapter_timeout", 600))
        for url in target.base_urls()[:2]:  # bound runtime for v0
            rc, stdout, stderr = self.run_cmd(
                ["nuclei", "-u", url, "-json", "-silent", "-no-color",
                 "-timeout", "12", "-retries", "1", "-duc"],
                timeout=timeout,
            )
            for line in stdout.splitlines():
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                info = rec.get("info", {}) or {}
                sev = Severity.parse(str(info.get("severity", "info")))
                out.add(Finding(
                    title=str(info.get("name") or rec.get("template-id", "nuclei finding")),
                    severity=sev, source=self.NAME,
                    target=str(rec.get("matched-at") or url),
                    category="vuln",
                    evidence=str(rec.get("matched-at", "")),
                    references=self._refs(info.get("reference")),
                    metadata={"template-id": rec.get("template-id", ""),
                              "tags": info.get("tags", [])},
                ))
        return out

    @staticmethod
    def _refs(reference) -> list[str]:
        if isinstance(reference, list):
            return [str(r) for r in reference]
        if isinstance(reference, str) and reference:
            return [reference]
        return []

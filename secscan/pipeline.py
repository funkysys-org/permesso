"""Scan orchestration: authorization -> adapters -> triage -> result."""
from __future__ import annotations

import datetime as dt
import traceback
from dataclasses import dataclass, field

from . import authorization as authz
from .adapters import resolve
from .findings import FindingSet
from .targets import TargetSpec
from .triage import enhance, executive_summary


@dataclass
class ScanResult:
    host: str
    ports: list[int]
    started_at: str
    finished_at: str
    authorization: dict
    findings: FindingSet
    skipped: list[dict] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "product": "secscan",
            "version": "0.1.0",
            "host": self.host,
            "ports": self.ports,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "authorization": self.authorization,
            "summary": executive_summary(self.findings.counts(), self.host),
            "counts": self.findings.counts(),
            "skipped": self.skipped,
            "errors": self.errors,
            "findings": [f.to_dict() for f in self.findings],
        }


def run_scan(
    spec: TargetSpec,
    key: bytes,
    opts: dict | None = None,
) -> tuple[ScanResult, dict]:
    """Run a full authorized scan.

    Returns (ScanResult, machine-readable dict). Raises AuthorizationError
    before any network activity if authorization is missing/invalid.
    """
    opts = opts or {}
    started = dt.datetime.now(dt.timezone.utc)
    payload = authz.verify(spec.host, key, opts.get("auth_dir", authz.DEFAULT_AUTH_DIR))

    results, skipped, errors = FindingSet(), [], []
    adapters = resolve(opts.get("adapters", "auto"))
    for adapter in adapters:
        ok, reason = adapter.available()
        if not ok:
            skipped.append({"adapter": adapter.NAME, "reason": reason})
            continue
        try:
            results.extend(adapter.run(spec, opts))
        except Exception as exc:  # one broken adapter must not kill the scan
            errors.append({
                "adapter": adapter.NAME,
                "error": f"{type(exc).__name__}: {exc}",
                "trace": traceback.format_exc(limit=2),
            })

    findings = enhance(results.sorted())
    finished = dt.datetime.now(dt.timezone.utc)
    result = ScanResult(
        host=spec.host, ports=spec.ports,
        started_at=started.isoformat(timespec="seconds"),
        finished_at=finished.isoformat(timespec="seconds"),
        authorization=payload,
        findings=FindingSet(findings),
        skipped=skipped, errors=errors,
    )
    return result, result.to_dict()

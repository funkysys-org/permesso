"""Finding model: severity, findings, dedupe and ordering."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name

    @classmethod
    def parse(cls, text: str) -> "Severity":
        mapping = {
            "critical": Severity.CRITICAL, "high": Severity.HIGH,
            "medium": Severity.MEDIUM, "moderate": Severity.MEDIUM,
            "low": Severity.LOW, "info": Severity.INFO,
            "informational": Severity.INFO, "ok": Severity.INFO,
        }
        return mapping.get(str(text).strip().lower(), Severity.INFO)


@dataclass
class Finding:
    title: str
    severity: Severity
    source: str                 # adapter name
    target: str
    category: str = "general"   # headers | tls | vuln | hardening | ssh | info
    evidence: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    @property
    def key(self) -> tuple:
        """Dedupe key: same source+title+target is the same finding."""
        return (self.source, self.title.strip().lower(), self.target)

    @property
    def id(self) -> str:
        h = hashlib.sha1("|".join(str(p) for p in self.key).encode()).hexdigest()[:10]
        return f"SEC-{h}"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["id"] = self.id
        d["severity"] = self.severity.name
        return d


class FindingSet:
    def __init__(self, findings: list[Finding] | None = None):
        self._items: dict[tuple, Finding] = {}
        for f in findings or []:
            self.add(f)

    def add(self, finding: Finding) -> None:
        """Add, keeping the highest severity on duplicate keys."""
        existing = self._items.get(finding.key)
        if existing is None or finding.severity > existing.severity:
            self._items[finding.key] = finding

    def extend(self, findings) -> None:
        for f in findings:
            self.add(f)

    def sorted(self) -> list[Finding]:
        """Most severe first; ties broken by source then title for stability."""
        return sorted(
            self._items.values(),
            key=lambda f: (-f.severity.value, f.source, f.title),
        )

    def counts(self) -> dict[str, int]:
        out = {s.name: 0 for s in Severity}
        for f in self._items.values():
            out[f.severity.name] += 1
        return out

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self):
        return iter(self.sorted())

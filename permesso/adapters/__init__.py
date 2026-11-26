"""Adapter registry."""
from __future__ import annotations

from .base import Adapter
from .nuclei import NucleiAdapter
from .passive import PassiveAdapter

# Optional heavy tools are imported lazily so the stdlib core never breaks.
_REGISTRY: dict[str, type[Adapter]] = {
    "passive": PassiveAdapter,
    "nuclei": NucleiAdapter,
}


def _extended_registry() -> dict[str, type[Adapter]]:
    reg = dict(_REGISTRY)
    try:
        from .testssl import TestsslAdapter
        reg["testssl"] = TestsslAdapter
    except Exception:
        pass
    try:
        from .ssh_audit import SshAuditAdapter
        reg["ssh_audit"] = SshAuditAdapter
    except Exception:
        pass
    try:
        from .lynis import LynisAdapter
        reg["lynis"] = LynisAdapter
    except Exception:
        pass
    return reg


ALL_ADAPTERS = ("passive", "nuclei", "testssl", "ssh_audit", "lynis")


def resolve(names: str | None) -> list[Adapter]:
    """'auto' -> every known adapter (unavailable ones are skipped later)."""
    reg = _extended_registry()
    if not names or names == "auto":
        chosen = list(reg.values())
    else:
        chosen = []
        for n in (x.strip() for x in names.split(",")):
            if not n:
                continue
            if n not in reg:
                raise KeyError(f"unknown adapter '{n}' (known: {', '.join(reg)})")
            chosen.append(reg[n]())
    return [cls() if isinstance(cls, type) else cls for cls in chosen]

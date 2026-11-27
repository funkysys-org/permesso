"""WPVulnerability API client (https://www.wpvulnerability.net — CC0 data).

Endpoints (public, no key, JSON envelope {error, message, data, updated}):
  /core/{version}/    server-side match for a core version
  /plugin/{slug}/     all known vulns; client-side match via `operator`
  /theme/{slug}/      same as plugin

Each vulnerability element: {uuid, name, description, operator?, source[], impact}.
`operator` = {min_version, min_operator, max_version, max_operator, unfixed,
closed}; comparison operators follow PHP version_compare() semantics (lt, le,
eq, ne, gt, ge). API data is CC0 1.0 — commercial use permitted; cite the
source (permesso does: report references point to the given links).
"""
from __future__ import annotations

import json
import operator as _op
import re
import urllib.parse
import urllib.request

from .findings import Severity

BASE = "https://www.wpvulnerability.net"
UA = "permesso (authorized scan; data CC0 by wpvulnerability.net)"

# per-process cache: one scan touches each component once
_CACHE: dict[str, dict | None] = {}

_OPS = {"lt": _op.lt, "le": _op.le, "eq": _op.eq,
        "ne": _op.ne, "gt": _op.gt, "ge": _op.ge}


def _version_tuple(v: str) -> tuple:
    v = str(v).strip().lower().split("-")[0].split("+")[0]
    parts = re.split(r"[^0-9]+", v)
    nums = [int(p) if p.isdigit() else 0 for p in parts if p != ""]
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums[:4])


def compare(a: str, b: str) -> int:
    ta, tb = _version_tuple(a), _version_tuple(b)
    return (ta > tb) - (ta < tb)


def applies(op_block: dict | None, version: str | None) -> bool:
    """True if a vulnerability with this operator block affects `version`."""
    if not op_block:
        return True            # no constraint (e.g. core: server already matched)
    if version in (None, "", "unknown"):
        return False           # cannot compare — do not claim a match
    mn, mx = op_block.get("min_version"), op_block.get("max_version")
    mo, xo = op_block.get("min_operator"), op_block.get("max_operator")
    if mn and mo and not _OPS[mo](compare(version, mn), 0):
        return False
    if mx and xo and not _OPS[xo](compare(version, mx), 0):
        return False
    return True


def severity_from_impact(impact: dict | None) -> Severity:
    if not impact:
        return Severity.MEDIUM
    cvss3 = (impact.get("cvss3") or {})
    sev = str(cvss3.get("severity", "")).lower()
    if not sev:
        sev = str((impact.get("cvss") or {}).get("severity", "")).lower()
    mapping = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
               "medium": Severity.MEDIUM, "moderate": Severity.MEDIUM,
               "low": Severity.LOW, "n": Severity.INFO, "none": Severity.INFO,
               "c": Severity.CRITICAL, "h": Severity.HIGH,
               "m": Severity.MEDIUM, "l": Severity.LOW}
    return mapping.get(sev, Severity.MEDIUM)


def fetch(kind: str, key: str, timeout: int = 10) -> dict | None:
    """GET /{kind}/{key}/ → data payload, or None on any failure."""
    cache_key = f"{kind}/{key}"
    if cache_key in _CACHE:
        return _CACHE[cache_key]
    url = f"{BASE}/{kind}/{urllib.parse.quote(str(key))}/"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA,
                                                   "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8", "replace"))
        data = payload["data"] if payload.get("error") == 0 else None
    except Exception:
        data = None
    _CACHE[cache_key] = data
    return data


def matches(data: dict | None, version: str | None) -> list[dict]:
    """Vulnerability elements in `data` that affect `version`."""
    if not data:
        return []
    vulns = data.get("vulnerability") or []
    out = []
    for v in vulns if isinstance(vulns, list) else []:
        if isinstance(v, dict) and applies(v.get("operator"), version):
            out.append(v)
    return out


def refs_of(vuln: dict) -> list[str]:
    refs = []
    for s in vuln.get("source") or []:
        link = s.get("link")
        if link and link not in refs:
            refs.append(link)
    return refs[:3]

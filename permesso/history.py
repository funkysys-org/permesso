"""Scan history and drift diff: what changed between two scans."""
from __future__ import annotations

import json


def load(path: str) -> dict:
    with open(path) as fh:
        return json.load(fh)


def _by_id(doc: dict) -> dict[str, dict]:
    return {f["id"]: f for f in doc.get("findings", [])}


def diff(old: dict, new: dict) -> dict:
    """Compare two scan documents by finding id (stable across runs)."""
    a, b = _by_id(old), _by_id(new)
    added = [f for fid, f in b.items() if fid not in a]
    resolved = [f for fid, f in a.items() if fid not in b]
    return {
        "old_host": old.get("host"),
        "new_host": new.get("host"),
        "old_started": old.get("started_at"),
        "new_started": new.get("started_at"),
        "added": added,
        "resolved": resolved,
        "kept": len(set(a) & set(b)),
        "counts_before": old.get("counts", {}),
        "counts_after": new.get("counts", {}),
        "has_new_high": any(
            f["severity"] in ("CRITICAL", "HIGH") for f in added
        ),
    }


def render_text(d: dict) -> str:
    lines = [
        f"permesso drift: {d['old_host']} {d['old_started']} -> {d['new_started']}",
        f"findings: {len(d['added'])} new, {len(d['resolved'])} resolved, "
        f"{d['kept']} unchanged",
    ]
    if d["added"]:
        lines.append("NEW:")
        for f in d["added"]:
            lines.append(f"  [{f['severity']:7}] {f['title']} ({f['source']})")
    if d["resolved"]:
        lines.append("RESOLVED:")
        for f in d["resolved"]:
            lines.append(f"  [{f['severity']:7}] {f['title']} ({f['source']})")
    if d["has_new_high"]:
        lines.append("ATTENTION: new CRITICAL/HIGH findings present.")
    return "\n".join(lines)

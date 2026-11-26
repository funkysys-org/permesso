"""Non-destructive finding validation — the safe subset of "validated PoC".

Every finding is either re-confirmed by an independent second observation
(the passive adapter runs again and must reproduce the finding) or marked
as backed by the originating tool's own evidence (e.g. nuclei matched-at).
Nothing here sends payloads, alters target state, or attempts exploitation.
A weaponized exploit layer is deliberately OUT of scope: that is a separate
product decision with legal exposure, and the owner has not taken it.
"""
from __future__ import annotations

from .adapters import resolve
from .findings import Finding


def validate(findings: list[Finding], opts: dict, fresh=None) -> dict:
    """Validate findings; returns stats and stamps finding.metadata['validated'].

    `fresh` (callable -> FindingSet) is injectable for tests; by default it
    re-runs the passive adapter against the same target (one extra round of
    requests, read-only).
    """
    if fresh is None:
        def fresh(spec, opts):
            return resolve("passive")[0].run(spec, opts)

    fresh_set = fresh(opts.get("_spec"), opts)
    fresh_keys = {f.key for f in fresh_set}

    rechecked = evidence = transient = 0
    for f in findings:
        if f.source == "passive":
            if f.key in fresh_keys:
                f.metadata["validated"] = "recheck"
                rechecked += 1
            else:
                f.metadata["validated"] = ""  # not reproduced: transient
                transient += 1
        else:
            f.metadata["validated"] = "source-evidence"
            evidence += 1
    return {
        "mode": "non-destructive",
        "total": len(findings),
        "rechecked": rechecked,
        "by_evidence": evidence,
        "transient": transient,
    }


def note(stats: dict, lang: str = "en") -> str:
    if not stats:
        return ""
    if lang == "it":
        return (f"Validazione non distruttiva: {stats['rechecked']} rilievi "
                f"riverificati live, {stats['by_evidence']} con evidenza dello "
                f"strumento, {stats['transient']} non riprodotti (transitori).")
    return (f"Non-destructive validation: {stats['rechecked']} findings "
            f"re-checked live, {stats['by_evidence']} backed by tool evidence, "
            f"{stats['transient']} not reproduced (transient).")

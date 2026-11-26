"""Continuous monitoring: scan -> keep history -> drift against previous run.

Designed to be driven by cron/CI: every run stores its scan JSON under
~/.permesso/history/<host>/, compares against the previous run, prints the
drift and exits 10 when new CRITICAL/HIGH findings appear (0 otherwise).
Scheduling stays outside permesso (cron, systemd timers, CI) — permesso only
provides the check.
"""
from __future__ import annotations

import datetime as dt
import json
import pathlib

from . import history
from .report.html import render

DEFAULT_HISTORY_DIR = "~/.permesso/history"
KEEP_RUNS = 20


def history_dir(base: str, host: str) -> pathlib.Path:
    p = pathlib.Path(base).expanduser() / host.replace("/", "_")
    p.mkdir(parents=True, exist_ok=True)
    return p


def previous_scan(hdir: pathlib.Path) -> pathlib.Path | None:
    scans = sorted(hdir.glob("scan-*.json"))
    return scans[-1] if scans else None


def prune(hdir: pathlib.Path, keep: int = KEEP_RUNS) -> None:
    scans = sorted(hdir.glob("scan-*.json"))
    for old in scans[:-keep] if len(scans) > keep else []:
        old.unlink()
    reports = sorted(hdir.glob("report-*.html"))
    for old in reports[:-keep] if len(reports) > keep else []:
        old.unlink()


def run_monitor(spec, key, opts: dict | None = None) -> dict:
    """One monitoring tick: scan, store, diff against previous, return drift.

    Raises AuthorizationError before any network activity (same gate as scan).
    """
    opts = dict(opts or {})
    opts.setdefault("adapters", opts.get("adapters", "auto"))
    hdir = history_dir(opts.get("history_dir", DEFAULT_HISTORY_DIR), spec.host)
    prev = previous_scan(hdir)

    # read the previous document BEFORE writing anything: two runs in the same
    # second must not overwrite the baseline they are about to diff against
    old_doc = None
    if prev is not None:
        try:
            old_doc = json.loads(prev.read_text())
        except (json.JSONDecodeError, OSError):
            old_doc = None

    from .pipeline import run_scan  # local import: keeps gate logic in one place
    result, doc = run_scan(spec, key, opts)

    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
    scan_path = hdir / f"scan-{stamp}.json"
    while scan_path.exists():  # same-second reruns stay unique
        stamp += "x"
        scan_path = hdir / f"scan-{stamp}.json"
    scan_path.write_text(json.dumps(doc, indent=2))

    out = opts.get("out")
    report_path = pathlib.Path(out) if out else hdir / f"report-{stamp}.html"
    from .branding import load as load_branding
    branding = load_branding(opts.get("branding"))
    branding.setdefault("language", opts.get("lang", "en"))  # --lang drives labels
    report_path.write_text(render(doc, branding))

    drift = None
    if old_doc and old_doc.get("findings") is not None:
        d = history.diff(old_doc, doc)
        drift = {"previous": str(prev), "text": history.render_text(d), **d}

    prune(hdir)
    return {
        "scan": doc,
        "scan_path": str(scan_path),
        "report_path": str(report_path),
        "history_dir": str(hdir),
        "baseline": prev is None,
        "drift": drift,
    }

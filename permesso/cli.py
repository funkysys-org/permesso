"""permesso command line interface."""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time

from . import __version__, authorization as authz
from .branding import load as load_branding
from .history import diff as diff_scans
from .history import render_text as render_diff
from .pipeline import run_scan
from .report.html import render
from .targets import TargetSpec


def _cmd_keygen(args) -> int:
    path = args.key_path or authz.DEFAULT_KEY_PATH
    authz.load_or_create_key(path)
    print(f"signing key ready: {path}")
    return 0


def _cmd_authorize(args) -> int:
    key = authz.load_or_create_key(args.key_path or authz.DEFAULT_KEY_PATH)
    doc = authz.authorize(
        target=args.target, owner=args.owner, key=key,
        scope=args.scope, days=args.days,
        auth_dir=args.auth_dir or authz.DEFAULT_AUTH_DIR,
    )
    payload = doc["authorization"]
    print(f"authorization saved for {payload['target']} "
          f"(scope={payload['scope']}, expires {payload['expires_at']})")
    return 0


def _cmd_scan(args) -> int:
    try:
        spec = TargetSpec.parse(args.target, args.ports)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    key = authz.load_or_create_key(args.key_path or authz.DEFAULT_KEY_PATH)
    opts = {
        "adapters": args.adapters,
        "auth_dir": args.auth_dir or authz.DEFAULT_AUTH_DIR,
        "adapter_timeout": args.adapter_timeout,
        "lynis_report": args.lynis_report,
        "plain_language": args.plain_language,
        "lang": args.lang,
    }
    try:
        result, doc = run_scan(spec, key, opts)
    except authz.AuthorizationError as exc:
        print(f"UNAUTHORIZED: {exc}", file=sys.stderr)
        return 2
    stamp = time.strftime("%Y%m%d-%H%M%S")
    json_path = args.json or f"scan-{spec.host}-{stamp}.json"
    out_path = args.out or f"report-{spec.host}-{stamp}.html"
    pathlib.Path(json_path).write_text(json.dumps(doc, indent=2))
    pathlib.Path(out_path).write_text(render(doc, load_branding(args.branding)))
    counts = doc["counts"]
    total = len(doc["findings"])
    print(f"scan complete: {total} finding(s) "
          f"(C:{counts.get('CRITICAL', 0)} H:{counts.get('HIGH', 0)} "
          f"M:{counts.get('MEDIUM', 0)} L:{counts.get('LOW', 0)} "
          f"I:{counts.get('INFO', 0)})")
    for s in doc["skipped"]:
        print(f"skipped {s['adapter']}: {s['reason']}")
    print(f"report: {out_path}\njson:   {json_path}")
    return 0


def _cmd_report(args) -> int:
    doc = json.loads(pathlib.Path(args.json).read_text())
    pathlib.Path(args.out).write_text(render(doc, load_branding(args.branding)))
    print(f"report: {args.out}")
    return 0


def _cmd_diff(args) -> int:
    old = diff_scans(json.loads(pathlib.Path(args.old).read_text()),
                     json.loads(pathlib.Path(args.new).read_text()))
    text = render_diff(old)
    print(text)
    if args.out:
        pathlib.Path(args.out).write_text(text + "\n")
    return 10 if old["has_new_high"] else 0


def _cmd_doctor(args) -> int:
    from .doctor import render
    print(render())
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="permesso",
        description="Authorized scan + hardening reports for websites and servers",
    )
    parser.add_argument("--version", action="version",
                        version=f"permesso {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="create the local signing key")
    p.add_argument("--key-path", default=None)
    p.set_defaults(fn=_cmd_keygen)

    p = sub.add_parser("authorize", help="authorize a target you own")
    p.add_argument("--target", required=True)
    p.add_argument("--owner", required=True, help="email of the authorizing person")
    p.add_argument("--scope", choices=("host", "domain"), default="host")
    p.add_argument("--days", type=int, default=30)
    p.add_argument("--key-path", default=None)
    p.add_argument("--auth-dir", default=None)
    p.set_defaults(fn=_cmd_authorize)

    p = sub.add_parser("scan", help="scan an authorized target")
    p.add_argument("--target", required=True, help="bare host or IP (no URL)")
    p.add_argument("--ports", default=None, help="comma-separated, default 80,443")
    p.add_argument("--adapters", default="auto",
                   help="auto or comma list: passive,nuclei,testssl,ssh_audit,lynis")
    p.add_argument("--key-path", default=None)
    p.add_argument("--auth-dir", default=None)
    p.add_argument("--adapter-timeout", type=int, default=600)
    p.add_argument("--lynis-report", default=None,
                   help="path to a lynis-report.dat from the target server")
    p.add_argument("--branding", default=None, help="branding.json path")
    p.add_argument("--out", default=None, help="HTML report path")
    p.add_argument("--json", default=None, help="machine-readable scan path")
    p.add_argument("--plain-language", action="store_true",
                   help="add customer-friendly 'what this means' text per finding")
    p.add_argument("--lang", default="en", choices=("en", "it"),
                   help="language for plain-language text")
    p.set_defaults(fn=_cmd_scan)

    p = sub.add_parser("report", help="re-render a report from a scan JSON")
    p.add_argument("--json", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--branding", default=None, help="branding.json path")
    p.set_defaults(fn=_cmd_report)

    p = sub.add_parser("diff", help="compare two scan JSONs (drift)")
    p.add_argument("old")
    p.add_argument("new")
    p.add_argument("--out", default=None, help="save the drift text to a file")
    p.set_defaults(fn=_cmd_diff)

    p = sub.add_parser("doctor", help="check installed adapters, show install recipes")
    p.set_defaults(fn=_cmd_doctor)

    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())

"""Client portal + agency console (static, zero-dependency).

Builds an index page (all targets — the agency console view) and one page
per target (the client portal view) from the scan history directory:
severity trend, drift since the previous scan, and links to every report.
Everything is static HTML: agencies can host it anywhere or send a file.
"""
from __future__ import annotations

import html
import json
import pathlib

from . import history

_CSS = """
*{box-sizing:border-box;margin:0}
body{font:15px/1.55 -apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
background:#fbfaf7;color:#182635;padding:32px 22px}
.wrap{max-width:920px;margin:0 auto}
h1{font-size:24px;margin-bottom:2px} h2{font-size:17px;margin:26px 0 10px;
border-bottom:2px solid #23408e;padding-bottom:6px}
.muted{color:#5b6470;font-size:13.5px}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #e5e2da}
th{font-size:12px;text-transform:uppercase;letter-spacing:.6px;color:#5b6470}
a{color:#23408e}
.chips{display:flex;gap:6px;flex-wrap:wrap;margin:10px 0}
.chip{color:#fff;font-weight:700;font-size:11.5px;padding:2px 9px;border-radius:14px}
pre{background:#f1f3f6;border:1px solid #e5e2da;border-radius:8px;padding:10px;
font:12.5px/1.6 ui-monospace,Menlo,Consolas,monospace;overflow-x:auto}
.spark{display:block;margin-top:6px}
"""


def _chips(counts: dict) -> str:
    colors = {"CRITICAL": "#a4080e", "HIGH": "#d13b10", "MEDIUM": "#c78a03",
              "LOW": "#3a7a2a", "INFO": "#5b6470"}
    return "".join(
        f'<span class="chip" style="background:{colors[s]}">{s[0]}:{counts.get(s, 0)}</span>'
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))


def _spark(values: list[int], w=220, h=36) -> str:
    if not values:
        return ""
    mx = max(values + [1])
    pts = " ".join(
        f"{round(2 + i * (w - 4) / max(len(values) - 1, 1), 1)},"
        f"{round(h - 2 - v * (h - 6) / mx, 1)}"
        for i, v in enumerate(values))
    return (f'<svg class="spark" width="{w}" height="{h}" viewBox="0 0 {w} {h}">'
            f'<polyline fill="none" stroke="#23408e" stroke-width="2" '
            f'points="{pts}"/></svg>')


def _page(title: str, body: str, accent="#23408e") -> str:
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<style>{_CSS.replace('#23408e', accent)}</style></head>
<body><div class="wrap">{body}</div></body></html>"""


def _host_docs(host_dir: pathlib.Path) -> list[dict]:
    docs = []
    for p in sorted(host_dir.glob("scan-*.json")):
        try:
            docs.append(json.loads(p.read_text()))
        except (json.JSONDecodeError, OSError):
            continue
    return docs


def _reports_for(host_dir: pathlib.Path, doc: dict) -> list[str]:
    started = str(doc.get("started_at", ""))
    return sorted(p.name for p in host_dir.glob("report-*.html")
                  if started[:11] in p.name or started[:8].replace("-", "") in p.name)


def build_portal(history_dir: str, out_dir: str, branding: dict | None = None,
                 title: str | None = None) -> list[str]:
    branding = branding or {}
    accent = branding.get("accent_color", "#23408e")
    label = branding.get("logo_text", "permesso")
    base = pathlib.Path(history_dir).expanduser()
    out = pathlib.Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: list[str] = []

    hosts = sorted(d.name for d in base.iterdir() if d.is_dir() and _host_docs(d))
    if not hosts:
        raise SystemExit(f"no scans found under {base}")

    # ---- per-target client pages -------------------------------------
    rows = []
    for host in hosts:
        hdir = base / host
        docs = _host_docs(hdir)
        latest = docs[-1]
        totals = [sum(d.get("counts", {}).values()) for d in docs]
        drift_html = ""
        if len(docs) >= 2:
            d = history.diff(docs[-2], docs[-1])
            drift_html = (f"<h2>Drift (last two scans)</h2><pre>"
                          f"{html.escape(history.render_text(d))}</pre>")
        reports = _reports_for(hdir, latest)
        reports_html = ""
        if reports:
            links = " ".join(
                f'<a href="../{html.escape(host)}/{html.escape(r)}">{html.escape(r)}</a>'
                for r in reports[-5:])
            reports_html = f"<h2>Reports</h2><p>{links}</p>"
        authz = latest.get("authorization", {})
        body = f"""
<h1>{html.escape(host)}</h1>
<div class="muted">{html.escape(label)} · last scan {html.escape(str(latest.get('finished_at','?')))}</div>
<div class="chips">{_chips(latest.get('counts', {}))}</div>
<h2>Trend ({len(docs)} scans)</h2>
{_spark(totals)}
<div class="muted">{html.escape(str(latest.get('summary','')))}</div>
<p class="muted">authorized for {html.escape(str(authz.get('owner','?')))} ·
expires {html.escape(str(authz.get('expires_at','?')))}</p>
{drift_html}{reports_html}"""
        page = _page(f"{host} — permesso", body, accent)
        path = out / f"{host}.html"
        path.write_text(page)
        written.append(str(path))
        rows.append((host, latest, totals))

    # ---- agency index --------------------------------------------------
    tr = "".join(
        f"<tr><td><a href='{html.escape(h)}.html'>{html.escape(h)}</a></td>"
        f"<td>{html.escape(str(l.get('finished_at', '?')))}</td>"
        f"<td><div class='chips' style='margin:0'>{_chips(l.get('counts', {}))}</div></td>"
        f"<td>{_spark(t, 140, 28)}</td></tr>"
        for h, l, t in rows)
    index_body = f"""
<h1>{html.escape(title or 'permesso console')}</h1>
<div class="muted">{html.escape(label)} · {len(rows)} target · static page, host it anywhere</div>
<h2>Targets</h2>
<table><tr><th>Target</th><th>Last scan</th><th>Findings</th><th>Trend</th></tr>
{tr}</table>"""
    (out / "index.html").write_text(_page("permesso console", index_body, accent))
    written.append(str(out / "index.html"))
    return written

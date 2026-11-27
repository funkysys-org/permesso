"""WordPress adapter — built-in, MIT-clean WP coverage (no WPScan needed).

Layer 1 (enumeration, own code): fingerprint WP, core version, plugins and
themes referenced in the HTML plus a bounded probe of popular plugin slugs
via readme.txt, users exposed through the REST API, exposed debug.log and
wp-config backups.
Layer 2 (vuln matching): detected components checked against the
WPVulnerability API (data CC0 1.0). Missing/failed API calls degrade to an
INFO note — never silent, never a crash.
Every request goes through the same authorization gate as any other adapter.
"""
from __future__ import annotations

import json
import re
import ssl
import time
import urllib.request

from .. import wpvuln
from ..findings import Finding, FindingSet, Severity
from .base import Adapter

UA = "permesso (authorized scan)"

# bounded probe list of popular wordpress.org plugin slugs (fallback when
# the live popular-list fetch fails); the live list from api.wordpress.org
# is preferred at scan time
TOP_PLUGINS = (
    "akismet contact-form-7 jetpack wordpress-seo woocommerce elementor "
    "wpforms classic-editor wordfence all-in-one-seo-pack wp-super-cache "
    "w3-total-cache updraftplus really-simple-ssl redirection seo-by-rank-math "
    "google-site-kit contact-form-plugin wp-mail-smtp loginizer tinymce-advanced "
    "autoptimize wp-fastest-cache litespeed-cache advanced-custom-fields "
    "classic-widgets widget-options mailpoet duplicator better-wp-security "
    "sucuri-scanner wp-statistics svg-support wp-file-manager disable-comments "
    "wpforms-lite google-analytics-for-wp google-analytics-dashboard-for-wp"
).split()

WP_PROBE_CAP = 80
_DELAY = 0.05  # politeness between target requests


class WordpressAdapter(Adapter):
    NAME = "wordpress"

    def available(self) -> tuple[bool, str]:
        return True, ""  # built-in

    # -- plumbing ---------------------------------------------------------
    @staticmethod
    def _fetch(url: str, timeout: int = 10) -> tuple[int, str]:
        ctx = ssl._create_unverified_context()  # noqa: SLF001 — we assess TLS separately
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return getattr(r, "status", 200), r.read(200_000).decode("utf-8", "replace")
        except Exception:
            return 0, ""

    def run(self, target, opts: dict) -> FindingSet:
        out = FindingSet()
        base = self._live_base(target)
        if base is None:
            return out
        status, html = self._fetch(base)
        if status != 200 or not self._is_wordpress(html, base):
            return out                      # not a WordPress site: quiet no-op
        root = base.rstrip("/")

        core_version = self._core_version(root, html)
        if core_version:
            out.add(Finding(
                title=f"WordPress core version disclosed: {core_version}",
                severity=Severity.INFO, source=self.NAME, target=root,
                category="wordpress", evidence="meta/readme/feed disclosure",
                remediation="Remove version disclosure (remove_generator, "
                            "remove readme.html)."))
            self._vuln_check(out, root, "core", "WordPress core", core_version)

        plugins = self._plugins(root, html, opts)
        for slug, version in plugins:
            out.add(Finding(
                title=f"WordPress plugin: {slug}"
                      + (f" {version}" if version else " (version unknown)"),
                severity=Severity.INFO, source=self.NAME, target=root,
                category="wordpress", evidence="readme.txt / HTML reference",
                metadata={"plugin": slug, "version": version or ""}))
            if version:
                self._vuln_check(out, root, "plugin", f"WordPress plugin {slug}",
                                 version, slug=slug)
        for theme in self._themes(html):
            out.add(Finding(
                title=f"WordPress theme referenced: {theme}",
                severity=Severity.INFO, source=self.NAME, target=root,
                category="wordpress", evidence="HTML reference"))
        self._check_users(root, out)
        self._check_sensitive(root, out)
        return out

    # -- layer 1 ----------------------------------------------------------
    def _live_base(self, target) -> str | None:
        for url in target.base_urls():
            status, _ = self._fetch(url)
            if status == 200:
                return url
        return None

    def _is_wordpress(self, html: str, base: str) -> bool:
        if "wp-content" in html or "wp-includes" in html:
            return True
        if re.search(r'name="generator"\s+content="WordPress', html):
            return True
        status, _ = self._fetch(f"{base.rstrip('/')}/wp-login.php")
        return status == 200

    def _core_version(self, root: str, html: str) -> str | None:
        m = re.search(r'content="WordPress\s+([0-9][0-9a-z.\-]*)"', html)
        if m:
            return m.group(1)
        status, body = self._fetch(f"{root}/readme.html")
        if status == 200:
            m = re.search(r"Version\s+([0-9][0-9a-z.\-]*)", body)
            if m:
                return m.group(1)
        status, body = self._fetch(f"{root}/feed/")
        if status == 200:
            m = re.search(r"\?v=([0-9][0-9a-z.\-]*)", body)
            if m:
                return m.group(1)
        return None

    def _plugins(self, root: str, html: str, opts: dict) -> list[tuple[str, str | None]]:
        found: dict[str, str | None] = {}
        for slug in set(re.findall(r"wp-content/plugins/([a-z0-9\-_]+)", html)):
            found[slug] = None
        if not opts.get("wp_probe", True):
            return list(found.items())
        probe = list(dict.fromkeys(list(found) + self._popular_slugs()))
        for slug in probe[:WP_PROBE_CAP]:
            version = self._probe_plugin(root, slug)
            if version is not None and found.get(slug) is None:
                found[slug] = version
            time.sleep(_DELAY)
        return list(found.items())

    def _probe_plugin(self, root: str, slug: str) -> str | None:
        status, body = self._fetch(f"{root}/wp-content/plugins/{slug}/readme.txt")
        if status != 200 or not body:
            return None
        m = re.search(r"Stable tag:\s*([0-9][0-9a-z.\-]*)", body, re.I)
        return m.group(1) if m else ""

    def _themes(self, html: str) -> list[str]:
        return sorted(set(re.findall(r"wp-content/themes/([a-z0-9\-_]+)", html)))

    def _popular_slugs(self) -> list[str]:
        url = ("https://api.wordpress.org/plugins/info/1.2/"
               "?action=query_plugins&request[per_page]=60&request[browse]=popular")
        try:
            status, body = self._fetch(url, timeout=8)
            if status == 200:
                data = json.loads(body)
                slugs = [p["slug"] for p in (data.get("plugins") or []) if p.get("slug")]
                if slugs:
                    return slugs
        except Exception:
            pass
        return [s for s in TOP_PLUGINS if s.isalnum() or "-" in s or "_" in s][:60]

    def _check_users(self, root: str, out: FindingSet) -> None:
        status, body = self._fetch(f"{root}/wp-json/wp/v2/users")
        if status != 200:
            return
        try:
            users = json.loads(body)
            names = [u.get("slug") or u.get("name") for u in users if isinstance(u, dict)]
        except (json.JSONDecodeError, TypeError):
            return
        if names:
            out.add(Finding(
                title="WordPress user enumeration via REST API",
                severity=Severity.MEDIUM, source=self.NAME, target=root,
                category="wordpress",
                evidence="users: " + ", ".join(n for n in names if n)[:200],
                remediation="Block /wp-json/wp/v2/users for anonymous "
                            "visitors (or disable user REST exposure)."))

    def _check_sensitive(self, root: str, out: FindingSet) -> None:
        status, body = self._fetch(f"{root}/wp-content/debug.log")
        if status == 200 and body.strip():
            out.add(Finding(
                title="WordPress debug.log is exposed",
                severity=Severity.MEDIUM, source=self.NAME, target=root,
                category="wordpress", evidence=body.strip()[:200],
                remediation="Delete the file and set WP_DEBUG_LOG to false; "
                            "deny access to *.log in the web server config."))
        for name in ("wp-config.php.bak", "wp-config.php~",
                     "wp-config.php.save", "wp-config.php.old"):
            status, body = self._fetch(f"{root}/{name}")
            time.sleep(_DELAY)
            if status == 200 and "DB_PASSWORD" in body:
                out.add(Finding(
                    title=f"WordPress config backup exposed: /{name}",
                    severity=Severity.CRITICAL, source=self.NAME, target=root,
                    category="wordpress",
                    evidence="contains DB_PASSWORD (database credentials)",
                    remediation=f"Delete /{name} immediately and rotate the "
                                "database credentials."))

    # -- layer 2 ----------------------------------------------------------
    def _vuln_check(self, out: FindingSet, root: str, kind: str, label: str,
                    version: str, slug: str | None = None) -> None:
        data = wpvuln.fetch(kind, slug or version)
        if data is None:
            out.add(Finding(
                title=f"Vulnerability check unavailable for {label} "
                      f"{version} (wpvulnerability.net)",
                severity=Severity.INFO, source=self.NAME, target=root,
                category="wordpress",
                evidence="API unreachable or component unknown",
                remediation="Re-run the scan later; the check is skipped, "
                            "not passed."))
            return
        matched = wpvuln.matches(data, version)
        if len(matched) > 3:
            # aggregate: dozens of core/plugin vulns as ONE readable finding
            worst = max(matched, key=lambda v: wpvuln.severity_from_impact(
                v.get("impact")))
            worst_name = worst.get("name") or "vulnerabilities"
            refs = []
            for v in sorted(matched, key=lambda x: -wpvuln.severity_from_impact(
                    x.get("impact"))):
                for r in wpvuln.refs_of(v):
                    if r not in refs:
                        refs.append(r)
                if len(refs) >= 3:
                    break
            out.add(Finding(
                title=f"{label} {version}: {len(matched)} known vulnerabilities",
                severity=wpvuln.severity_from_impact(worst.get("impact")),
                source=self.NAME, target=root, category="vuln",
                evidence=f"worst: {worst_name[:120]}",
                references=refs,
                remediation="Update the component to the latest version and "
                            "re-scan.",
                metadata={"vuln_count": len(matched)}))
            return
        for v in matched:
            name = v.get("name") or "vulnerability"
            if name == version and (v.get("source") or [{}])[0].get("id"):
                name = f"known vulnerability ({v['source'][0]['id']})"
            out.add(Finding(
                title=f"{label} {version}: {name}",
                severity=wpvuln.severity_from_impact(v.get("impact")),
                source=self.NAME, target=root,
                category="vuln",
                evidence=str(v.get("description") or "")[:300],
                references=wpvuln.refs_of(v),
                remediation="Update the component to a fixed version "
                            "(see references) and re-scan.",
                metadata={"wpvuln_uuid": v.get("uuid", "")}))

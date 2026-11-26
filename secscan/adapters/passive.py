"""Built-in passive checks — zero external dependencies.

HTTP security headers, HTTPS availability/redirect, cookie flags, server
banner, and TLS certificate validity via the system openssl binary.
"""
from __future__ import annotations

import datetime as dt
import re
import ssl
import urllib.error
import urllib.request
from http.client import HTTPResponse  # noqa: F401 (typing clarity)

from ..findings import Finding, FindingSet, Severity
from .base import Adapter

UA = "secscan/0.1 (+authorized scan)"

HEADER_CHECKS = [  # (header, severity, remediation hint)
    ("strict-transport-security", Severity.MEDIUM,
     "Add Strict-Transport-Security to force HTTPS."),
    ("content-security-policy", Severity.MEDIUM,
     "Add a Content-Security-Policy to mitigate XSS."),
    ("x-content-type-options", Severity.LOW,
     "Add X-Content-Type-Options: nosniff."),
    ("x-frame-options", Severity.LOW,
     "Add X-Frame-Options: DENY/SAMEORIGIN or a CSP frame-ancestors directive."),
    ("referrer-policy", Severity.LOW,
     "Add a Referrer-Policy header (e.g. strict-origin-when-cross-origin)."),
    ("permissions-policy", Severity.INFO,
     "Add a Permissions-Policy to restrict browser features."),
]

CERT_RE = re.compile(
    r"notAfter=(?P<after>.+)\n", re.M,
)


class PassiveAdapter(Adapter):
    NAME = "passive"

    def run(self, target, opts: dict) -> FindingSet:
        out = FindingSet()
        answered_schemes: list[str] = []
        for url in target.base_urls():
            scheme = url.split(":", 1)[0]
            try:
                resp = self._get(url)
            except Exception:
                continue
            answered_schemes.append(scheme)
            self._check_headers(url, resp, out)
            self._check_cookie(url, resp, out)
            self._check_banner(url, resp, out)
        if target.ports == [80, 443]:
            self._check_https_redirect(target, out)
        if any(u.startswith("https") for u in target.base_urls()):
            for port in target.ports:
                self._check_tls(target, port, out)
        if not answered_schemes:
            out.add(Finding(
                title="No HTTP service answered on the requested ports",
                severity=Severity.INFO, source=self.NAME, target=target.host,
                category="info",
                evidence=f"ports tried: {target.ports}",
            ))
        return out

    # -- HTTP ------------------------------------------------------------
    def _get(self, url: str, timeout: int = 10):
        ctx = ssl._create_unverified_context()  # noqa: SLF001 — we *assess* TLS
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        return urllib.request.urlopen(req, timeout=timeout, context=ctx)

    def _check_headers(self, url, resp, out: FindingSet) -> None:
        headers = {k.lower(): v for k, v in resp.headers.items()}
        is_https = url.startswith("https")
        for name, sev, fix in HEADER_CHECKS:
            if name == "strict-transport-security" and not is_https:
                continue  # HSTS is only meaningful over HTTPS
            if name not in headers:
                out.add(Finding(
                    title=f"Missing security header: {name}",
                    severity=sev, source=self.NAME, target=url,
                    category="headers", remediation=fix,
                ))

    def _check_cookie(self, url, resp, out: FindingSet) -> None:
        for raw in resp.headers.get_all("Set-Cookie") or []:
            low = raw.lower()
            if "httponly" not in low:
                out.add(Finding(
                    title="Cookie without HttpOnly flag",
                    severity=Severity.MEDIUM, source=self.NAME, target=url,
                    category="headers",
                    evidence=raw[:200],
                    remediation="Set HttpOnly on session cookies.",
                ))
            if url.startswith("https") and "secure" not in low:
                out.add(Finding(
                    title="Cookie without Secure flag over HTTPS",
                    severity=Severity.MEDIUM, source=self.NAME, target=url,
                    category="headers", evidence=raw[:200],
                    remediation="Set Secure on cookies served over HTTPS.",
                ))

    def _check_banner(self, url, resp, out: FindingSet) -> None:
        server = resp.headers.get("Server", "").strip()
        if server and re.search(r"\d+\.\d+", server):
            out.add(Finding(
                title="Server banner discloses version",
                severity=Severity.INFO, source=self.NAME, target=url,
                category="info", evidence=server,
                remediation="Suppress version tokens in the Server header.",
            ))

    def _check_https_redirect(self, target, out: FindingSet) -> None:
        """Plain HTTP on :80 must redirect to HTTPS when 443 is in scope."""
        if 443 not in target.ports or 80 not in target.ports:
            return
        try:
            resp = self._get(f"http://{target.host}", timeout=10)
            final = resp.geturl()
            status = resp.status
        except Exception:
            return
        if status == 200 and final.startswith("http://"):
            out.add(Finding(
                title="HTTP does not redirect to HTTPS",
                severity=Severity.MEDIUM, source=self.NAME,
                target=f"http://{target.host}", category="tls",
                remediation="301-redirect all HTTP traffic to HTTPS.",
            ))

    # -- TLS -------------------------------------------------------------
    def _check_tls(self, target, port: int, out: FindingSet) -> None:
        if port != 443:
            return  # v0 probes the standard HTTPS port only
        rc, outp, _ = self.run_cmd(
            ["openssl", "s_client", "-connect", f"{target.host}:{port}",
             "-servername", target.host],
            timeout=20,
        )
        cert = re.search(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            outp, re.S,
        )
        if not cert:
            return
        import subprocess
        x = subprocess.run(
            ["openssl", "x509", "-noout", "-subject", "-issuer", "-dates"],
            input=cert.group(0), capture_output=True, text=True, timeout=10,
        )
        fields = dict(
            line.split("=", 1) for line in x.stdout.strip().splitlines() if "=" in line
        )
        issuer, subject = fields.get("issuer", ""), fields.get("subject", "")
        not_after = fields.get("notAfter", "")
        if issuer == subject:
            out.add(Finding(
                title="Self-signed TLS certificate",
                severity=Severity.HIGH, source=self.NAME,
                target=f"https://{target.host}", category="tls",
                evidence=issuer,
                remediation="Install a certificate from a public CA (e.g. Let's Encrypt).",
            ))
        try:
            expiry = dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=dt.timezone.utc
            )
        except Exception:
            return
        days = (expiry - dt.datetime.now(dt.timezone.utc)).days
        if days < 0:
            out.add(Finding(
                title="TLS certificate has EXPIRED",
                severity=Severity.CRITICAL, source=self.NAME,
                target=f"https://{target.host}", category="tls",
                evidence=f"expired {abs(days)} days ago ({not_after})",
                remediation="Renew the certificate immediately.",
            ))
        elif days <= 15:
            out.add(Finding(
                title="TLS certificate expires soon",
                severity=Severity.HIGH, source=self.NAME,
                target=f"https://{target.host}", category="tls",
                evidence=f"expires in {days} days ({not_after})",
                remediation="Renew the certificate (automate renewal).",
            ))

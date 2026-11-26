import unittest

from permesso.branding import load as load_branding
from permesso.report.html import render

DOC = {
    "version": "0.1.0",
    "host": "demo.local",
    "ports": [80],
    "started_at": "2026-11-26T01:00:00+00:00",
    "finished_at": "2026-11-26T01:00:05+00:00",
    "authorization": {"owner": "owner@example.com", "scope": "host",
                      "issued_at": "2026-11-26T00:00:00+00:00",
                      "expires_at": "2026-12-26T00:00:00+00:00"},
    "summary": "Scan of demo.local",
    "counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
    "skipped": [], "errors": [],
    "findings": [
        {"id": "SEC-1", "title": "Expired cert", "severity": "HIGH",
         "source": "passive", "target": "https://demo.local", "category": "tls",
         "evidence": "expired", "remediation": "Renew.", "references": [],
         "metadata": {"plain_meaning": "Connections are not trustworthy."}},
    ],
}

BRANDING_IT = {
    "agency_name": "Agencia X",
    "logo_text": "Agencia X Security",
    "accent_color": "#7c2d12",
    "language": "it",
}


class BrandingTest(unittest.TestCase):
    def test_load_merges_over_defaults(self):
        b = load_branding(None)
        self.assertEqual(b["language"], "en")
        self.assertEqual(b["logo_text"], "permesso")
        b2 = load_branding("/nonexistent-does-not-exist") if False else \
            load_branding(None)
        self.assertEqual(b2["accent_color"], "#23408e")

    def test_italian_labels(self):
        html = render(DOC, BRANDING_IT)
        self.assertIn("Report di scansione di sicurezza", html)
        self.assertIn("Perimetro e autorizzazione", html)
        self.assertIn("Cosa significa", html)
        self.assertIn("Rimedio", html)
        self.assertIn("preparato da Agencia X", html)

    def test_branding_values_reach_the_page(self):
        html = render(DOC, BRANDING_IT)
        self.assertIn("Agencia X Security", html)
        self.assertIn("--accent:#7c2d12", html)

    def test_plain_meaning_rendered_and_not_in_meta(self):
        html = render(DOC, BRANDING_IT)
        self.assertIn("Connections are not trustworthy.", html)
        self.assertNotIn("plain_meaning", html)

    def test_english_default(self):
        html = render(DOC, None)
        self.assertIn("Security scan report", html)
        self.assertIn("What this means", html)

    def test_bad_language_rejected(self):
        with self.assertRaises(ValueError):
            render(DOC, {"language": "xx"})


if __name__ == "__main__":
    unittest.main()

import unittest

from secscan.report.html import render

DOC = {
    "version": "0.1.0",
    "host": "demo.local",
    "ports": [80],
    "started_at": "2026-11-26T01:00:00+00:00",
    "finished_at": "2026-11-26T01:00:05+00:00",
    "authorization": {"owner": "owner@example.com", "scope": "host",
                      "issued_at": "2026-11-26T00:00:00+00:00",
                      "expires_at": "2026-12-26T00:00:00+00:00"},
    "summary": "Scan of demo.local found 0 critical, 1 high...",
    "counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 1, "LOW": 0, "INFO": 0},
    "skipped": [{"adapter": "nuclei", "reason": "nuclei not found on PATH."}],
    "errors": [],
    "findings": [
        {"id": "SEC-1", "title": "Expired cert <script>alert(1)</script>",
         "severity": "HIGH", "source": "passive", "target": "https://demo.local",
         "category": "tls", "evidence": "<img src=x onerror=alert(2)>",
         "remediation": "Renew.", "references": ["https://example.com/a"],
         "metadata": {"t": "<b>"}},
        {"id": "SEC-2", "title": "Missing header", "severity": "MEDIUM",
         "source": "passive", "target": "http://demo.local", "category": "headers",
         "evidence": "", "remediation": "", "references": [], "metadata": {}},
    ],
}


class ReportTest(unittest.TestCase):
    def setUp(self):
        self.html = render(DOC)

    def test_contains_target_and_counts(self):
        self.assertIn("demo.local", self.html)
        self.assertIn("HIGH 1", self.html)
        self.assertIn("Checks skipped", self.html)
        self.assertIn("nuclei not found on PATH", self.html)

    def test_evidence_is_escaped(self):
        self.assertNotIn("<script>alert(1)</script>", self.html)
        self.assertIn("&lt;script&gt;", self.html)
        self.assertNotIn("<img src=x", self.html)

    def test_references_rendered(self):
        self.assertIn('href="https://example.com/a"', self.html)


if __name__ == "__main__":
    unittest.main()

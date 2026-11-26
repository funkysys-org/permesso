import unittest

from permesso.findings import Finding, Severity
from permesso.writer import plain_meaning

CATS = ["headers", "tls", "vuln", "ssh", "hardening", "info", "unknown-cat"]


def f(category, sev=Severity.MEDIUM):
    return Finding(title="t", severity=sev, source="s", target="t",
                   category=category)


class WriterTest(unittest.TestCase):
    def test_every_category_produces_text(self):
        for c in CATS:
            self.assertTrue(plain_meaning(f(c), lang="en").strip())

    def test_languages_differ(self):
        en = plain_meaning(f("tls"), lang="en")
        it = plain_meaning(f("tls"), lang="it")
        self.assertNotEqual(en, it)
        self.assertTrue(it.strip())

    def test_high_severity_adds_priority_tone(self):
        low = plain_meaning(f("vuln", Severity.LOW))
        high = plain_meaning(f("vuln", Severity.HIGH))
        self.assertTrue(high.startswith(low))
        self.assertIn("priority", high)

    def test_no_unfilled_placeholders(self):
        for c in CATS:
            text = plain_meaning(f(c))
            self.assertNotIn("{", text)
            self.assertNotIn("}", text)


if __name__ == "__main__":
    unittest.main()

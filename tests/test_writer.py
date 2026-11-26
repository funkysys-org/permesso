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


class SpecificTest(unittest.TestCase):
    def test_specific_beats_generic(self):
        cookie = Finding(title="Cookie without HttpOnly flag", severity=Severity.MEDIUM,
                         source="s", target="t", category="headers")
        generic = Finding(title="Something else", severity=Severity.MEDIUM,
                          source="s", target="t", category="headers")
        self.assertIn("cookie", plain_meaning(cookie).lower())
        self.assertNotIn("cookie", plain_meaning(generic).lower())

    def test_specific_works_in_both_languages(self):
        finding = Finding(title="TLS certificate has EXPIRED", severity=Severity.CRITICAL,
                          source="s", target="t", category="tls")
        en = plain_meaning(finding, lang="en")
        it = plain_meaning(finding, lang="it")
        self.assertIn("down", en.lower())
        self.assertIn("giù", it)
        self.assertNotEqual(en, it)

    def test_high_tone_still_applies_to_specific(self):
        finding = Finding(title="TLS certificate has EXPIRED", severity=Severity.CRITICAL,
                          source="s", target="t", category="tls")
        self.assertTrue(plain_meaning(finding).endswith(_HIGH := __import__(
            "permesso.writer", fromlist=["_HIGH_TONE"])._HIGH_TONE))


if __name__ == "__main__":
    unittest.main()

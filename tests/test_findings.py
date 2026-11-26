import unittest

from permesso.findings import Finding, FindingSet, Severity


def f(title, sev, source="passive", target="h"):
    return Finding(title=title, severity=sev, source=source, target=target)


class FindingsTest(unittest.TestCase):
    def test_severity_parsing(self):
        self.assertEqual(Severity.parse("CRITICAL"), Severity.CRITICAL)
        self.assertEqual(Severity.parse("moderate"), Severity.MEDIUM)
        self.assertEqual(Severity.parse("weird"), Severity.INFO)

    def test_dedupe_keeps_highest_severity(self):
        fs = FindingSet()
        fs.add(f("Missing header", Severity.LOW))
        fs.add(f("Missing header", Severity.HIGH))
        fs.add(f("Missing header", Severity.MEDIUM))
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs.sorted()[0].severity, Severity.HIGH)

    def test_sorting_most_severe_first(self):
        fs = FindingSet([f("a", Severity.LOW), f("c", Severity.CRITICAL),
                         f("b", Severity.HIGH)])
        self.assertEqual([x.severity for x in fs],
                         [Severity.CRITICAL, Severity.HIGH, Severity.LOW])

    def test_counts(self):
        fs = FindingSet([f("a", Severity.LOW), f("b", Severity.LOW),
                         f("c", Severity.INFO)])
        self.assertEqual(fs.counts(), {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 2, "INFO": 1})


if __name__ == "__main__":
    unittest.main()

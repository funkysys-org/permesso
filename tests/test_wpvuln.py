import unittest

from permesso import wpvuln
from permesso.findings import Severity


AKISMET_FIXTURE = {
    "error": 0, "message": None, "updated": 1795700000,
    "data": {
        "name": "Akismet Anti-spam: Spam Protection",
        "plugin": "akismet", "latest": "5.3.3",
        "vulnerability": [
            {"uuid": "u1", "name": "Akismet < 3.1.5 XSS",
             "description": "XSS before 3.1.5.",
             "operator": {"min_version": None, "min_operator": None,
                          "max_version": "3.1.5", "max_operator": "lt",
                          "unfixed": "0", "closed": "0"},
             "source": [{"id": "CVE-2015-9357", "name": "CVE-2015-9357",
                         "link": "https://www.cve.org/CVERecord?id=CVE-2015-9357"}],
             "impact": {"cvss3": {"severity": "medium", "score": "6.1"}}},
            {"uuid": "u2", "name": "Akismet 4.x minor issue",
             "operator": {"min_version": "4.0", "min_operator": "ge",
                          "max_version": "4.5", "max_operator": "le",
                          "unfixed": "0", "closed": "0"},
             "source": [], "impact": {"cvss3": {"severity": "low"}}},
            {"uuid": "u3", "name": "Unfixed, all versions",
             "operator": {"min_version": None, "min_operator": None,
                          "max_version": None, "max_operator": None,
                          "unfixed": "1", "closed": "0"},
             "source": [], "impact": None},
        ],
    },
}


class VersionCompareTest(unittest.TestCase):
    def test_basic_orders(self):
        self.assertEqual(wpvuln.compare("6.3", "6.3.1"), -1)
        self.assertEqual(wpvuln.compare("6.4.2", "6.4.2"), 0)
        self.assertEqual(wpvuln.compare("3.2", "3.1.5"), 1)
        self.assertEqual(wpvuln.compare("10.0", "9.9.9"), 1)

    def test_applies_operators(self):
        block = AKISMET_FIXTURE["data"]["vulnerability"][0]["operator"]
        self.assertTrue(wpvuln.applies(block, "3.1.4"))
        self.assertTrue(wpvuln.applies(block, "2.5.0"))
        self.assertFalse(wpvuln.applies(block, "3.1.5"))
        self.assertFalse(wpvuln.applies(block, "5.3.3"))

    def test_applies_range(self):
        block = AKISMET_FIXTURE["data"]["vulnerability"][1]["operator"]
        self.assertTrue(wpvuln.applies(block, "4.2.1"))
        self.assertFalse(wpvuln.applies(block, "4.6"))
        self.assertFalse(wpvuln.applies(block, "3.9"))

    def test_no_operator_means_applies(self):
        self.assertTrue(wpvuln.applies(None, "anything"))

    def test_unknown_version_never_matches(self):
        block = AKISMET_FIXTURE["data"]["vulnerability"][0]["operator"]
        self.assertFalse(wpvuln.applies(block, None))
        self.assertFalse(wpvuln.applies(block, ""))

    def test_matches_filters(self):
        got = wpvuln.matches(AKISMET_FIXTURE["data"], "3.1.4")
        self.assertEqual({v["uuid"] for v in got}, {"u1", "u3"})

    def test_severity_mapping(self):
        self.assertEqual(wpvuln.severity_from_impact(
            {"cvss3": {"severity": "critical"}}), Severity.CRITICAL)
        self.assertEqual(wpvuln.severity_from_impact(
            {"cvss3": {"severity": "medium"}}), Severity.MEDIUM)
        self.assertEqual(wpvuln.severity_from_impact(None), Severity.MEDIUM)

    def test_refs_of(self):
        refs = wpvuln.refs_of(AKISMET_FIXTURE["data"]["vulnerability"][0])
        self.assertEqual(refs, ["https://www.cve.org/CVERecord?id=CVE-2015-9357"])

    def test_fetch_unknown_slug_yields_no_matches(self):
        data = wpvuln.fetch("plugin", "slug-that-never-exists-xyz")
        self.assertEqual(wpvuln.matches(data, "1.0"), [])


if __name__ == "__main__":
    unittest.main()

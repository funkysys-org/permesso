import types
import unittest

from permesso.adapters.wordpress import WordpressAdapter
from permesso.findings import Severity
from permesso import wpvuln


HOMEPAGE = ('<meta name="generator" content="WordPress 6.3">'
            '<script src="/wp-content/plugins/akismet/f.js"></script>'
            '<link href="/wp-content/themes/faketheme/style.css">')
README = "=== Akismet ===\nStable tag: 3.1.4\n"
USERS = '[{"slug":"admin"},{"slug":"editor"}]'
VULN_DATA = {"vulnerability": [{
    "uuid": "u1", "name": "Akismet < 3.1.5 XSS",
    "operator": {"max_version": "3.1.5", "max_operator": "lt",
                 "min_version": None, "min_operator": None},
    "source": [{"link": "https://example.com/cve"}],
    "impact": {"cvss3": {"severity": "medium"}}}]}


def fake_fetch(url, timeout=10):
    if url.endswith("/"):
        url = url[:-1]
    if url.endswith("/wp-content/plugins/akismet/readme.txt"):
        return 200, README
    if url.endswith("/wp-json/wp/v2/users"):
        return 200, USERS
    if url.endswith("/wp-content/debug.log"):
        return 200, "PHP Notice: something\n"
    if url.endswith("/wp-login.php"):
        return 200, ""
    if "api.wordpress.org" in url:
        return 200, '{"plugins": [{"slug": "akismet"}, {"slug": "contact-form-7"}]}'
    if url.endswith("/feed/"):
        return 200, "<generator>https://wordpress.org/?v=6.3</generator>"
    if url.endswith("/readme.html"):
        return 404, ""
    if url.endswith("/wp-config.php.bak"):
        return 200, "define('DB_PASSWORD', 'hunter2');"
    if url == "http://wp.test:8099":
        return 200, HOMEPAGE
    return 404, ""


class WordpressAdapterTest(unittest.TestCase):
    def setUp(self):
        self.adapter = WordpressAdapter()
        self.spec = types.SimpleNamespace(host="wp.test", ports=[8099],
                                          base_urls=lambda: ["http://wp.test:8099"])
        self.adapter._fetch = staticmethod(fake_fetch)
        wpvuln._CACHE.clear()
        wpvuln._CACHE["plugin/akismet"] = VULN_DATA
        wpvuln._CACHE["core/6.3"] = {"vulnerability": []}  # no network in tests

    def test_wordpress_site_detected(self):
        findings = self.adapter.run(self.spec, {})
        titles = {f.title for f in findings}
        self.assertTrue(any("WordPress core version disclosed: 6.3" in t
                            for t in titles))
        self.assertTrue(any("plugin: akismet 3.1.4" in t for t in titles))
        self.assertTrue(any("user enumeration" in t.lower() for t in titles))
        self.assertTrue(any("debug.log" in t for t in titles))
        self.assertTrue(any("theme referenced: faketheme" in t for t in titles))

    def test_vuln_match_becomes_finding(self):
        findings = self.adapter.run(self.spec, {})
        vulns = [f for f in findings if f.category == "vuln"]
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0].severity, Severity.MEDIUM)
        self.assertIn("3.1.5", vulns[0].title)
        self.assertEqual(vulns[0].references, ["https://example.com/cve"])

    def test_vuln_unavailable_degrades_to_info_not_crash(self):
        wpvuln._CACHE.clear()
        real_fetch = wpvuln.fetch

        def failing(kind, key, timeout=10):
            return None

        wpvuln.fetch = failing
        try:
            findings = self.adapter.run(self.spec, {})
        finally:
            wpvuln.fetch = real_fetch
        titles = " ".join(f.title for f in findings)
        self.assertIn("Vulnerability check unavailable", titles)
        notes = [f for f in findings if "unavailable" in f.title]
        self.assertEqual(notes[0].severity, Severity.INFO)

    def test_non_wordpress_site_noop(self):
        def plain(url, timeout=10):
            url = url.rstrip("/")
            return (200, "<html><body>plain site</body></html>") \
                if url == "http://wp.test:8099" else (404, "")
        self.adapter._fetch = staticmethod(plain)
        findings = self.adapter.run(self.spec, {})
        self.assertEqual(len(findings), 0)

    def test_wp_probe_false_skips_slug_probe(self):
        findings = self.adapter.run(self.spec, {"wp_probe": False})
        titles = [f.title for f in findings]
        self.assertTrue(any("akismet" in t for t in titles))  # from HTML + readme


if __name__ == "__main__":
    unittest.main()

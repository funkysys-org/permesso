import json
import tempfile
import unittest
from pathlib import Path

from permesso.portal import build_portal


def scan_doc(n, total=2, started="2026-11-26T01:00:00+00:00"):
    return {"host": "h.example", "started_at": started,
            "finished_at": started, "counts": {"HIGH": 1, "MEDIUM": total - 1},
            "summary": "scan doc",
            "authorization": {"owner": "o@x", "scope": "host",
                              "issued_at": started, "expires_at": started},
            "findings": []}


def make_history():
    tmp = Path(tempfile.mkdtemp())
    h1 = tmp / "a.example"; h1.mkdir()
    (h1 / "scan-20261126-010000.json").write_text(json.dumps(scan_doc(1)))
    (h1 / "scan-20261126-020000.json").write_text(
        json.dumps(scan_doc(2, started="2026-11-26T02:00:00+00:00")))
    (h1 / "report-20261126-020000.html").write_text("<html>r2</html>")
    h2 = tmp / "b.example"; h2.mkdir()
    (h2 / "scan-20261126-030000.json").write_text(
        json.dumps(scan_doc(1, started="2026-11-26T03:00:00+00:00")))
    return tmp, h1


class PortalTest(unittest.TestCase):
    def setUp(self):
        self.hist, self.h1 = make_history()
        self.out = Path(tempfile.mkdtemp()) / "portal"
        self.written = build_portal(str(self.hist), str(self.out),
                                    {"logo_text": "Agencia X"})

    def test_builds_index_and_host_pages(self):
        names = {Path(p).name for p in self.written}
        self.assertEqual(names, {"index.html", "a.example.html", "b.example.html"})

    def test_index_lists_targets_and_branding(self):
        idx = (self.out / "index.html").read_text()
        self.assertIn("a.example", idx)
        self.assertIn("b.example", idx)
        self.assertIn("Agencia X", idx)
        self.assertIn("2 target", idx)

    def test_host_page_has_trend_drift_and_report_link(self):
        page = (self.out / "a.example.html").read_text()
        self.assertIn("Trend (2 scans)", page)
        self.assertIn("polyline", page)
        self.assertIn("Drift", page)
        self.assertIn("report-20261126-020000.html", page)
        self.assertIn("o@x", page)

    def test_empty_history_raises(self):
        empty = Path(tempfile.mkdtemp())
        with self.assertRaises(SystemExit):
            build_portal(str(empty), str(empty / "p"), None)


if __name__ == "__main__":
    unittest.main()

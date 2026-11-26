import unittest

from permesso.history import diff, render_text


def scan(findings, started="2026-11-26T01:00:00+00:00", host="h.example"):
    return {"host": host, "started_at": started,
            "counts": {}, "findings": findings}


def fd(fid, title, sev):
    return {"id": fid, "title": title, "severity": sev,
            "source": "passive", "target": "h.example",
            "category": "headers", "evidence": "", "remediation": "",
            "references": [], "metadata": {}}


OLD = scan([fd("A", "missing header", "MEDIUM"), fd("B", "old banner", "INFO")])
NEW = scan([fd("A", "missing header", "MEDIUM"),
            fd("C", "expired cert", "CRITICAL")],
           started="2026-11-27T01:00:00+00:00")


class HistoryTest(unittest.TestCase):
    def test_added_resolved_kept(self):
        d = diff(OLD, NEW)
        self.assertEqual([f["id"] for f in d["added"]], ["C"])
        self.assertEqual([f["id"] for f in d["resolved"]], ["B"])
        self.assertEqual(d["kept"], 1)

    def test_new_high_flag(self):
        self.assertTrue(diff(OLD, NEW)["has_new_high"])
        self.assertFalse(diff(NEW, OLD)["has_new_high"])

    def test_render_text_sections(self):
        text = render_text(diff(OLD, NEW))
        self.assertIn("1 new", text)
        self.assertIn("NEW:", text)
        self.assertIn("RESOLVED:", text)
        self.assertIn("expired cert", text)
        self.assertIn("ATTENTION", text)

    def test_hosts_must_match_warning(self):
        other = scan(OLD["findings"], host="other.example")
        d = diff(OLD, other)
        self.assertEqual(d["old_host"], "h.example")
        self.assertEqual(d["new_host"], "other.example")


if __name__ == "__main__":
    unittest.main()

import json
import tempfile
import unittest
from pathlib import Path

from permesso import monitor


def doc(n, host="h.example", started="2026-11-26T01:00:00+00:00"):
    return {"host": host, "started_at": started, "counts": {},
            "findings": [{"id": f"F{n}", "title": f"t{n}", "severity": "LOW",
                          "source": "passive", "target": host, "category": "info",
                          "evidence": "", "remediation": "", "references": [],
                          "metadata": {}}]}


class MonitorHelpersTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.hdir = monitor.history_dir(str(self.tmp), "h.example")
        self.assertTrue(self.hdir.is_dir())
        self.assertIn("h.example", str(self.hdir))

    def test_previous_scan_none_then_last(self):
        self.assertIsNone(monitor.previous_scan(self.hdir))
        (self.hdir / "scan-a.json").write_text("{}")
        (self.hdir / "scan-b.json").write_text("{}")
        self.assertEqual(monitor.previous_scan(self.hdir).name, "scan-b.json")

    def test_prune_keeps_last_n(self):
        for i in range(25):
            (self.hdir / f"scan-{i:04d}.json").write_text("{}")
            (self.hdir / f"report-{i:04d}.html").write_text("x")
        monitor.prune(self.hdir, keep=20)
        self.assertEqual(len(list(self.hdir.glob("scan-*.json"))), 20)
        self.assertEqual(len(list(self.hdir.glob("report-*.html"))), 20)

    def test_run_monitor_baseline_then_drift(self):
        # stub pipeline.run_scan to avoid network: monitor must still gate+store+diff
        import types
        import permesso.pipeline as pipeline
        calls = {"n": 0}
        real = pipeline.run_scan
        spec = types.SimpleNamespace(host="h.example", ports=[80])

        def fake(spec, key, opts):
            calls["n"] += 1
            return None, doc(calls["n"], started=f"2026-11-26T01:00:0{calls['n']}+00:00")

        pipeline.run_scan = fake
        try:
            r1 = monitor.run_monitor(spec, b"key", {"history_dir": str(self.tmp)})
            self.assertTrue(r1["baseline"])          # first run = baseline
            self.assertIsNone(r1["drift"])
            r2 = monitor.run_monitor(spec, b"key", {"history_dir": str(self.tmp)})
            self.assertFalse(r2["baseline"])
            self.assertEqual(r2["drift"]["added"][0]["id"], "F2")
            self.assertEqual(r2["drift"]["resolved"][0]["id"], "F1")
            self.assertEqual(r2["drift"]["kept"], 0)
        finally:
            pipeline.run_scan = real
        self.assertEqual(calls["n"], 2)
        # artifacts exist
        self.assertTrue(Path(r1["scan_path"]).exists())
        self.assertTrue(Path(r2["report_path"]).exists())
        self.assertTrue(json.loads(Path(r2["scan_path"]).read_text())["findings"])


if __name__ == "__main__":
    unittest.main()

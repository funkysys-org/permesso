import unittest

from permesso.findings import Finding, FindingSet, Severity
from permesso.validation import note, validate


def f(title, source="passive"):
    return Finding(title=title, severity=Severity.LOW, source=source,
                   target="t", category="headers")


class ValidationTest(unittest.TestCase):
    def test_recheck_evidence_transient(self):
        findings = [f("Missing header: a"),        # reproduced -> recheck
                    f("Missing header: b"),        # not reproduced -> transient
                    f("SQLi", source="nuclei")]    # tool evidence
        fresh = lambda spec, opts: FindingSet([f("Missing header: a")])
        stats = validate(findings, {}, fresh=fresh)
        self.assertEqual(stats, {"mode": "non-destructive", "total": 3,
                                 "rechecked": 1, "by_evidence": 1,
                                 "transient": 1})
        self.assertEqual(findings[0].metadata["validated"], "recheck")
        self.assertEqual(findings[1].metadata["validated"], "")
        self.assertEqual(findings[2].metadata["validated"], "source-evidence")

    def test_note_both_languages(self):
        stats = {"total": 2, "rechecked": 1, "by_evidence": 1, "transient": 0,
                 "mode": "non-destructive"}
        en, it = note(stats, "en"), note(stats, "it")
        self.assertIn("re-checked live", en)
        self.assertIn("riverificati", it)

    def test_default_fresh_runs_passive_adapter(self):
        # default fresh callable resolves the passive adapter and takes (spec, opts)
        called = {}

        def fake_run(spec, opts):
            called["spec"] = spec
            return FindingSet()

        import types
        import permesso.validation as validation
        real_resolve = validation.resolve

        def fake_resolve(name):
            return [types.SimpleNamespace(run=fake_run)]

        validation.resolve = fake_resolve
        try:
            stats = validate([f("x")], {"_spec": "SPEC"})
        finally:
            validation.resolve = real_resolve
        self.assertEqual(called["spec"], "SPEC")
        self.assertEqual(stats["rechecked"], 0)


if __name__ == "__main__":
    unittest.main()

import unittest

from permesso import doctor


class DoctorTest(unittest.TestCase):
    def test_recipes_cover_every_optional_adapter(self):
        for name in ("nuclei", "ssh_audit", "testssl", "lynis"):
            self.assertIn(name, doctor.RECIPES)
            self.assertIn("linux", doctor.RECIPES[name])
            self.assertIn("macos", doctor.RECIPES[name])

    def test_every_linux_recipe_has_actionable_lines(self):
        for name, r in doctor.RECIPES.items():
            lines = [l for l in r["linux"].splitlines() if l.strip()]
            self.assertTrue(len(lines) >= 1, f"{name} recipe empty")
            joined = r["linux"]
            self.assertTrue(
                any(k in joined for k in ("install", "clone", "curl", "pipx", "apt")),
                f"{name} recipe has no actionable command")

    def test_adapter_rows_covers_all_five(self):
        rows = {r["name"]: r for r in doctor.adapter_rows()}
        self.assertEqual(set(rows), {"passive", "nuclei", "testssl", "ssh_audit", "lynis"})
        self.assertEqual(rows["passive"]["status"], "built-in")
        # lynis missing on a scanning machine is 'server-side', not an error
        if not rows["lynis"]["ok"]:
            self.assertEqual(rows["lynis"]["status"], "server-side")

    def test_render_mentions_adapters_and_skips_never_break(self):
        text = doctor.render()
        for name in ("passive", "nuclei", "testssl", "ssh_audit", "lynis"):
            self.assertIn(name, text)
        self.assertIn("never break a scan", text)


if __name__ == "__main__":
    unittest.main()

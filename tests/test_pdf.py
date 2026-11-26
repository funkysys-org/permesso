import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from permesso import pdf


class PdfTest(unittest.TestCase):
    def test_no_engine_gives_install_hint(self):
        with mock.patch("shutil.which", return_value=None):
            ok, detail = pdf.to_pdf("r.html", "r.pdf")
        self.assertFalse(ok)
        self.assertIn("wkhtmltopdf", detail)
        self.assertIn("apt install", detail)

    def test_uses_wkhtmltopdf_when_present(self):
        import os
        tmp = Path(tempfile.mkdtemp(prefix="pdftest-",
                                    dir=os.path.expanduser("~")))  # /tmp is noexec in some sandboxes
        fake = tmp / "wkhtmltopdf"
        fake.write_text("#!/bin/sh\nshift 0\ncp \"$1\" \"$2\" 2>/dev/null || "
                        "printf '%%PDF-1.4 %%fake\\n' > \"$2\"\n")
        fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
        src = tmp / "r.html"; src.write_text("<html>x</html>")
        dst = tmp / "r.pdf"

        def fake_which(name):
            return str(fake) if name == "wkhtmltopdf" else None

        with mock.patch("shutil.which", side_effect=fake_which):
            ok, detail = pdf.to_pdf(str(src), str(dst))
        self.assertTrue(ok)
        self.assertIn("wkhtmltopdf", detail)
        self.assertTrue(dst.exists() and dst.stat().st_size > 0)

    def test_available_reports_missing_engines(self):
        with mock.patch("shutil.which", return_value=None):
            path, msg = pdf.available()
        self.assertIsNone(path)
        self.assertIn("chromium", msg.lower())


if __name__ == "__main__":
    unittest.main()

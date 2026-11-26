"""PDF export for HTML reports — external process only, zero new deps.

Uses whatever is already on the machine (wkhtmltopdf or a headless
Chromium/Chrome); reports clearly when nothing is available. No PDF
library is embedded: the tool shells out, exactly like the GPL adapters.
"""
from __future__ import annotations

import pathlib
import shutil

CHROMIUM_FLAGS = ["--headless", "--disable-gpu", "--no-sandbox",
                   "--no-pdf-header-footer"]


def available() -> tuple[str | None, str]:
    for tool in ("wkhtmltopdf", "chromium", "chromium-browser",
                 "google-chrome", "chrome"):
        path = shutil.which(tool)
        if path:
            return path, tool
    return None, ("No PDF engine found. Install one of: wkhtmltopdf "
                  "(sudo apt install wkhtmltopdf) or Chromium "
                  "(sudo apt install chromium) — then re-run.")


def to_pdf(html_path: str, pdf_path: str, timeout: int = 120) -> tuple[bool, str]:
    path, detail = available()
    if path is None:
        return False, detail
    src = pathlib.Path(html_path).resolve()
    dst = pathlib.Path(pdf_path)
    if "wkhtmltopdf" in path:
        cmd = [path, str(src), str(dst)]
    else:
        cmd = [path, *CHROMIUM_FLAGS, f"--print-to-pdf={dst}", src.as_uri()]
    import subprocess
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          stdin=subprocess.DEVNULL)
    if proc.returncode != 0 or not dst.exists():
        return False, f"{pathlib.Path(path).name} failed: {(proc.stderr or proc.stdout)[:300]}"
    return True, f"pdf written with {pathlib.Path(path).name}: {dst}"

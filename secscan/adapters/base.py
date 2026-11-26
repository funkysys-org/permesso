"""Adapter contract and helpers."""
from __future__ import annotations

import shutil
import subprocess

from ..findings import FindingSet


class Adapter:
    """One scan capability. Subclasses set NAME and implement run()."""

    NAME: str = "adapter"

    def available(self) -> tuple[bool, str]:
        """(is_usable, reason_if_not)"""
        return True, ""

    def run(self, target, opts: dict) -> FindingSet:
        raise NotImplementedError

    # -- helpers ---------------------------------------------------------
    @staticmethod
    def which(binary: str) -> str | None:
        return shutil.which(binary)

    @staticmethod
    def run_cmd(cmd: list[str], timeout: int = 300) -> tuple[int, str, str]:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        return proc.returncode, proc.stdout, proc.stderr

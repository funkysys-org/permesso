"""Branding configuration for client-facing reports."""
from __future__ import annotations

import json

DEFAULTS: dict = {
    "agency_name": "",        # e.g. "Agencia X" — shown as report author
    "logo_text": "secscan",   # text logo in the header
    "accent_color": "#23408e",
    "footer": "",             # custom footer line, replaces default when set
    "language": "en",         # "en" | "it"
}


def load(path: str | None) -> dict:
    """Load a branding.json over the defaults (missing keys keep defaults)."""
    branding = dict(DEFAULTS)
    if path:
        with open(path) as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise ValueError("branding file must be a JSON object")
        for key in DEFAULTS:
            if key in data:
                branding[key] = data[key]
    if branding["language"] not in ("en", "it"):
        raise ValueError("branding.language must be 'en' or 'it'")
    return branding

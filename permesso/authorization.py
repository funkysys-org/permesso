"""Authorization gate.

Every scan requires a signed authorization file for the exact target.
Signatures are HMAC-SHA256 over the canonical JSON of the authorization
payload, using a local 256-bit key. Upgrade path: Ed25519 + remote signing.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import pathlib
import secrets

DEFAULT_KEY_PATH = os.path.expanduser("~/.permesso/secret.key")
DEFAULT_AUTH_DIR = os.path.expanduser("~/.permesso/authorizations")


class AuthorizationError(Exception):
    """Raised when a scan is attempted without valid authorization."""


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def load_or_create_key(key_path: str = DEFAULT_KEY_PATH) -> bytes:
    p = pathlib.Path(key_path)
    if p.exists():
        return p.read_bytes().strip()
    p.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    p.write_bytes(key)
    os.chmod(p, 0o600)
    return key


def key_id(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:12]


def authorize(
    target: str,
    owner: str,
    key: bytes,
    scope: str = "host",
    days: int = 30,
    auth_dir: str = DEFAULT_AUTH_DIR,
) -> dict:
    if scope not in ("host", "domain"):
        raise AuthorizationError("scope must be 'host' or 'domain'")
    if scope == "domain" and target.count(".") < 1:
        raise AuthorizationError("domain scope needs a domain, not an IP")
    now = dt.datetime.now(dt.timezone.utc)
    payload = {
        "product": "permesso",
        "target": target.lower().strip(),
        "scope": scope,
        "owner": owner,
        "issued_at": now.isoformat(timespec="seconds"),
        "expires_at": (now + dt.timedelta(days=days)).isoformat(timespec="seconds"),
    }
    signature = hmac.new(key, _canonical(payload), hashlib.sha256).hexdigest()
    doc = {"authorization": payload, "signature": signature, "key_id": key_id(key)}
    out_dir = pathlib.Path(auth_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{payload['target'].replace('/', '_')}.auth.json").write_text(
        json.dumps(doc, indent=2)
    )
    return doc


def _target_in_scope(auth_target: str, scope: str, target: str) -> bool:
    t = target.lower().strip().rstrip(".")
    a = auth_target.lower().strip().rstrip(".")
    if t == a:
        return True
    if scope == "domain" and t.endswith("." + a):
        return True
    return False


def verify(target: str, key: bytes, auth_dir: str = DEFAULT_AUTH_DIR) -> dict:
    """Verify a valid, unexpired, un-tampered authorization for target.

    Returns the authorization payload. Raises AuthorizationError otherwise.
    """
    path = pathlib.Path(auth_dir) / f"{target.lower().strip().replace('/', '_')}.auth.json"
    if not path.exists():
        # fall back to a domain-scope authorization covering this target
        parent = ".".join(target.lower().strip().split(".")[-2:]) if "." in target else target
        path = pathlib.Path(auth_dir) / f"{parent}.auth.json"
        if not path.exists():
            raise AuthorizationError(
                f"No authorization file for '{target}'. Run: "
                f"permesso authorize --target {target} --owner you@example.com"
            )
    doc = json.loads(path.read_text())
    payload, signature = doc.get("authorization", {}), doc.get("signature", "")
    expected = hmac.new(key, _canonical(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise AuthorizationError(
            f"Authorization signature mismatch for '{target}' — file tampered or wrong key."
        )
    if not _target_in_scope(payload.get("target", ""), payload.get("scope", "host"), target):
        raise AuthorizationError(
            f"Authorization does not cover '{target}' (covers '{payload.get('target')}', "
            f"scope={payload.get('scope')})."
        )
    expires = dt.datetime.fromisoformat(payload["expires_at"])
    if dt.datetime.now(dt.timezone.utc) > expires:
        raise AuthorizationError(
            f"Authorization for '{target}' expired on {payload['expires_at']}. Re-authorize."
        )
    return payload

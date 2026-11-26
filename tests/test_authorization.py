import tempfile
import unittest
from pathlib import Path

from permesso import authorization as authz


class AuthorizationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.key_path = str(Path(self.tmp) / "secret.key")
        self.auth_dir = str(Path(self.tmp) / "auths")
        self.key = authz.load_or_create_key(self.key_path)

    def _auth(self, target="www.example.com", scope="host", days=30):
        return authz.authorize(
            target=target, owner="owner@example.com", key=self.key,
            scope=scope, days=days, auth_dir=self.auth_dir,
        )

    def test_valid_authorization_passes(self):
        self._auth()
        payload = authz.verify("www.example.com", self.key, self.auth_dir)
        self.assertEqual(payload["target"], "www.example.com")

    def test_domain_scope_covers_subdomain(self):
        self._auth(target="example.com", scope="domain")
        payload = authz.verify("shop.example.com", self.key, self.auth_dir)
        self.assertEqual(payload["scope"], "domain")

    def test_tampered_payload_is_rejected(self):
        doc = self._auth()
        doc["authorization"]["owner"] = "attacker@evil.example"
        out = Path(self.auth_dir) / "www.example.com.auth.json"
        import json
        out.write_text(json.dumps(doc))
        with self.assertRaises(authz.AuthorizationError):
            authz.verify("www.example.com", self.key, self.auth_dir)

    def test_expired_authorization_is_rejected(self):
        self._auth(days=-1)
        with self.assertRaises(authz.AuthorizationError):
            authz.verify("www.example.com", self.key, self.auth_dir)

    def test_wrong_target_is_rejected(self):
        self._auth(target="example.com", scope="host")
        with self.assertRaises(authz.AuthorizationError):
            authz.verify("other-site.example", self.key, self.auth_dir)

    def test_missing_authorization_is_rejected(self):
        with self.assertRaises(authz.AuthorizationError):
            authz.verify("never-authorized.example", self.key, self.auth_dir)


if __name__ == "__main__":
    unittest.main()

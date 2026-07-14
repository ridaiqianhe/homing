import importlib
import json
import os
import tempfile
import unittest


class SecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        os.environ.update({
            "DATA_FILE": os.path.join(cls.tmp.name, "data.json"),
            "ADMIN_USER": "admin",
            "ADMIN_PASS": "correct-password",
            "SECRET_KEY": "test-secret",
        })
        cls.mod = importlib.import_module("app")
        cls.mod.DATA_FILE = os.environ["DATA_FILE"]
        cls.mod.ADMIN_USER = os.environ["ADMIN_USER"]
        cls.mod.ADMIN_PASS = os.environ["ADMIN_PASS"]
        cls.mod.app.config.update(TESTING=True, SERVER_NAME="example.test", PREFERRED_URL_SCHEME="https")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.client = self.mod.app.test_client()
        self.mod._login_failures.clear()
        self.mod.save({
            "hosts": {"home.example.com": {"key": "ddns-secret", "proxied": False, "ttl": 120}},
            "tokens": [{"id": "t1", "token": "cf-secret", "zones": [{"name": "example.com", "id": "z1"}]}],
            "certs": {"example.com": {"download_token": "cert-secret", "expires_at": None}},
        })

    def csrf_headers(self):
        with self.client.session_transaction() as session:
            session["csrf"] = "test-csrf"
        return {"Origin": "https://example.test", "X-CSRF-Token": "test-csrf"}

    def login(self, next_path=None):
        path = "/login" + ("?next=" + next_path if next_path else "")
        return self.client.post(path, data={"username": "admin", "password": "correct-password"},
                                base_url="https://example.test",
                                headers=self.csrf_headers())

    def test_csrf_rejects_cross_origin_mutation(self):
        self.login()
        r = self.client.post("/hosts", data={"hostname": "x.example.com"},
                             base_url="https://example.test", headers={"Origin": "https://evil.test"})
        self.assertEqual(r.status_code, 403)

    def test_csrf_rejects_same_origin_mutation_without_token(self):
        r = self.client.post("/login", data={"username": "admin", "password": "wrong"},
                             base_url="https://example.test", headers={"Origin": "https://example.test"})
        self.assertEqual(r.status_code, 403)

    def test_login_does_not_open_redirect(self):
        r = self.login("//evil.test/path")
        self.assertEqual(r.headers["Location"], "/")

    def test_login_rate_limit(self):
        for _ in range(self.mod.LOGIN_MAX_FAILURES):
            self.client.post("/login", data={"username": "admin", "password": "wrong"},
                             base_url="https://example.test", headers=self.csrf_headers())
        r = self.client.post("/login", data={"username": "admin", "password": "wrong"},
                             base_url="https://example.test", headers=self.csrf_headers())
        self.assertEqual(r.status_code, 429)

    def test_ddns_key_cannot_download_certificate(self):
        r = self.client.get("/cert", headers={"Authorization": "Bearer ddns-secret"},
                            base_url="https://example.test")
        self.assertEqual(r.status_code, 403)

    def test_query_certificate_secret_disabled(self):
        r = self.client.get("/cert?key=cert-secret", base_url="https://example.test")
        self.assertEqual(r.status_code, 403)

    def test_certificate_token_can_be_rotated_and_revoked(self):
        self.login()
        headers = self.csrf_headers()
        cert_id = next(iter(self.mod.load()["certs"]))
        rotated = self.client.post(f"/certs/{cert_id}/token", base_url="https://example.test", headers=headers)
        token = rotated.get_json()["token"]
        self.assertNotEqual(token, "cert-secret")
        self.assertTrue(self.mod.load()["certs"][cert_id].get("download_token_hash"))
        old = self.client.get("/cert", base_url="https://example.test",
                              headers={"Authorization": "Bearer cert-secret"})
        self.assertEqual(old.status_code, 403)
        revoked = self.client.delete(f"/certs/{cert_id}/token", base_url="https://example.test", headers=headers)
        self.assertEqual(revoked.status_code, 200)
        self.assertNotIn("download_token_hash", self.mod.load()["certs"][cert_id])

    def test_invalid_hostname_is_not_added(self):
        self.login()
        self.client.post("/hosts", data={"hostname": "bad_name.example.com", "ttl": "120"},
                         base_url="https://example.test", headers=self.csrf_headers())
        self.assertNotIn("bad_name.example.com", self.mod.load()["hosts"])

    def test_sensitive_response_is_not_cached(self):
        r = self.client.get("/cert", headers={"Authorization": "Bearer wrong"},
                            base_url="https://example.test")
        self.assertIn("no-store", r.headers["Cache-Control"])


if __name__ == "__main__":
    unittest.main()

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import threading
import unittest

from certificates import certificate_id


ROOT = Path(__file__).resolve().parents[1]


class CertificateSyncRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.fixtures.cleanup)
        cls.pairs = {}
        for name in ("one.example.com", "two.example.com"):
            prefix = Path(cls.fixtures.name) / name
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", str(prefix) + ".key", "-out", str(prefix) + ".pem",
                            "-days", "1", "-subj", "/CN=" + name,
                            "-addext", "subjectAltName=DNS:" + name],
                           capture_output=True, check=True)
            cls.pairs[name] = (Path(str(prefix) + ".pem").read_bytes(), Path(str(prefix) + ".key").read_bytes())

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name) / "certificates"
        self.requests = []
        self.responses = dict(zip(("fullchain", "key"), self.pairs["one.example.com"]))
        test = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                test.requests.append((self.path, self.headers.get("Authorization")))
                data = test.responses[self.path.rsplit("/", 1)[-1]]
                self.send_response(200)
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.reload_marker = Path(self.tmp.name) / "reloaded"
        self.reload = "touch " + shlex.quote(str(self.reload_marker))

    def run_sync(self):
        config = Path(self.tmp.name) / "client.env"
        values = {"CERT_ENDPOINT": "http://127.0.0.1:" + str(self.server.server_port),
                  "CERT_ID": certificate_id("single", "one.example.com"),
                  "CERT_TOKEN": "test-only-secret", "CERT_HOSTNAME": "one.example.com",
                  "CERT_DIR": str(self.directory), "RELOAD_CMD": self.reload, "ALLOW_HTTP": "1"}
        config.write_text("\n".join(key + "=" + shlex.quote(value) for key, value in values.items()))
        config.chmod(0o600)
        return subprocess.run(["bash", str(ROOT / "client/cert-sync.sh")],
                              env={**os.environ, "DDNS_CLIENT_CONFIG": str(config)}, capture_output=True, text=True)

    def test_valid_certificate_uses_scoped_url_and_protected_key(self):
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.reload_marker.exists())
        self.assertEqual((self.directory / "key.pem").stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.directory / "fullchain.pem").read_bytes(), self.pairs["one.example.com"][0])
        for path, auth in self.requests:
            self.assertIn("/cert/" + certificate_id("single", "one.example.com") + "/", path)
            self.assertNotIn("test-only-secret", path)
            self.assertEqual(auth, "Bearer test-only-secret")
        self.reload_marker.unlink()
        self.assertEqual(self.run_sync().returncode, 0)
        self.assertFalse(self.reload_marker.exists())

    def test_mismatched_private_key_does_not_replace_existing_files(self):
        self.assertEqual(self.run_sync().returncode, 0)
        old_key = (self.directory / "key.pem").read_bytes()
        self.reload_marker.unlink()
        self.responses["key"] = self.pairs["two.example.com"][1]
        result = self.run_sync()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.directory / "key.pem").read_bytes(), old_key)
        self.assertFalse(self.reload_marker.exists())

    def test_wrong_hostname_does_not_install_a_certificate(self):
        self.responses = dict(zip(("fullchain", "key"), self.pairs["two.example.com"]))
        result = self.run_sync()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.directory / "key.pem").exists())
        self.assertFalse(self.reload_marker.exists())

    def test_failed_reload_is_retried_even_when_certificate_is_unchanged(self):
        self.reload = "exit 1"
        self.assertNotEqual(self.run_sync().returncode, 0)
        self.assertTrue((self.directory / ".reload-pending").exists())
        self.reload = "touch " + shlex.quote(str(self.reload_marker))
        self.assertEqual(self.run_sync().returncode, 0)
        self.assertTrue(self.reload_marker.exists())
        self.assertFalse((self.directory / ".reload-pending").exists())


if __name__ == "__main__":
    unittest.main()

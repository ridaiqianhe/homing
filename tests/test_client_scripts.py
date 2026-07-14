import os
import pathlib
import stat
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "client" / "install.sh"


class NativeClientTests(unittest.TestCase):
    def run_installer(self, root, *args, **extra):
        env = os.environ.copy()
        env.update({
            "DDNS_CLIENT_ROOT": str(root),
            "DDNS_ENDPOINT": "https://panel.example.test",
            "DDNS_API_KEY": "ddns secret",
            "CERT_ENDPOINT": "https://panel.example.test",
            "CERT_TOKEN": "cert secret",
            "CERT_DIR": "/etc/ssl/private/panel",
            "RELOAD_CMD": "systemctl reload nginx",
        })
        env.update(extra)
        return subprocess.run(["bash", str(INSTALLER), *args], env=env, text=True,
                              capture_output=True, check=True)

    def test_config_is_0600_and_shell_quoted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.run_installer(root, "configure")
            config = root / "etc/ddns-panel/client.env"
            self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)
            text = config.read_text()
            self.assertIn("DDNS_API_KEY='ddns secret'", text)
            self.assertIn("RELOAD_CMD='systemctl reload nginx'", text)

    def test_cron_has_no_secrets_or_urls(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.run_installer(root, "configure")
            self.run_installer(root, "cron", INTERVAL_MINUTES="10")
            cron = (root / "etc/cron.d/ddns-panel-client").read_text()
            self.assertIn("*/10", cron)
            self.assertNotIn("ddns secret", cron)
            self.assertNotIn("cert secret", cron)
            self.assertNotIn("https://", cron)

    def test_scripts_use_headers_and_not_query_secrets(self):
        ddns = (ROOT / "client/ddns-update.sh").read_text()
        cert = (ROOT / "client/cert-sync.sh").read_text()
        self.assertIn("curl --config -", ddns)
        self.assertIn("curl --config -", cert)
        self.assertIn('X-Api-Key: %s', ddns)
        self.assertIn('Authorization: Bearer %s', cert)
        self.assertNotIn('-H "X-Api-Key:', ddns)
        self.assertNotIn('-H "Authorization:', cert)
        self.assertNotIn("?key=", ddns + cert)

    def test_systemd_units_have_no_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.run_installer(root, "configure")
            self.run_installer(root, "systemd")
            units = "\n".join(p.read_text() for p in (root / "etc/systemd/system").glob("ddns-panel-*"))
            self.assertIn("OnUnitActiveSec=5min", units)
            self.assertIn("Environment=DDNS_CLIENT_CONFIG=", units)
            self.assertNotIn("ddns secret", units)
            self.assertNotIn("cert secret", units)
            self.assertNotIn("https://", units)

    def test_status_and_uninstall_preserve_config_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.run_installer(root, "configure")
            self.run_installer(root, "cron")
            status_result = self.run_installer(root, "status")
            self.assertIn("Scheduler: cron", status_result.stdout)
            self.run_installer(root, "uninstall")
            self.assertTrue((root / "etc/ddns-panel/client.env").exists())
            self.assertFalse((root / "etc/cron.d/ddns-panel-client").exists())

    def test_dry_run_does_not_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            result = self.run_installer(root, "configure", DDNS_CLIENT_DRY_RUN="1")
            self.assertIn("[dry-run]", result.stdout)
            self.assertFalse((root / "etc/ddns-panel/client.env").exists())


if __name__ == "__main__":
    unittest.main()

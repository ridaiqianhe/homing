import os
import pathlib
import stat
import subprocess
import tempfile
import shutil
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
            "DDNS_IP_FAMILY": "4",
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
            self.assertIn("DDNS_IP_FAMILY='4'", text)
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
        self.assertIn('4) curl_args+=(--ipv4)', ddns)
        self.assertIn('6) curl_args+=(--ipv6)', ddns)
        self.assertIn('auto) ;;', ddns)

    def test_remote_bootstrap_is_https_and_validates_downloads(self):
        installer = INSTALLER.read_text()
        self.assertIn('case "$INSTALL_BASE" in https://*', installer)
        self.assertIn("--proto '=https' --tlsv1.2", installer)
        self.assertIn('bash -n "$DOWNLOAD_DIR/$name"', installer)
        self.assertIn('DDNS_INSTALL_BASE:-https://ddns.227755.xyz/client', installer)

    def test_remote_bootstrap_installs_missing_companions(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            isolated = base / "bootstrap"
            fake_bin = base / "bin"
            root = base / "root"
            isolated.mkdir()
            fake_bin.mkdir()
            shutil.copy2(INSTALLER, isolated / "install.sh")
            fake_curl = fake_bin / "curl"
            fake_curl.write_text("""#!/usr/bin/env bash
set -eu
out=''
url=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    http*) url="$1"; shift ;;
    *) shift ;;
  esac
done
cp "$FIXTURE_DIR/${url##*/}" "$out"
""")
            fake_curl.chmod(0o755)
            env = os.environ.copy()
            env.update({
                "PATH": f"{fake_bin}:{env['PATH']}",
                "FIXTURE_DIR": str(ROOT / "client"),
                "DDNS_CLIENT_ROOT": str(root),
                "DDNS_ENDPOINT": "https://panel.example.test",
                "DDNS_API_KEY": "secret",
                "DDNS_IP_FAMILY": "6",
                "CERT_ENDPOINT": "https://panel.example.test",
                "CERT_TOKEN": "cert-secret",
                "CERT_DIR": "/etc/certs",
                "RELOAD_CMD": "true",
                "INTERVAL_MINUTES": "5",
            })
            subprocess.run(["bash", str(isolated / "install.sh"), "cron"], env=env,
                           text=True, capture_output=True, check=True)
            installed = root / "usr/local/lib/ddns-panel"
            self.assertTrue((installed / "ddns-update.sh").is_file())
            self.assertTrue((installed / "cert-sync.sh").is_file())

    def test_stdin_bootstrap_does_not_require_bash_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["DDNS_CLIENT_ROOT"] = tmp
            result = subprocess.run(
                ["bash", "-s", "--", "status"], input=INSTALLER.read_text(),
                env=env, text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

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

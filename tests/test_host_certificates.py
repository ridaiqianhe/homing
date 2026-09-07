from pathlib import Path
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import app as panel
from certificate_commands import pull_commands
from certificates import (certificate_paths, new_certificate,
                          rotate_download_token, token_authorizes)
from dns_slots import new_slot


class HostCertificateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.settings = patch.multiple(panel, DATA_FILE=self.tmp.name + "/data.json",
                                       CERT_DIR=self.tmp.name + "/certs", ADMIN_USER="admin",
                                       ACME_CONF=self.tmp.name + "/acme")
        self.settings.start()
        self.addCleanup(self.settings.stop)
        config = patch.dict(panel.app.config, TESTING=True, SESSION_COOKIE_SECURE=False)
        config.start()
        self.addCleanup(config.stop)
        panel.save({"hosts": {"one.example.com": {"slots": [new_slot("A"), new_slot("AAAA")]},
                              "two.example.com": {"slots": [new_slot("A")]}},
                    "tokens": [{"token": "cloudflare-secret", "id": "cf", "zones": [
                        {"name": "example.com", "id": "zone"}]}], "certs": {}})
        self.client = panel.app.test_client()
        with self.client.session_transaction() as session:
            session.update(u="admin", csrf="csrf")
        self.headers = {"X-CSRF-Token": "csrf"}

    def ensure(self, host="one.example.com", ready=True):
        response = self.client.post("/hosts/" + host + "/certificate", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        cert_id = response.json["certificate"]["id"]
        if ready:
            d = panel.load()
            cert = d["certs"][cert_id]
            cert["expires_at"] = int(time.time()) + 86400
            paths = certificate_paths(cert, panel.CERT_DIR)
            Path(paths["directory"]).mkdir(parents=True, exist_ok=True)
            Path(paths["fullchain"]).write_text("certificate for " + host)
            Path(paths["key"]).write_text("key for " + host)
            panel.save(d)
        return cert_id

    def grant(self, cert_id, label="server-one"):
        response = self.client.post("/certs/" + cert_id + "/clients", headers=self.headers,
                                    data={"label": label, "directory": "/etc/ssl/test"})
        self.assertEqual(response.status_code, 200)
        return response.json

    def test_host_entry_is_idempotent_and_never_uses_wildcard(self):
        d = panel.load()
        wildcard = new_certificate("wildcard", "example.com")
        d["certs"][wildcard["id"]] = wildcard
        panel.save(d)
        cert_id = self.ensure()
        self.assertEqual(self.ensure(), cert_id)
        self.assertNotEqual(wildcard["id"], cert_id)
        self.assertEqual(panel.load()["certs"][cert_id]["domains"], ["one.example.com"])
        self.assertEqual(len(panel.load()["certs"]), 2)
        self.assertNotEqual(cert_id, self.ensure("two.example.com"))

    def test_every_record_row_has_its_domain_entry_without_credentials(self):
        cert_id = self.ensure()
        grant = self.grant(cert_id)
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text.count('data-host-certificate="one.example.com"'), 2)
        self.assertEqual(response.text.count('data-host-certificate="two.example.com"'), 1)
        self.assertNotIn(grant["token"], response.text)
        self.assertNotIn("cloudflare-secret", response.text)

    def test_mutations_require_login_csrf_and_managed_host(self):
        self.assertEqual(self.client.post("/hosts/one.example.com/certificate").status_code, 403)
        self.assertEqual(self.client.post("/hosts/other.example.com/certificate", headers=self.headers).status_code, 404)
        with self.client.session_transaction() as session:
            session.pop("u")
        self.assertEqual(self.client.post("/hosts/one.example.com/certificate", headers=self.headers).status_code, 302)

    def test_unissued_certificate_cannot_generate_deployment_credentials(self):
        cert_id = self.ensure(ready=False)
        response = self.client.post("/certs/" + cert_id + "/clients", headers=self.headers,
                                    data={"label": "server", "directory": "/etc/ssl/test"})
        self.assertEqual(response.status_code, 409)
        self.assertNotIn("download_clients", panel.load()["certs"][cert_id])

    def test_multiple_clients_are_independent_and_revocation_is_scoped(self):
        first = self.ensure()
        second = self.ensure("two.example.com")
        a, b, c = self.grant(first), self.grant(first, "server-two"), self.grant(second)
        for grant in (a, b):
            response = self.client.get("/cert/" + first + "/key", headers={"Authorization": "Bearer " + grant["token"]})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.text, "key for one.example.com")
            response.close()
            self.assertEqual(self.client.get("/cert/" + second + "/key", headers={"Authorization": "Bearer " + grant["token"]}).status_code, 403)
        self.assertEqual(self.client.delete("/certs/" + second + "/clients/" + a["client"]["id"], headers=self.headers).status_code, 404)
        self.assertEqual(self.client.delete("/certs/" + first + "/clients/" + a["client"]["id"], headers=self.headers).status_code, 200)
        certs = panel.load()["certs"]
        self.assertFalse(token_authorizes(certs[first], a["token"]))
        self.assertTrue(token_authorizes(certs[first], b["token"]))
        self.assertTrue(token_authorizes(certs[second], c["token"]))

    def test_credentials_are_hashed_and_not_in_details_or_cache(self):
        cert_id = self.ensure()
        grant = self.grant(cert_id)
        stored = Path(panel.DATA_FILE).read_text()
        details = self.client.get("/certs/" + cert_id + "/details")
        self.assertNotIn(grant["token"], stored + details.text)
        self.assertNotIn("token_hash", details.text)
        self.assertIn("no-store", details.headers["Cache-Control"])
        key = panel.load()["hosts"]["one.example.com"]["slots"][0]["key"]
        self.assertEqual(self.client.get("/cert/" + cert_id + "/key", headers={"Authorization": "Bearer " + key}).status_code, 403)
        self.assertEqual(self.client.get("/cert/" + cert_id + "/key?key=" + grant["token"]).status_code, 403)

    def test_new_clients_preserve_legacy_certificate_credential(self):
        cert_id = self.ensure()
        d = panel.load()
        old_token = rotate_download_token(d["certs"][cert_id])
        panel.save(d)
        grant = self.grant(cert_id)
        cert = panel.load()["certs"][cert_id]
        self.assertTrue(token_authorizes(cert, old_token))
        self.assertTrue(token_authorizes(cert, grant["token"]))
        panel.migrate_certificate_data(d)
        self.assertTrue(token_authorizes(panel.load()["certs"][cert_id], grant["token"]))

    def test_invalid_command_options_do_not_save_a_credential(self):
        cert_id = self.ensure()
        for directory in ("relative/path", "/etc/ssl/test\ncommand"):
            response = self.client.post("/certs/" + cert_id + "/clients", headers=self.headers,
                                        data={"label": "server", "directory": directory})
            self.assertEqual(response.status_code, 400)
        self.assertNotIn("download_clients", panel.load()["certs"][cert_id])

    def test_dns_update_does_not_overwrite_a_new_certificate_client(self):
        cert_id = self.ensure()
        stale = panel.load()
        grant = self.grant(cert_id)
        current = panel.load()
        key = stale["hosts"]["one.example.com"]["slots"][0]["key"]
        with patch.object(panel, "load", side_effect=[stale, current]), patch.object(panel, "cf_update_slot", return_value=SimpleNamespace(status="nochg")):
            response = self.client.get("/api/update?ip=192.0.2.1", headers={"X-Api-Key": key})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(token_authorizes(panel.load()["certs"][cert_id], grant["token"]))

    def test_failed_issuance_does_not_report_an_old_file_as_success(self):
        cert_id = self.ensure()
        jid = panel._new_job("test")
        with patch.object(panel, "run_acme_stream", return_value=1) as run:
            panel.issue_job(jid, cert_id)
        self.assertEqual(run.call_count, 1)
        self.assertFalse(panel.JOBS[jid]["ok"])
        self.assertTrue(panel.JOBS[jid]["done"])

    def test_duplicate_issue_requests_share_one_job(self):
        cert_id = self.ensure()
        with patch.dict(panel.JOBS, {}, clear=True), patch.object(panel.threading, "Thread") as thread:
            first = self.client.post("/certs/" + cert_id + "/issue", headers=self.headers)
            second = self.client.post("/certs/" + cert_id + "/issue", headers=self.headers)
            self.assertEqual(first.json["job"], second.json["job"])
            self.assertEqual(thread.call_count, 1)

    def test_silent_acme_child_process_is_stopped_at_timeout(self):
        script = Path(self.tmp.name) / "acme.sh"
        script.write_text("#!/bin/bash\nsleep 10\n")
        jid = panel._new_job("timeout test")
        start = time.monotonic()
        with patch.object(panel, "ACME", str(script)):
            result = panel.run_acme_stream(jid, [], "test-secret", "zone", panel.ACME_CONF, timeout=0.1)
        self.assertNotEqual(result, 0)
        self.assertLess(time.monotonic() - start, 3)
        self.assertIn("[timeout, killed]", panel.JOBS[jid]["lines"])


class PullCommandTests(unittest.TestCase):
    def test_commands_have_isolated_paths_and_no_secrets_in_cron(self):
        for target in ("one.example.com", "two.example.com"):
            cert = new_certificate("single", target)
            commands = pull_commands(cert, "test-only-secret", "https://panel.example.com", "/etc/ssl/" + target)
            for command in commands.values():
                result = subprocess.run(["bash", "-n"], input=command, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("CERT_ID=" + cert["id"], command)
                self.assertIn("CERT_HOSTNAME=" + target, command)
            cron = commands["cron"].split("<<'DDNS_CERT_CRON'\n", 1)[1].split("DDNS_CERT_CRON", 1)[0]
            self.assertNotIn("test-only-secret", cron)
            self.assertNotIn("https://", cron)
            self.assertIn(cert["id"], cron)

    def test_config_values_are_shell_quoted(self):
        cert = new_certificate("single", "one.example.com")
        directory = "/etc/ssl/a 'quoted' $(echo injected)"
        reload = "printf '%s' 'service reloaded'"
        command = pull_commands(cert, "test-secret", "https://panel.example.com", directory, reload)["once"]
        config = command.split("<<'DDNS_CERT_CONFIG'\n", 1)[1].split("DDNS_CERT_CONFIG", 1)[0]
        result = subprocess.run(["bash"], input=config + "printf '%s\\n' \"$CERT_DIR\" \"$RELOAD_CMD\"", text=True, capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.splitlines(), [directory, reload])


if __name__ == "__main__":
    unittest.main()

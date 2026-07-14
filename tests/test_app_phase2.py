import json
import os
import tempfile
import unittest

import app as panel


class Phase2AppTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.originals = (panel.DATA_FILE, panel.ADMIN_USER, panel.ADMIN_PASS)
        panel.DATA_FILE = os.path.join(self.tmp.name, "data.json")
        panel.ADMIN_USER = "admin"
        panel.ADMIN_PASS = "correct"
        panel.app.config.update(TESTING=True, SESSION_COOKIE_SECURE=False)
        panel.save({
            "hosts": {"multi.example.com": {
                "label": "legacy", "key": "legacy-key", "proxied": False, "ttl": 120,
            }},
            "tokens": [{"id": "t1", "token": "cf-token", "zones": [{"name": "example.com", "id": "z1"}]}],
            "certs": {},
        })
        self.client = panel.app.test_client()
        with self.client.session_transaction() as session:
            session["u"] = "admin"
            session["csrf"] = "csrf"
        self.headers = {"X-CSRF-Token": "csrf", "Origin": "http://localhost"}

    def tearDown(self):
        panel.DATA_FILE, panel.ADMIN_USER, panel.ADMIN_PASS = self.originals
        self.tmp.cleanup()

    def test_legacy_host_key_becomes_default_slot(self):
        data = panel.load()
        slot = data["hosts"]["multi.example.com"]["slots"][0]
        self.assertEqual(slot["key"], "legacy-key")
        self.assertEqual(slot["type"], "A")

    def test_same_hostname_can_add_second_a_and_aaaa_slots(self):
        for record_type in ("A", "AAAA"):
            response = self.client.post(
                "/hosts",
                data={"hostname": "multi.example.com", "record_type": record_type, "ttl": "120", "label": record_type},
                headers=self.headers,
            )
            self.assertEqual(response.status_code, 302)
        slots = panel.load()["hosts"]["multi.example.com"]["slots"]
        self.assertEqual([slot["type"] for slot in slots], ["A", "A", "AAAA"])
        self.assertEqual(len({slot["key"] for slot in slots}), 3)

    def test_api_update_enforces_slot_address_family(self):
        response = self.client.post(
            "/hosts", data={"hostname": "v6.example.com", "record_type": "AAAA", "ttl": "120"},
            headers=self.headers,
        )
        key = panel.load()["hosts"]["v6.example.com"]["slots"][0]["key"]
        bad = self.client.get("/api/update?ip=192.0.2.1", headers={"X-Api-Key": key})
        self.assertEqual(bad.status_code, 400)
        self.assertIn("IPv6", bad.get_json()["error"])

    def test_single_and_wildcard_certificates_are_distinct(self):
        single = self.client.post(
            "/certificates", data={"scope": "single", "target": "multi.example.com"}, headers=self.headers
        )
        wildcard = self.client.post(
            "/certificates", data={"scope": "wildcard", "target": "example.com"}, headers=self.headers
        )
        self.assertEqual(single.status_code, 200)
        self.assertEqual(wildcard.status_code, 200)
        self.assertNotEqual(single.get_json()["certificate"], wildcard.get_json()["certificate"])
        self.assertEqual(len(panel.load()["certs"]), 2)

    def test_native_client_scripts_are_served_without_secrets(self):
        response = self.client.get("/client/install.sh")
        self.assertEqual(response.status_code, 200)
        self.assertIn("no-store", response.headers["Cache-Control"])
        self.assertIn(b"DDNS_IP_FAMILY", response.data)
        response.close()
        self.assertEqual(self.client.get("/client/unknown.sh").status_code, 404)


if __name__ == "__main__":
    unittest.main()

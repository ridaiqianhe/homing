import copy
import os
import tempfile
import unittest

import certificates


class CertificateModelTests(unittest.TestCase):
    def test_ids_are_stable_and_scopes_do_not_collide(self):
        single = certificates.new_certificate("single", "nas.example.com")
        same = certificates.new_certificate("single", "NAS.EXAMPLE.COM")
        wildcard = certificates.new_certificate("wildcard", "example.com")
        self.assertEqual(single["id"], same["id"])
        self.assertNotEqual(single["id"], wildcard["id"])
        self.assertEqual(wildcard["domains"], ["example.com", "*.example.com"])

    def test_scope_membership_can_be_enforced_at_creation(self):
        certificates.new_certificate("single", "nas.example.com", managed_hosts=["nas.example.com"])
        certificates.new_certificate("wildcard", "example.com", managed_zones=["example.com"])
        with self.assertRaises(certificates.CertificateError):
            certificates.new_certificate("single", "other.example.com", managed_hosts=["nas.example.com"])
        with self.assertRaises(certificates.CertificateError):
            certificates.new_certificate("wildcard", "evil.test", managed_zones=["example.com"])

    def test_strict_dns_validation(self):
        for value in ("../example.com", "*.example.com", "bad_name.example.com", "example.com.", "localhost"):
            with self.subTest(value=value), self.assertRaises(certificates.CertificateError):
                certificates.new_certificate("single", value)

    def test_paths_use_only_certificate_id_and_block_traversal(self):
        cert = certificates.new_certificate("single", "nas.example.com")
        with tempfile.TemporaryDirectory() as root:
            paths = certificates.certificate_paths(cert, root)
            self.assertEqual(os.path.dirname(paths["fullchain"]), paths["directory"])
            self.assertEqual(os.path.basename(paths["directory"]), cert["id"])
            broken = dict(cert, id="../../etc")
            with self.assertRaises(certificates.CertificateError):
                certificates.certificate_paths(broken, root)

    def test_acme_arguments_match_scope(self):
        single = certificates.new_certificate("single", "nas.example.com")
        wildcard = certificates.new_certificate("wildcard", "example.com")
        self.assertEqual(certificates.acme_issue_args(single).count("-d"), 1)
        self.assertEqual(certificates.acme_issue_args(wildcard).count("-d"), 2)
        self.assertIn("*.example.com", certificates.acme_issue_args(wildcard))
        for cert in (single, wildcard):
            issue = certificates.acme_issue_args(cert)
            install = certificates.acme_install_args(cert, "/tmp/certs")
            self.assertEqual(issue[issue.index("-d") + 1], install[install.index("-d") + 1])

    def test_legacy_files_move_without_overwriting_new_output(self):
        cert = certificates.new_certificate("wildcard", "example.com")
        with tempfile.TemporaryDirectory() as root:
            legacy = os.path.join(root, "example.com")
            os.mkdir(legacy)
            with open(os.path.join(legacy, "fullchain.pem"), "w") as handle:
                handle.write("legacy")
            self.assertTrue(certificates.migrate_legacy_certificate_files(cert, root))
            paths = certificates.certificate_paths(cert, root)
            with open(paths["fullchain"]) as handle:
                self.assertEqual(handle.read(), "legacy")
            self.assertFalse(certificates.migrate_legacy_certificate_files(cert, root))

    def test_tokens_rotate_revoke_and_are_scope_isolated(self):
        single = certificates.new_certificate("single", "nas.example.com")
        wildcard = certificates.new_certificate("wildcard", "example.com")
        first = certificates.rotate_download_token(single)
        wildcard_token = certificates.rotate_download_token(wildcard)
        self.assertTrue(certificates.token_authorizes(single, first))
        self.assertFalse(certificates.token_authorizes(wildcard, first))
        self.assertFalse(certificates.token_authorizes(single, wildcard_token))
        self.assertNotIn(first, repr(single))
        second = certificates.rotate_download_token(single)
        self.assertFalse(certificates.token_authorizes(single, first))
        self.assertTrue(certificates.token_authorizes(single, second))
        certificates.revoke_download_token(single)
        self.assertFalse(certificates.token_authorizes(single, second))

    def test_authentication_rejects_ambiguous_reused_token(self):
        first = certificates.new_certificate("single", "one.example.com")
        second = certificates.new_certificate("single", "two.example.com")
        digest = certificates.token_digest("reused-secret")
        first["download_token_hash"] = digest
        second["download_token_hash"] = digest
        self.assertIsNone(certificates.authenticate_certificate({first["id"]: first, second["id"]: second}, "reused-secret"))

    def test_legacy_migration_is_lossless_and_idempotent(self):
        data = {"certs": {"example.com": {
            "download_token": "legacy-secret",
            "expires_at": 123,
            "custom_metadata": {"keep": True},
        }}}
        self.assertTrue(certificates.migrate_certificate_data(data))
        cert = next(iter(data["certs"].values()))
        self.assertEqual(cert["scope"], "wildcard")
        self.assertEqual(cert["target"], "example.com")
        self.assertEqual(cert["expires_at"], 123)
        self.assertEqual(cert["custom_metadata"], {"keep": True})
        self.assertNotIn("download_token", cert)
        self.assertTrue(certificates.token_authorizes(cert, "legacy-secret"))
        once = copy.deepcopy(data)
        self.assertFalse(certificates.migrate_certificate_data(data))
        self.assertEqual(data, once)

    def test_dns_update_keys_never_authorize_certificates(self):
        cert = certificates.new_certificate("single", "nas.example.com")
        certificates.rotate_download_token(cert)
        self.assertFalse(certificates.token_authorizes(cert, "ddns-update-key"))


if __name__ == "__main__":
    unittest.main()

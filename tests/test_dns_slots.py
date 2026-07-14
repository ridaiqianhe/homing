import unittest

from dns_slots import (
    SlotConflict,
    delete_slot_record,
    find_slot,
    find_slot_by_key,
    migrate_hosts,
    new_slot,
    normalize_ip_for_slot,
    upsert_slot,
)


class FakeCloudflare:
    def __init__(self, records=()):
        self.records = {record["id"]: dict(record) for record in records}
        self.calls = []

    def __call__(self, method, path, token, body=None):
        self.calls.append((method, path, body))
        if method == "GET" and "?" in path:
            query = path.split("?", 1)[1]
            record_type = "AAAA" if "type=AAAA" in query else "A"
            name = query.split("name=", 1)[1].replace("%2E", ".")
            found = [r for r in self.records.values() if r["type"] == record_type and r["name"] == name]
            return {"success": True, "result": found}
        record_id = path.rsplit("/", 1)[-1]
        if method == "GET":
            return {"success": True, "result": self.records.get(record_id)}
        if method == "POST":
            record_id = "created-1"
            self.records[record_id] = {"id": record_id, **body}
            return {"success": True, "result": self.records[record_id]}
        if method == "PUT":
            self.records[record_id] = {"id": record_id, **body}
            return {"success": True, "result": self.records[record_id]}
        if method == "DELETE":
            self.records.pop(record_id, None)
            return {"success": True, "result": {"id": record_id}}
        raise AssertionError((method, path))


class DnsSlotTests(unittest.TestCase):
    def test_migration_is_idempotent_and_preserves_key(self):
        original = {"hosts": {"home.example.com": {"key": "keep-me", "proxied": False, "ttl": 120}}}
        once, changed = migrate_hosts(original)
        twice, changed_again = migrate_hosts(once)
        self.assertTrue(changed)
        self.assertFalse(changed_again)
        self.assertEqual(once, twice)
        slot = find_slot(once, "home.example.com")
        self.assertEqual(slot["key"], "keep-me")
        self.assertEqual(find_slot_by_key(once, "keep-me")[0], "home.example.com")

    def test_two_a_slots_update_independent_record_ids(self):
        first = new_slot("A", "HK", key="key-1", record_id="r1")
        second = new_slot("A", "US", key="key-2", record_id="r2")
        cf = FakeCloudflare([
            {"id": "r1", "type": "A", "name": "app.example.com", "content": "1.1.1.1", "ttl": 120, "proxied": False},
            {"id": "r2", "type": "A", "name": "app.example.com", "content": "2.2.2.2", "ttl": 120, "proxied": False},
        ])
        upsert_slot(cf, "z1", "token", "app.example.com", second, "3.3.3.3", now=10)
        self.assertEqual(cf.records["r1"]["content"], "1.1.1.1")
        self.assertEqual(cf.records["r2"]["content"], "3.3.3.3")
        self.assertEqual(second["last_ip"], "3.3.3.3")

    def test_ipv6_slot_accepts_only_ipv6(self):
        slot = new_slot("AAAA")
        self.assertEqual(normalize_ip_for_slot(slot, "2001:0db8::1"), "2001:db8::1")
        with self.assertRaises(ValueError):
            normalize_ip_for_slot(slot, "192.0.2.1")

    def test_ambiguous_unbound_records_fail_without_write(self):
        slot = new_slot("A")
        cf = FakeCloudflare([
            {"id": "r1", "type": "A", "name": "app.example.com", "content": "1.1.1.1"},
            {"id": "r2", "type": "A", "name": "app.example.com", "content": "2.2.2.2"},
        ])
        with self.assertRaisesRegex(SlotConflict, "multiple matching"):
            upsert_slot(cf, "z1", "token", "app.example.com", slot, "3.3.3.3")
        self.assertIsNone(slot["record_id"])
        self.assertFalse(any(call[0] in ("POST", "PUT") for call in cf.calls))

    def test_single_unbound_record_is_bound_then_updated(self):
        slot = new_slot("A")
        cf = FakeCloudflare([
            {"id": "r1", "type": "A", "name": "app.example.com", "content": "1.1.1.1", "ttl": 120, "proxied": False},
        ])
        result = upsert_slot(cf, "z1", "token", "app.example.com", slot, "2.2.2.2")
        self.assertEqual(result.record_id, "r1")
        self.assertEqual(slot["record_id"], "r1")
        self.assertEqual(cf.records["r1"]["content"], "2.2.2.2")

    def test_zero_records_creates_and_binds(self):
        slot = new_slot("AAAA")
        cf = FakeCloudflare()
        result = upsert_slot(cf, "z1", "token", "v6.example.com", slot, "2001:db8::2")
        self.assertEqual(result.record_id, "created-1")
        self.assertEqual(slot["record_id"], "created-1")

    def test_reserved_record_is_not_reused_by_another_slot(self):
        slot = new_slot("A", key="second")
        cf = FakeCloudflare([
            {"id": "already-owned", "type": "A", "name": "multi.example.com",
             "content": "192.0.2.1", "ttl": 120, "proxied": False},
        ])
        result = upsert_slot(cf, "z1", "token", "multi.example.com", slot, "192.0.2.2",
                             reserved_record_ids={"already-owned"})
        self.assertEqual(result.status, "good")
        self.assertNotEqual(slot["record_id"], "already-owned")

    def test_delete_targets_only_bound_record(self):
        slot = new_slot("A", record_id="r2")
        cf = FakeCloudflare([
            {"id": "r1", "type": "A", "name": "app.example.com", "content": "1.1.1.1"},
            {"id": "r2", "type": "A", "name": "app.example.com", "content": "2.2.2.2"},
        ])
        result = delete_slot_record(cf, "z1", "token", slot)
        self.assertEqual(result.record_id, "r2")
        self.assertIn("r1", cf.records)
        self.assertNotIn("r2", cf.records)
        self.assertIsNone(slot["record_id"])


if __name__ == "__main__":
    unittest.main()

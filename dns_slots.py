"""DNS record slot data model and Cloudflare operations.

This module deliberately has no Flask or storage dependency. Callers persist the
mutated data/slot after a successful migration or provider operation.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import ipaddress
import secrets
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any, Callable, Mapping, MutableMapping


RECORD_TYPES = frozenset(("A", "AAAA"))
DEFAULT_SLOT_LABEL = "Default IPv4"


class SlotError(Exception):
    """Base error for invalid slot operations."""


class SlotNotFound(SlotError):
    pass


class SlotConflict(SlotError):
    """Raised when an unbound slot matches multiple provider records."""


class ProviderError(SlotError):
    pass


@dataclass(frozen=True)
class SlotResult:
    status: str
    record_id: str | None
    ip: str | None = None


def stable_legacy_slot_id(hostname: str) -> str:
    """Return a deterministic ID so repeated/offline migrations agree."""
    digest = hashlib.sha256(("legacy-default-a\0" + hostname.lower()).encode()).hexdigest()
    return "slot_" + digest[:20]


def new_slot_id() -> str:
    return "slot_" + secrets.token_hex(10)


def new_slot(
    record_type: str,
    label: str = "",
    *,
    key: str | None = None,
    slot_id: str | None = None,
    record_id: str | None = None,
    proxied: bool = False,
    ttl: int = 120,
    created: int | None = None,
) -> dict[str, Any]:
    record_type = record_type.upper()
    if record_type not in RECORD_TYPES:
        raise ValueError("record_type must be A or AAAA")
    if isinstance(ttl, bool) or not isinstance(ttl, int) or not (ttl == 1 or 60 <= ttl <= 86400):
        raise ValueError("ttl must be 1 or between 60 and 86400")
    if proxied:
        ttl = 1
    return {
        "id": slot_id or new_slot_id(),
        "type": record_type,
        "label": label.strip(),
        "key": key or secrets.token_urlsafe(24),
        "record_id": record_id,
        "last_ip": None,
        "last_update": None,
        "proxied": bool(proxied),
        "ttl": ttl,
        "created": int(time.time()) if created is None else int(created),
    }


def migrate_hosts(data: Mapping[str, Any]) -> tuple[dict[str, Any], bool]:
    """Return a migrated deep copy and whether it changed.

    Legacy host credentials are preserved byte-for-byte in a deterministic
    default A slot. Unknown host fields are retained for forward compatibility.
    """
    migrated = copy.deepcopy(dict(data))
    hosts = migrated.setdefault("hosts", {})
    changed = False
    for hostname, host in list(hosts.items()):
        if not isinstance(host, dict):
            continue
        if isinstance(host.get("slots"), list):
            continue
        slot = new_slot(
            "A",
            host.get("label") or DEFAULT_SLOT_LABEL,
            key=host.get("key"),
            slot_id=stable_legacy_slot_id(hostname),
            record_id=host.get("record_id"),
            proxied=bool(host.get("proxied", False)),
            ttl=int(host.get("ttl", 120)),
            created=host.get("created"),
        )
        slot["last_ip"] = host.get("last_ip")
        slot["last_update"] = host.get("last_update")
        host["slots"] = [slot]
        changed = True
    return migrated, changed


def slots_for_host(data: Mapping[str, Any], hostname: str) -> list[MutableMapping[str, Any]]:
    host = data.get("hosts", {}).get(hostname)
    if not isinstance(host, Mapping):
        raise SlotNotFound("hostname not found")
    slots = host.get("slots")
    if not isinstance(slots, list):
        raise SlotNotFound("hostname has not been migrated to slots")
    return slots


def find_slot(data: Mapping[str, Any], hostname: str, slot_id: str | None = None) -> MutableMapping[str, Any]:
    slots = slots_for_host(data, hostname)
    if slot_id is None:
        if len(slots) != 1:
            raise SlotConflict("hostname has multiple slots; slot_id is required")
        return slots[0]
    for slot in slots:
        if hmac.compare_digest(str(slot.get("id", "")), slot_id):
            return slot
    raise SlotNotFound("slot not found")


def find_slot_by_key(data: Mapping[str, Any], key: str, hostname: str | None = None) -> tuple[str, MutableMapping[str, Any]]:
    if not key:
        raise SlotNotFound("slot key not found")
    hosts = data.get("hosts", {})
    candidates = ((hostname, hosts.get(hostname)) if hostname else hosts.items())
    if hostname:
        candidates = [candidates]
    for name, host in candidates:
        if not isinstance(host, Mapping):
            continue
        for slot in host.get("slots", []):
            candidate = str(slot.get("key", ""))
            if candidate and hmac.compare_digest(candidate, key):
                return name, slot
    raise SlotNotFound("slot key not found")


def normalize_ip_for_slot(slot: Mapping[str, Any], value: str) -> str:
    try:
        address = ipaddress.ip_address(value.strip())
    except (AttributeError, ValueError) as exc:
        raise ValueError("invalid IP address") from exc
    expected = slot.get("type")
    if expected == "A" and address.version != 4:
        raise ValueError("A slots accept IPv4 only")
    if expected == "AAAA" and address.version != 6:
        raise ValueError("AAAA slots accept IPv6 only")
    if expected not in RECORD_TYPES:
        raise ValueError("invalid slot record type")
    return address.compressed


def _provider_result(response: Mapping[str, Any]) -> Any:
    if not response.get("success"):
        raise ProviderError("Cloudflare request failed")
    return response.get("result")


def upsert_slot(
    cf_client: Callable[..., Mapping[str, Any]],
    zone_id: str,
    token: str,
    hostname: str,
    slot: MutableMapping[str, Any],
    ip: str,
    *,
    now: int | None = None,
) -> SlotResult:
    """Create, bind, or update exactly the record owned by ``slot``."""
    ip = normalize_ip_for_slot(slot, ip)
    record_type = slot["type"]
    record_id = slot.get("record_id")

    if record_id:
        record = _provider_result(cf_client("GET", f"/zones/{zone_id}/dns_records/{record_id}", token))
        if not record or record.get("name") != hostname or record.get("type") != record_type:
            raise SlotConflict("bound record does not match slot hostname and type")
    else:
        query = urllib.parse.urlencode({"type": record_type, "name": hostname})
        records = _provider_result(cf_client("GET", f"/zones/{zone_id}/dns_records?{query}", token)) or []
        if len(records) > 1:
            raise SlotConflict("multiple matching DNS records; bind a record ID explicitly")
        record = records[0] if records else None
        if record:
            record_id = record.get("id")
            if not record_id:
                raise ProviderError("Cloudflare record has no ID")
            slot["record_id"] = record_id

    payload = {
        "type": record_type,
        "name": hostname,
        "content": ip,
        "ttl": int(slot.get("ttl", 120)),
        "proxied": bool(slot.get("proxied", False)),
    }
    if record is None:
        created = _provider_result(cf_client("POST", f"/zones/{zone_id}/dns_records", token, payload))
        record_id = created.get("id") if isinstance(created, Mapping) else None
        if not record_id:
            raise ProviderError("Cloudflare did not return a created record ID")
        slot["record_id"] = record_id
        status = "good"
    elif (
        record.get("content") == ip
        and record.get("proxied", False) == payload["proxied"]
        and int(record.get("ttl", payload["ttl"])) == payload["ttl"]
    ):
        status = "nochg"
    else:
        _provider_result(cf_client("PUT", f"/zones/{zone_id}/dns_records/{record_id}", token, payload))
        status = "good"

    slot["last_ip"] = ip
    slot["last_update"] = int(time.time()) if now is None else int(now)
    return SlotResult(status, record_id, ip)


def delete_slot_record(
    cf_client: Callable[..., Mapping[str, Any]],
    zone_id: str,
    token: str,
    slot: MutableMapping[str, Any],
) -> SlotResult:
    """Delete only the exact provider record bound to this slot."""
    record_id = slot.get("record_id")
    if not record_id:
        raise SlotNotFound("slot is not bound to a DNS record")
    _provider_result(cf_client("DELETE", f"/zones/{zone_id}/dns_records/{record_id}", token))
    slot["record_id"] = None
    return SlotResult("deleted", record_id)

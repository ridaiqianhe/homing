"""Offline/in-process migration entry point for the DNS slot schema."""

from __future__ import annotations

from typing import Any, Mapping

from dns_slots import migrate_hosts


def migrate(data: Mapping[str, Any]) -> tuple[dict[str, Any], bool]:
    return migrate_hosts(data)

"""Certificate object model, credentials, migration, and ACME path helpers."""

from __future__ import annotations

import copy
import hashlib
import hmac
import os
import re
import secrets
import shutil
from pathlib import Path
from typing import Any, Iterable, Mapping, MutableMapping


CERTIFICATE_SCHEMA_VERSION = 2
VALID_SCOPES = frozenset({"single", "wildcard"})
_DNS_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_CERT_ID = re.compile(r"^cert_[0-9a-f]{32}$")


class CertificateError(ValueError):
    """Raised when certificate input or stored data is invalid."""


def normalize_dns_name(value: str, *, field: str = "hostname") -> str:
    if not isinstance(value, str):
        raise CertificateError(f"{field} must be a string")
    name = value.strip().lower()
    if not name or name.endswith(".") or len(name) > 253:
        raise CertificateError(f"invalid {field}")
    labels = name.split(".")
    if len(labels) < 2 or any(not _DNS_LABEL.fullmatch(label) for label in labels):
        raise CertificateError(f"invalid {field}")
    return name


def normalize_zone(value: str) -> str:
    return normalize_dns_name(value, field="zone")


def zone_contains(zone: str, hostname: str, *, allow_apex: bool = True) -> bool:
    zone = normalize_zone(zone)
    hostname = normalize_dns_name(hostname)
    return (allow_apex and hostname == zone) or hostname.endswith("." + zone)


def certificate_id(scope: str, target: str) -> str:
    scope, target = normalize_scope(scope, target)
    digest = hashlib.sha256(f"ddns-panel:certificate:v2\0{scope}\0{target}".encode()).hexdigest()
    return "cert_" + digest[:32]


def normalize_scope(scope: str, target: str) -> tuple[str, str]:
    if scope not in VALID_SCOPES:
        raise CertificateError("scope must be single or wildcard")
    target = normalize_zone(target) if scope == "wildcard" else normalize_dns_name(target)
    return scope, target


def domains_for(scope: str, target: str) -> list[str]:
    scope, target = normalize_scope(scope, target)
    return [target] if scope == "single" else [target, f"*.{target}"]


def new_certificate(
    scope: str,
    target: str,
    *,
    managed_hosts: Iterable[str] | None = None,
    managed_zones: Iterable[str] | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    scope, target = normalize_scope(scope, target)
    if scope == "single" and managed_hosts is not None:
        hosts = {normalize_dns_name(host) for host in managed_hosts}
        if target not in hosts:
            raise CertificateError("single certificate target is not a managed hostname")
    if scope == "wildcard" and managed_zones is not None:
        zones = {normalize_zone(zone) for zone in managed_zones}
        if target not in zones:
            raise CertificateError("wildcard certificate target is not a managed zone")
    cert = copy.deepcopy(dict(metadata or {}))
    cert.update({
        "id": certificate_id(scope, target),
        "scope": scope,
        "target": target,
        "domains": domains_for(scope, target),
    })
    cert.pop("download_token", None)
    return cert


def token_digest(token: str) -> str:
    if not isinstance(token, str) or not token:
        raise CertificateError("certificate token must not be empty")
    return hashlib.sha256(("ddns-panel:certificate-token:v1\0" + token).encode()).hexdigest()


def rotate_download_token(cert: MutableMapping[str, Any]) -> str:
    validate_certificate(cert)
    token = secrets.token_urlsafe(32)
    cert["download_token_hash"] = token_digest(token)
    cert["download_token_version"] = int(cert.get("download_token_version", 0)) + 1
    cert.pop("download_token", None)
    return token


def revoke_download_token(cert: MutableMapping[str, Any]) -> None:
    validate_certificate(cert)
    cert.pop("download_token", None)
    cert.pop("download_token_hash", None)
    cert["download_token_version"] = int(cert.get("download_token_version", 0)) + 1


def token_authorizes(cert: Mapping[str, Any], token: str) -> bool:
    try:
        validate_certificate(cert)
        candidate = token_digest(token)
    except CertificateError:
        return False
    expected = cert.get("download_token_hash")
    if isinstance(expected, str) and len(expected) == 64:
        return hmac.compare_digest(candidate, expected)
    # Read compatibility for data that has not yet passed through migration.
    legacy = cert.get("download_token")
    return isinstance(legacy, str) and bool(legacy) and hmac.compare_digest(token, legacy)


def authenticate_certificate(certs: Mapping[str, Mapping[str, Any]], token: str) -> dict[str, Any] | None:
    if not token:
        return None
    matches = [cert for cert in certs.values() if token_authorizes(cert, token)]
    return dict(matches[0]) if len(matches) == 1 else None


def validate_certificate(cert: Mapping[str, Any]) -> None:
    if not isinstance(cert, Mapping):
        raise CertificateError("certificate must be an object")
    scope, target = normalize_scope(cert.get("scope"), cert.get("target"))
    expected_id = certificate_id(scope, target)
    if cert.get("id") != expected_id or not _CERT_ID.fullmatch(expected_id):
        raise CertificateError("certificate id does not match its scope")
    if cert.get("domains") != domains_for(scope, target):
        raise CertificateError("certificate domains do not match its scope")


def _safe_child(root: str | os.PathLike[str], cert_id: str) -> Path:
    if not isinstance(cert_id, str) or not _CERT_ID.fullmatch(cert_id):
        raise CertificateError("invalid certificate id")
    root_path = Path(root).resolve(strict=False)
    child = (root_path / cert_id).resolve(strict=False)
    if child.parent != root_path:
        raise CertificateError("certificate path escapes its root")
    return child


def certificate_paths(cert: Mapping[str, Any], cert_root: str | os.PathLike[str]) -> dict[str, str]:
    validate_certificate(cert)
    directory = _safe_child(cert_root, cert["id"])
    return {
        "directory": str(directory),
        "fullchain": str(directory / "fullchain.pem"),
        "key": str(directory / "key.pem"),
    }


def acme_state_path(cert: Mapping[str, Any], acme_root: str | os.PathLike[str]) -> str:
    validate_certificate(cert)
    return str(_safe_child(acme_root, cert["id"]))


def migrate_legacy_certificate_files(
    cert: Mapping[str, Any], cert_root: str | os.PathLike[str]
) -> bool:
    """Move an old ``CERT_ROOT/<zone>`` wildcard directory to its ID path.

    Existing ID-based output always wins. If both directories exist, neither is
    modified so an operator can compare them instead of losing certificate data.
    """
    validate_certificate(cert)
    if cert["scope"] != "wildcard":
        return False
    root = Path(cert_root).resolve(strict=False)
    legacy = (root / cert["target"]).resolve(strict=False)
    if legacy.parent != root:
        raise CertificateError("legacy certificate path escapes its root")
    destination = _safe_child(root, cert["id"])
    if not legacy.exists() or destination.exists():
        return False
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(legacy), str(destination))
    return True


def acme_issue_args(cert: Mapping[str, Any]) -> list[str]:
    validate_certificate(cert)
    args = ["--issue", "--dns", "dns_cf"]
    for domain in cert["domains"]:
        args.extend(("-d", domain))
    args.extend(("--server", "letsencrypt", "--keylength", "2048"))
    return args


def acme_install_args(cert: Mapping[str, Any], cert_root: str | os.PathLike[str]) -> list[str]:
    paths = certificate_paths(cert, cert_root)
    primary = cert["target"] if cert["scope"] == "single" else f"*.{cert['target']}"
    return [
        "--install-cert", "-d", primary,
        "--fullchain-file", paths["fullchain"],
        "--key-file", paths["key"],
        "--reloadcmd", "true",
    ]


def migrate_certificate_data(data: MutableMapping[str, Any]) -> bool:
    """Migrate legacy ``certs: {zone: metadata}`` in place, idempotently."""
    certs = data.get("certs")
    if certs is None:
        data["certs"] = {}
        data["certificate_schema_version"] = CERTIFICATE_SCHEMA_VERSION
        return True
    if not isinstance(certs, Mapping):
        raise CertificateError("certs must be an object")

    migrated: dict[str, dict[str, Any]] = {}
    changed = data.get("certificate_schema_version") != CERTIFICATE_SCHEMA_VERSION
    for key, raw in certs.items():
        if not isinstance(raw, Mapping):
            raise CertificateError("certificate metadata must be an object")
        if raw.get("scope") in VALID_SCOPES and raw.get("target"):
            cert = new_certificate(raw["scope"], raw["target"], metadata=raw)
        else:
            # Legacy keys are zone names and always represented wildcard certificates.
            cert = new_certificate("wildcard", key, metadata=raw)
        legacy_token = raw.get("download_token")
        if isinstance(legacy_token, str) and legacy_token:
            cert["download_token_hash"] = token_digest(legacy_token)
            cert.setdefault("download_token_version", 1)
        cert.pop("download_token", None)
        validate_certificate(cert)
        if cert["id"] in migrated and migrated[cert["id"]] != cert:
            raise CertificateError("duplicate certificate scope")
        migrated[cert["id"]] = cert
        if key != cert["id"] or dict(raw) != cert:
            changed = True
    if changed:
        data["certs"] = migrated
        data["certificate_schema_version"] = CERTIFICATE_SCHEMA_VERSION
    return changed

# Phase 2 Plan: Native Clients, Certificate Modes, Multi-Record DNS

## Goals

1. Provide a no-Docker interactive installer for DDNS updates and certificate synchronization.
2. Support both single-host certificates and zone wildcard certificates with least-privilege download credentials.
3. Support multiple independently updated DNS records for one hostname, including multiple IPv4 records and IPv6.

## Shared Architecture

### DNS record slots

Each managed hostname owns one or more record slots. A slot contains:

- stable slot ID;
- record type (`A` or `AAAA`);
- operator label, such as `Hong Kong IPv4`, `US IPv4`, or `Home IPv6`;
- independent update credential;
- Cloudflare DNS record ID once bound or created;
- last reported address and update time;
- proxy and TTL policy.

An update credential authorizes exactly one slot. It cannot update another slot, download certificates, or select an arbitrary record ID.

Existing host objects are migrated to a default IPv4 slot without changing their current update credential. If Cloudflare returns multiple matching records and the legacy slot has no stored record ID, the update must fail with an explicit conflict instead of selecting the first record.

### Certificate objects

Certificates become independent objects with a stable ID and one of two scopes:

- `single`: exactly one managed hostname;
- `wildcard`: zone apex plus `*.zone`.

Each certificate object has an independent rotatable download credential. A single-host credential cannot download a wildcard certificate, and a DNS update credential cannot download any certificate.

Certificate files and ACME state use certificate IDs or safely encoded scopes, avoiding path traversal and scope collisions.

### Native client installer

The installer must work with Bash, curl, and standard system tools. Docker is optional. It supports:

- DDNS one-shot update;
- cron installation;
- systemd service and timer installation;
- certificate one-shot synchronization;
- certificate cron or systemd synchronization;
- custom reload command;
- status, diagnostics, reconfiguration, and uninstall;
- secret files with mode `0600` and Authorization headers instead of URL credentials.

## Compatibility

- Existing DynDNS2 clients continue using hostname as username and the migrated default slot key as password.
- Existing `/api/update` header authentication continues to work for migrated default slots.
- Query-string credentials remain disabled by default.
- Existing wildcard certificate metadata is migrated in place to a wildcard certificate object.
- No migration may silently rotate credentials or delete Cloudflare records.

## UI Requirements

- Host details show record slots separately with type, label, current address, state, and independent Connect action.
- Operators can add, edit, rotate, bind, and delete slots.
- Adding a slot requires an explicit `A` or `AAAA` type.
- A duplicate record type is allowed because multiple IPv4 or IPv6 records may coexist.
- Certificate creation requires choosing Single Host or Wildcard and clearly describes the security scope.
- Wildcard mode displays a larger-impact warning.
- Client setup commands use the selected slot or certificate credential and never expose secrets until explicitly revealed.

## API Requirements

- Slot update responses identify the slot and record type.
- IPv4 is accepted only by `A` slots; IPv6 only by `AAAA` slots.
- Cloudflare updates use stored record IDs. Ambiguous unbound records return a conflict requiring administrator action.
- Slot administration and certificate administration require login and CSRF protection.
- Certificate download requests use Bearer credentials scoped to one certificate object.

## Verification

- Migrate a copy of current production data and preserve every hostname and update key.
- Test one hostname with two independent `A` slots.
- Test one hostname with one `A` and one `AAAA` slot.
- Test ambiguous legacy Cloudflare records fail safely.
- Test single-host and wildcard certificate issue, rotation, revocation, and download isolation.
- Test installer one-shot, cron rendering, systemd rendering, status, and uninstall in temporary directories.
- Re-run existing authentication, CSRF, privacy, UI, container, and deployment checks.

## Deployment

1. Back up source, data, certificate files, proxy configuration, and the running image.
2. Run an offline migration against a copied `data.json` and inspect the result.
3. Build and smoke-test the new image without replacing production.
4. Deploy with rollback image retained.
5. Verify all migrated legacy DDNS credentials still authenticate.
6. Exercise new A, AAAA, single-certificate, wildcard-certificate, and native-client flows.
7. Push a feature branch, open a PR, and merge only after production verification.

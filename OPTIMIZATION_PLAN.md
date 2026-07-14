# DDNS Panel Optimization Plan

## Objectives

- Preserve the existing DynDNS2 and JSON update workflows.
- Make host creation use a managed-zone selector plus a host/subdomain input.
- Switch language and light/dark theme immediately without reloading.
- Separate DNS update credentials from certificate download credentials.
- Prevent credentials, private keys, and provider errors from leaking through URLs, logs, UI, or caches.
- Add repeatable tests, backups, deployment checks, rollback steps, and GitHub synchronization.

## Workstreams

### 1. Backend security

- Add CSRF protection to all state-changing panel operations.
- Add bounded login throttling and security-event logging without passwords or tokens.
- Validate redirect targets, hostnames, zones, TTL values, IP addresses, and identifiers.
- Set secure session cookie policy and security/cache headers.
- Replace query-string certificate credentials with a dedicated certificate credential accepted through an authorization header.
- Keep DNS update keys limited to DNS updates only.
- Avoid returning raw Cloudflare errors or secrets to clients.
- Add focused automated tests for authentication, authorization, validation, and compatibility.

### 2. Frontend interaction

- Change Add Host to `managed zone + host prefix`, with a live FQDN preview.
- Implement in-page English/Chinese translation without navigation or reload.
- Implement in-page light/dark theme switching and persist the preference locally.
- Mask update keys, certificate credentials, and Cloudflare token identifiers by default.
- Require an explicit, short-lived reveal action before copying sensitive values.
- Add CSRF fields to forms and CSRF headers to JavaScript requests.
- Verify desktop and mobile layout, empty states, errors, and long domain names.

### 3. Runtime and operations

- Upgrade and pin Python dependencies.
- Add container health checks and conservative runtime limits.
- Document the minimum filesystem permissions required by ACME and persisted data.
- Disable or redact sensitive request logging for credential-bearing endpoints.
- Add reverse-proxy security headers, request limits, login rate limits, and trusted proxy handling.
- Document backup, restore, secret rotation, deployment, smoke-test, and rollback procedures.

## Migration

1. Back up `/root/ddns-api`, container metadata, Nginx Proxy Manager host configuration, and current image ID.
2. Build and test a new image without replacing the running container.
3. Migrate existing host records by generating independent certificate credentials.
4. Rotate credentials previously used in certificate query URLs.
5. Deploy through Docker Compose and retain the prior image and source directory for rollback.
6. Validate login, host management, DynDNS2 update, JSON update, certificate retrieval, language/theme switching, and renewal jobs.
7. Inspect application, proxy, and Cloudflare-facing responses for secret leakage.

## Acceptance Criteria

- Existing DDNS clients continue updating records successfully.
- A DNS update key cannot download a certificate or private key.
- Certificate credentials are never required in a URL query string.
- No state-changing panel endpoint succeeds without a valid CSRF token.
- Login attempts are rate limited and logged without sensitive values.
- Language and theme change immediately and survive navigation/reload.
- A new host is created from a selected managed zone and validated host prefix.
- Secrets are masked by default in rendered HTML and are not cached.
- Automated tests pass and public `/health` remains operational.
- Deployment has a verified backup and a tested rollback command.
- The final reviewed commit is pushed to the intended GitHub repository.

## GitHub Synchronization Gate

GitHub synchronization requires a valid authenticated account and a confirmed destination repository. The local `gh` credential is currently invalid, so implementation and server deployment can proceed, but the push must wait until authentication is refreshed or an existing SSH-accessible repository is identified.

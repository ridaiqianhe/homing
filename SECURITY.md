# Security operations

## Secrets

- Keep `.env`, `data/data.json`, `data/acme/` and `data/certs/` out of Git and backups with broad access.
- Use a dedicated Cloudflare API token per zone with only `Zone:DNS:Edit` and `Zone:Zone:Read` for the required zone.
- Generate `SECRET_KEY` with `openssl rand -hex 32` and an unrelated password-manager generated admin password.
- Certificate clients must send keys in `Authorization: Bearer ...`; never place keys in URLs.
- Treat any key previously used in a query string as exposed. Rotate it after deploying header authentication, then purge or restrict old proxy/CDN logs according to retention policy.

## Edge controls

Use Cloudflare Full (strict), enable HSTS only after confirming every subdomain supports HTTPS, and rate-limit `/login`, update endpoints, and certificate downloads. `deploy/nginx-security.conf` contains origin examples. At Cloudflare, add managed WAF rules and rate limits equivalent to 5 login attempts/minute/IP and 30 API requests/minute/IP, with an allowance for known updater addresses when practical.

Do not log query strings on sensitive routes. During the compatibility window, configure the proxy access log to omit `$args` for `/cert`, `/cert/key`, and `/cert/fullchain`. Disable legacy query authentication after all clients are migrated.

## Rotation order

1. Back up current state, deploy support for header authentication, and update all clients.
2. Rotate every host/certificate download key and verify the old keys fail.
3. Rotate `ADMIN_PASS`, invalidate sessions by rotating `SECRET_KEY`, then re-login.
4. Create replacement scoped Cloudflare tokens, verify each zone, and revoke the old tokens.
5. Reissue wildcard certificates if their private keys may have been downloaded by an unauthorized party. Deploy the new certificates before revoking or deleting old files.

# Homing / DDNS Panel

Self-hosted Cloudflare DDNS and wildcard certificate panel.

## Hardened deployment

Requirements: Docker Engine with Compose v2, a TLS reverse proxy, and a Cloudflare token scoped to the required zone.

```sh
cp .env.example .env
openssl rand -hex 32
mkdir -p data
sudo chown -R 10001:10001 data
sudo chmod 750 data
docker compose build --pull
docker compose up -d
docker compose ps
curl -fsS http://127.0.0.1:8787/health
```

Put the generated secret and strong credentials in `.env`; do not commit it. The container runs as UID/GID 10001 with all Linux capabilities removed, a read-only root filesystem, bounded resources, a local-only published port, health checks, and rotated container logs. Only `/app/data` and a small in-memory `/tmp` are writable.

The application still references `/root/.acme.sh/acme.sh`; the image exposes the pinned, read-only acme.sh installation there while the process remains non-root. acme.sh state and issued certificates remain under `/app/data`.

## No-loss migration

1. Record the current image ID and Compose file: `docker inspect ddns-api --format '{{.Image}}'` and `docker compose config > /root/ddns-compose-before.yml`.
2. Stop writes briefly: `docker compose stop`. Do not remove the container or volumes.
3. Back up state preserving modes: `sudo tar --xattrs --acls -C . -czf /root/ddns-data-$(date +%F-%H%M%S).tgz data .env`.
4. Verify the archive with `tar -tzf /root/ddns-data-*.tgz`, then copy it to encrypted off-host storage.
5. Change ownership for the non-root runtime: `sudo chown -R 10001:10001 data`; keep directories at 750, JSON/secrets/private keys at 600, and public certificate chains at 644.
6. Build with a unique immutable tag, for example `IMAGE_TAG=2026-07-14 docker compose build --pull`, then start and verify health, login, DNS update, certificate listing, and one header-authenticated certificate download.
7. Keep the backup and previous image until at least one successful certificate renewal.

## Rollback

Stop the new container, restore the saved Compose configuration or set `IMAGE_TAG` to the recorded prior image, and restore the data archive only if the new version changed persistent data. Run `sudo chown -R 10001:10001 data` when returning to this hardened image. Start the service, check `/health`, then test login and a non-destructive DNS update.

## Reverse proxy and Cloudflare

The origin must remain bound to `127.0.0.1:8787`. Apply the headers and rate-limit guidance in `deploy/nginx-security.conf` and `SECURITY.md`. Cloudflare SSL mode should be Full (strict). Never expose the application container directly to the Internet.

## Certificate client

`get-cert.sh` retrieves certificates with `Authorization: Bearer` so the key is absent from URLs and access logs:

```sh
CERT_KEY='rotated-client-key' CERT_API='https://ddns.example.com' \
  CERT_DIR='/etc/ssl/mycerts' RELOAD_CMD='systemctl reload nginx' ./get-cert.sh
```

Protect the script's environment and service definition. Do not put `CERT_KEY` directly in a cron command; load it from a root-owned `0600` environment file.

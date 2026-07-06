# 🕊️ Homing

**Self-hosted dynamic DNS + wildcard TLS hub, backed by Cloudflare.**

Homing keeps your machines reachable by a stable name even as their IPs change, and it hands each of them a fresh wildcard certificate — all from one small, self-hosted control panel. Your Cloudflare API token lives only on the server; every client holds nothing but a scoped, revocable key.

> Like a homing pigeon that carries each machine's current IP (and its certificate) back home.

---

## Why

Most Cloudflare DDNS tools put your **API token on every client**. If one box is compromised, your whole DNS is exposed. Homing inverts that:

- The **token stays on the hub** (one trusted server).
- Each machine gets a **per-host key** that can only update **its own subdomain**.
- The hub also issues and renews a **`*.yourdomain` wildcard cert** and lets each machine pull it with the same key.

Speaks the standard **dyndns2** protocol, so routers, NAS boxes, `ddclient`, `inadyn`, and plain `curl` all work as clients with zero custom software.

---

## Features

- 🔐 **Login-protected web panel** — manage everything from the browser
- 🗝️ **Per-host keys** — a leaked key can only touch its own subdomain; rotate it in one click
- ☁️ **Cloudflare tokens managed in-panel** — add multiple tokens for multiple domains; auto-detects which zones each token covers
- 🔄 **dyndns2 compatible** — works with ddclient / inadyn / OpenWrt / Synology / curl out of the box
- 📜 **Wildcard TLS, automated** — issue `*.yourdomain` via Let's Encrypt DNS-01, auto-renewed
- 📥 **Cert distribution** — each machine pulls its cert with a one-line script; drops `fullchain.pem` + `key.pem` and reloads your service
- 🖥️ **Live terminal view** — watch `acme.sh` output stream in real time while a cert is issued
- ✅ **Validity checks** — verify a token or test what a host currently resolves to, inline
- 🎯 **Correct client IP behind Cloudflare** — reads `CF-Connecting-IP`, never leaks the edge IP into a record
- 🐳 **All Docker** — one `docker compose up`

---

## How it works

```
┌── your machines (clients) ──┐         ┌── Homing hub (trusted) ─────────────┐
│  dyndns2 check-in  ─────────┼── HTTPS ┼─►  web panel + API                  │
│  (curl / ddclient / router) │         │     ├─ per-host key auth            │
│                             │         │     ├─ reads real IP (CF-Connecting)│
│  cert-sync (pull cert)  ────┼── HTTPS ┼─►    ├─ updates Cloudflare DNS       │
└─────────────────────────────┘         │     └─ issues/renews *.wildcard     │
        holds only its KEY              │   Cloudflare API token lives ONLY   │
                                        │   here (never leaves the hub)       │
                                        └─────────────────────────────────────┘
```

---

## Quick start

```bash
git clone https://github.com/<you>/homing.git
cd homing
cp .env.example .env
#   edit .env: set ADMIN_PASS and a long SECRET_KEY
docker compose up -d --build
```

The panel now listens on `127.0.0.1:8787`. Put it behind your reverse proxy (Nginx / Caddy / NPM) with TLS and a hostname, e.g. `ddns.example.com`.

> **Behind Cloudflare (orange cloud)?** Good — Homing reads `CF-Connecting-IP` to get each client's real address. Just make sure your reverse proxy forwards request headers (Nginx does by default).

Then open the panel, log in, and:

1. **Add a Cloudflare token** — it auto-detects the domains it can manage.
2. **Add a host** — e.g. `nas.example.com`; a key is generated.
3. Click **接入 / Connect** on the host to copy a ready-made client command.
4. (Optional) **Issue a wildcard cert** for the domain and copy the cert-pull command.

---

## Configuration (`.env`)

| Variable | Required | Description |
|----------|----------|-------------|
| `ADMIN_USER` | yes | Panel login user |
| `ADMIN_PASS` | yes | Panel login password |
| `SECRET_KEY` | recommended | Flask session key; set a long random string so sessions survive restarts |
| `SITE_NAME` | no | Brand shown in the panel (default `Homing`) |
| `CF_ZONE_NAME` | no | Optional default zone; leave empty to infer from hostnames |

Cloudflare **API tokens are added in the panel**, not in `.env`.

### Creating a Cloudflare token

Cloudflare Dashboard → **My Profile → API Tokens → Create Token** → template **Edit zone DNS** → under *Zone Resources* pick the domain(s) you want Homing to manage → create and paste it into the panel. The template's `Zone:Read + DNS:Edit` scope is exactly what both DDNS updates and DNS-01 cert issuance need.

---

## Client setup

Every host's **Connect** dialog generates these with the host's own key filled in.

### DDNS (dyndns2)

Plain curl, run on a timer:

```bash
curl -4 -u nas.example.com:YOUR_KEY https://ddns.example.com/nic/update
```

Or a self-contained Docker loop (no software to install):

```bash
docker run -d --name ddns-nas --restart=always \
  curlimages/curl sh -c \
  'while true; do curl -4su nas.example.com:YOUR_KEY \
    https://ddns.example.com/nic/update; sleep 300; done'
```

`ddclient`, `inadyn`, OpenWrt, Synology, Merlin, etc.: choose a **custom / dyndns2** provider, server `ddns.example.com`, username = hostname, password = key.

### Pull the wildcard cert

```bash
docker run -d --name cert-sync --restart=always \
  -v /etc/ssl/homing:/certs \
  -e CERT_KEY=YOUR_KEY -e CERT_API=https://ddns.example.com -e CERT_DIR=/certs \
  curlimages/curl sh -c \
  'while true; do curl -4fsSL $CERT_API/get-cert.sh | sh; sleep 43200; done'
```

Writes `fullchain.pem` + `key.pem` into the directory and runs `RELOAD_CMD` (e.g. `nginx -s reload`) whenever the cert changes.

---

## Security model

- **Token isolation** — the Cloudflare token never leaves the hub. Clients only ever send their host key.
- **Least privilege per client** — a host key can update exactly one subdomain and pull the wildcard cert for its zone. Nothing else.
- **Revocation** — rotate or delete a key in the panel; that client is cut off, others untouched.
- **Wildcard trade-off** — a wildcard cert is valid for every subdomain of its zone, so any client that can pull it holds a zone-wide cert. That's inherent to wildcards; use per-host certs instead if that isn't acceptable for you.
- Keep the panel behind TLS. `data/` (keys, tokens, certs) is written `chmod 600` and must never be committed — it's already in `.gitignore`.

---

## API reference

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `GET /nic/update` | Basic `hostname:key` | dyndns2 update (`good`/`nochg`/`badauth`/`nohost`) |
| `GET /api/update?key=&ip=` | key | JSON update, optional explicit IP |
| `GET /cert/fullchain?key=` | key | Download wildcard fullchain |
| `GET /cert/key?key=` | key | Download wildcard private key |
| `GET /get-cert.sh` | — | The client pull script |
| `GET /ip` | — | What IP the server sees you as (debug) |
| `GET /health` | — | Liveness |

Panel routes (`/`, `/tokens`, `/hosts`, `/certs/...`) require the login session.

---

## Tech

Python + Flask (stdlib-only Cloudflare client), [`acme.sh`](https://github.com/acmesh-official/acme.sh) for DNS-01, served by `waitress`. No database — state is a single JSON file under `data/`.

## License

MIT — see [LICENSE](LICENSE).

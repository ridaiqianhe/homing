# Native client (no Docker)

Requirements: Bash 4+, curl, and root access for installation. `openssl` is not required. The client works with cron and with systemd timers; use cron on OpenWrt, NAS appliances, containers, and other systems without systemd.

```sh
sudo ./client/install.sh
```

The menu can configure or reconfigure credentials, run DDNS or certificate synchronization immediately, install cron or systemd schedules, show status and diagnostics, and uninstall. Select IP family `4` for an A slot, `6` for an AAAA slot, or `auto` to let the operating system choose. Non-interactive commands are also available:

```sh
sudo ./client/install.sh configure
sudo INTERVAL_MINUTES=10 ./client/install.sh cron
sudo DDNS_INTERVAL=10min CERT_INTERVAL=12h ./client/install.sh systemd
sudo ./client/install.sh run ddns
sudo ./client/install.sh run cert
sudo ./client/install.sh diagnose
sudo ./client/install.sh uninstall
sudo PURGE_CONFIG=1 ./client/install.sh uninstall
```

Secrets are stored in `/etc/ddns-panel/client.env` with mode `0600`. Cron and systemd contain only the config path and script path. DDNS uses `X-Api-Key`; certificate downloads use `Authorization: Bearer`. Secrets never appear in URLs, cron entries, or process arguments.

Set a custom panel endpoint, schedule, certificate directory, and certificate-change reload command during configuration. For scripted provisioning, export `DDNS_ENDPOINT`, `DDNS_API_KEY`, `DDNS_IP_FAMILY`, `CERT_ENDPOINT`, `CERT_TOKEN`, `CERT_DIR`, and `RELOAD_CMD` before running `configure`.

The installer also supports direct bootstrap without Docker or a repository checkout:

```sh
curl -fsSL https://ddns.227755.xyz/client/install.sh | sudo bash
```

If companion scripts are absent, the installer securely downloads them from `https://ddns.227755.xyz/client` or the HTTPS `DDNS_INSTALL_BASE` override, then validates their shell syntax before installation.

For packaging tests, `DDNS_CLIENT_ROOT=/tmp/root` redirects installed files under a temporary root. `DDNS_CLIENT_DRY_RUN=1` prints mutations without applying them.

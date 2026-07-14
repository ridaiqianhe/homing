#!/usr/bin/env bash
set -euo pipefail

ROOT="${DDNS_CLIENT_ROOT:-}"
PREFIX="${DDNS_CLIENT_PREFIX:-/usr/local}"
ETC="${DDNS_CLIENT_ETC:-/etc/ddns-panel}"
SYSTEMD="${DDNS_CLIENT_SYSTEMD:-/etc/systemd/system}"
CRON="${DDNS_CLIENT_CRON:-/etc/cron.d/ddns-panel-client}"
BIN_DIR="$ROOT$PREFIX/lib/ddns-panel"
ENV_FILE="$ROOT$ETC/client.env"
STATE_FILE="$ROOT$ETC/install.state"
SYSTEMD_DIR="$ROOT$SYSTEMD"
CRON_FILE="$ROOT$CRON"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRY_RUN="${DDNS_CLIENT_DRY_RUN:-0}"

say() { printf '%s\n' "$*"; }
run() { if [ "$DRY_RUN" = 1 ]; then printf '[dry-run]'; printf ' %q' "$@"; printf '\n'; else "$@"; fi; }
need_root() { [ -n "$ROOT" ] || [ "$(id -u)" = 0 ] || { say 'Run as root (or set DDNS_CLIENT_ROOT for testing).'; exit 1; }; }
have_systemd() { [ -n "$ROOT" ] || { command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; }; }
service_user() { if [ -n "$ROOT" ]; then printf root; else printf root; fi; }
shell_quote() { printf "'%s'" "${1//\'/\'\\\'\'}"; }

read_value() {
  local var="$1" prompt="$2" default="${3:-}" secret="${4:-0}" value
  if [ -n "${!var:-}" ]; then return; fi
  if [ "$secret" = 1 ]; then read -r -s -p "$prompt: " value; printf '\n'; else read -r -p "$prompt${default:+ [$default]}: " value; fi
  printf -v "$var" '%s' "${value:-$default}"
}

write_config() {
  need_root
  read_value DDNS_ENDPOINT 'DDNS panel endpoint' 'https://ddns.227755.xyz'
  read_value DDNS_API_KEY 'DDNS API key (empty to disable DDNS)' '' 1
  read_value CERT_ENDPOINT 'Certificate endpoint' "$DDNS_ENDPOINT"
  read_value CERT_TOKEN 'Certificate token (empty to disable certificate sync)' '' 1
  read_value CERT_DIR 'Certificate destination' '/etc/ssl/ddns-panel'
  read_value RELOAD_CMD 'Reload command after certificate change' ''
  run install -d -m 700 "$ROOT$ETC"
  if [ "$DRY_RUN" = 1 ]; then say "[dry-run] write 0600 $ENV_FILE"; return; fi
  umask 077
  {
    printf 'DDNS_ENDPOINT=%s\n' "$(shell_quote "$DDNS_ENDPOINT")"
    printf 'DDNS_API_KEY=%s\n' "$(shell_quote "$DDNS_API_KEY")"
    printf 'CERT_ENDPOINT=%s\n' "$(shell_quote "$CERT_ENDPOINT")"
    printf 'CERT_TOKEN=%s\n' "$(shell_quote "$CERT_TOKEN")"
    printf 'CERT_DIR=%s\n' "$(shell_quote "$CERT_DIR")"
    printf 'RELOAD_CMD=%s\n' "$(shell_quote "$RELOAD_CMD")"
  } >"$ENV_FILE.tmp"
  chmod 600 "$ENV_FILE.tmp"; mv -f "$ENV_FILE.tmp" "$ENV_FILE"
}

install_files() {
  need_root
  run install -d -m 755 "$BIN_DIR"
  run install -m 755 "$SOURCE_DIR/ddns-update.sh" "$BIN_DIR/ddns-update.sh"
  run install -m 755 "$SOURCE_DIR/cert-sync.sh" "$BIN_DIR/cert-sync.sh"
}

write_cron() {
  local minutes="${INTERVAL_MINUTES:-5}"
  [[ "$minutes" =~ ^[0-9]+$ ]] && [ "$minutes" -ge 1 ] && [ "$minutes" -le 59 ] || { say 'Interval must be 1-59 minutes.'; exit 2; }
  need_root; install_files
  [ -r "$ENV_FILE" ] || write_config
  run install -d -m 755 "$(dirname "$CRON_FILE")"
  if [ "$DRY_RUN" = 1 ]; then say "[dry-run] write cron every $minutes minutes to $CRON_FILE"; return; fi
  {
    printf 'SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n'
    printf '*/%s * * * * %s DDNS_CLIENT_CONFIG=%s %s/ddns-update.sh >/dev/null 2>&1\n' "$minutes" "$(service_user)" "$ENV_FILE" "$BIN_DIR"
    printf '17 */6 * * * %s DDNS_CLIENT_CONFIG=%s %s/cert-sync.sh >/dev/null 2>&1\n' "$(service_user)" "$ENV_FILE" "$BIN_DIR"
  } >"$CRON_FILE"; chmod 644 "$CRON_FILE"
  printf 'scheduler=cron\n' >"$STATE_FILE"; chmod 600 "$STATE_FILE"
}

unit() {
  local name="$1" command="$2" interval="$3"
  cat >"$SYSTEMD_DIR/ddns-panel-$name.service" <<EOF
[Unit]
Description=DDNS Panel $name client
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Environment=DDNS_CLIENT_CONFIG=$ENV_FILE
ExecStart=$BIN_DIR/$command
EOF
  cat >"$SYSTEMD_DIR/ddns-panel-$name.timer" <<EOF
[Unit]
Description=Run DDNS Panel $name client periodically

[Timer]
OnBootSec=2min
OnUnitActiveSec=$interval
Persistent=true

[Install]
WantedBy=timers.target
EOF
}

write_systemd() {
  need_root; have_systemd || { say 'systemd is unavailable; use cron.'; exit 3; }
  install_files; [ -r "$ENV_FILE" ] || write_config
  run install -d -m 755 "$SYSTEMD_DIR"
  if [ "$DRY_RUN" = 1 ]; then say "[dry-run] write and enable DDNS/certificate systemd timers"; return; fi
  unit ddns ddns-update.sh "${DDNS_INTERVAL:-5min}"
  unit cert cert-sync.sh "${CERT_INTERVAL:-6h}"
  if [ -z "$ROOT" ]; then
    systemctl daemon-reload
    systemctl enable --now ddns-panel-ddns.timer ddns-panel-cert.timer
  fi
  printf 'scheduler=systemd\n' >"$STATE_FILE"; chmod 600 "$STATE_FILE"
}

one_shot() {
  local kind="${1:-both}" script
  install_files; [ -r "$ENV_FILE" ] || write_config
  for script in ddns cert; do
    [ "$kind" = both ] || [ "$kind" = "$script" ] || continue
    DDNS_CLIENT_CONFIG="$ENV_FILE" "$BIN_DIR/$([ "$script" = ddns ] && printf ddns-update || printf cert-sync).sh"
  done
}

status() {
  local config_state=MISSING ddns_state=MISSING cert_state=MISSING
  [ ! -r "$ENV_FILE" ] || config_state=OK
  [ ! -x "$BIN_DIR/ddns-update.sh" ] || ddns_state=OK
  [ ! -x "$BIN_DIR/cert-sync.sh" ] || cert_state=OK
  say "Config: $ENV_FILE $config_state"
  say "DDNS client: $BIN_DIR/ddns-update.sh $ddns_state"
  say "Certificate client: $BIN_DIR/cert-sync.sh $cert_state"
  [ -f "$CRON_FILE" ] && say "Scheduler: cron ($CRON_FILE)"
  [ -f "$SYSTEMD_DIR/ddns-panel-ddns.timer" ] && say 'Scheduler: systemd'
  return 0
}

diagnose() {
  status
  command -v bash >/dev/null || say 'ERROR: bash is missing'
  command -v curl >/dev/null || say 'ERROR: curl is missing'
  [ ! -e "$ENV_FILE" ] || { mode="$(stat -c %a "$ENV_FILE" 2>/dev/null || stat -f %Lp "$ENV_FILE")"; [ "$mode" = 600 ] || say "WARNING: config mode is $mode, expected 600"; }
  have_systemd || say 'INFO: systemd unavailable; cron is supported.'
}

uninstall_client() {
  need_root
  if have_systemd && [ -z "$ROOT" ]; then systemctl disable --now ddns-panel-ddns.timer ddns-panel-cert.timer 2>/dev/null || true; fi
  run rm -f "$SYSTEMD_DIR"/ddns-panel-{ddns,cert}.{service,timer} "$CRON_FILE"
  run rm -rf "$BIN_DIR"
  if [ "${PURGE_CONFIG:-0}" = 1 ]; then run rm -rf "$ROOT$ETC"; else run rm -f "$STATE_FILE"; say "Secrets retained at $ENV_FILE (set PURGE_CONFIG=1 to remove)."; fi
  if have_systemd && [ -z "$ROOT" ]; then systemctl daemon-reload; fi
}

menu() {
  while true; do
    printf '\n1) Configure/reconfigure\n2) Run DDNS now\n3) Sync certificate now\n4) Install cron\n5) Install systemd timers\n6) Status\n7) Diagnostics\n8) Uninstall\n0) Exit\n'
    read -r -p 'Select: ' choice
    case "$choice" in 1) write_config;; 2) one_shot ddns;; 3) one_shot cert;; 4) read_value INTERVAL_MINUTES 'DDNS interval in minutes' 5; write_cron;; 5) write_systemd;; 6) status;; 7) diagnose;; 8) uninstall_client;; 0) return;; *) say 'Invalid selection.';; esac
  done
}

case "${1:-menu}" in
  configure|reconfigure) write_config;; run) one_shot "${2:-both}";; cron) write_cron;; systemd) write_systemd;; status) status;; diagnose) diagnose;; uninstall) uninstall_client;; menu) menu;;
  *) say "Usage: $0 {menu|configure|run [ddns|cert|both]|cron|systemd|status|diagnose|uninstall}"; exit 2;;
esac

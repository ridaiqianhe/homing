#!/usr/bin/env bash
set -euo pipefail

CONFIG="${DDNS_CLIENT_CONFIG:-/etc/ddns-panel/client.env}"
[ -r "$CONFIG" ] || { echo "[cert] config not readable: $CONFIG" >&2; exit 1; }
# shellcheck disable=SC1090
. "$CONFIG"

: "${CERT_ENDPOINT:?CERT_ENDPOINT is required}"
: "${CERT_TOKEN:?CERT_TOKEN is required}"
[[ "$CERT_TOKEN" != *$'\n'* && "$CERT_TOKEN" != *$'\r'* && "$CERT_TOKEN" != *'"'* && "$CERT_TOKEN" != *'\\'* ]] || {
  echo '[cert] token contains unsupported characters' >&2; exit 1;
}
CERT_DIR="${CERT_DIR:-/etc/ssl/ddns-panel}"

mkdir -p "$CERT_DIR"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl_args=(--fail --silent --show-error --connect-timeout "${CONNECT_TIMEOUT:-10}" --max-time "${MAX_TIME:-30}")
[ "${ALLOW_HTTP:-0}" = 1 ] || curl_args+=(--proto '=https' --tlsv1.2)
base="${CERT_ENDPOINT%/}"
printf 'header = "Authorization: Bearer %s"\n' "$CERT_TOKEN" | curl --config - "${curl_args[@]}" "$base/cert/fullchain" -o "$tmp/fullchain.pem"
printf 'header = "Authorization: Bearer %s"\n' "$CERT_TOKEN" | curl --config - "${curl_args[@]}" "$base/cert/key" -o "$tmp/key.pem"

grep -q 'BEGIN CERTIFICATE' "$tmp/fullchain.pem" || { echo '[cert] invalid certificate response' >&2; exit 1; }
grep -Eq 'BEGIN ([A-Z ]+)?PRIVATE KEY' "$tmp/key.pem" || { echo '[cert] invalid private key response' >&2; exit 1; }

changed=0
for name in fullchain.pem key.pem; do
  if ! cmp -s "$tmp/$name" "$CERT_DIR/$name" 2>/dev/null; then
    mode=600; [ "$name" = fullchain.pem ] && mode=644
    install -m "$mode" "$tmp/$name" "$CERT_DIR/$name.new"
    mv -f "$CERT_DIR/$name.new" "$CERT_DIR/$name"
    changed=1
  fi
done
chmod 644 "$CERT_DIR/fullchain.pem"
chmod 600 "$CERT_DIR/key.pem"

if [ "$changed" = 1 ]; then
  printf '[cert] %s certificate updated in %s\n' "$(date '+%F %T')" "$CERT_DIR"
  [ -z "${RELOAD_CMD:-}" ] || /bin/sh -c "$RELOAD_CMD"
else
  printf '[cert] %s certificate unchanged\n' "$(date '+%F %T')"
fi

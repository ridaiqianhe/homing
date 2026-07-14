#!/usr/bin/env bash
set -euo pipefail

CONFIG="${DDNS_CLIENT_CONFIG:-/etc/ddns-panel/client.env}"
[ -r "$CONFIG" ] || { echo "[ddns] config not readable: $CONFIG" >&2; exit 1; }
# shellcheck disable=SC1090
. "$CONFIG"

: "${DDNS_ENDPOINT:?DDNS_ENDPOINT is required}"
: "${DDNS_API_KEY:?DDNS_API_KEY is required}"
[[ "$DDNS_API_KEY" != *$'\n'* && "$DDNS_API_KEY" != *$'\r'* && "$DDNS_API_KEY" != *'"'* && "$DDNS_API_KEY" != *'\\'* ]] || {
  echo '[ddns] API key contains unsupported characters' >&2; exit 1;
}

endpoint="${DDNS_ENDPOINT%/}/api/update"
curl_args=(--fail --silent --show-error --connect-timeout "${CONNECT_TIMEOUT:-10}" --max-time "${MAX_TIME:-30}")
[ "${ALLOW_HTTP:-0}" = 1 ] || curl_args+=(--proto '=https' --tlsv1.2)

# With no explicit address the panel derives it from the request source.
if [ -n "${DDNS_IP:-}" ]; then
  curl_args+=(--get --data-urlencode "ip=${DDNS_IP}")
fi

# Feed the header through stdin so the secret is absent from argv and process listings.
response="$(printf 'header = "X-Api-Key: %s"\n' "$DDNS_API_KEY" | curl --config - "${curl_args[@]}" "$endpoint")"
printf '[ddns] %s %s\n' "$(date '+%F %T')" "$response"

"""Build per-certificate client setup commands without putting secrets in argv."""

import shlex
from urllib.parse import urlsplit

from certificates import CertificateError, validate_certificate


def pull_commands(cert, token, endpoint, directory, reload_command=""):
    validate_certificate(cert)
    parsed = urlsplit(endpoint)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise CertificateError("certificate endpoint must be HTTPS")
    if not directory.startswith("/") or len(directory) > 400:
        raise CertificateError("certificate directory must be an absolute path")
    if len(reload_command) > 1000 or any(ord(c) < 32 for c in directory + reload_command):
        raise CertificateError("invalid certificate directory or reload command")
    quote = shlex.quote
    profile = "/etc/ddns-panel/certificates/" + cert["id"]
    config = profile + "/client.env"
    script = profile + "/cert-sync.sh"
    cron_file = "/etc/cron.d/ddns-panel-" + cert["id"]
    values = {"CERT_ENDPOINT": endpoint.rstrip("/"), "CERT_ID": cert["id"],
              "CERT_HOSTNAME": cert["target"], "CERT_TOKEN": token,
              "CERT_DIR": directory, "RELOAD_CMD": reload_command}
    setup = [
        "(", "set -eu", "umask 077",
        '[ "$(id -u)" -eq 0 ] || { echo "Run this command as root." >&2; exit 1; }',
        "for tool in bash curl openssl install; do command -v \"$tool\" >/dev/null; done",
        "install -d -m 700 " + quote(profile),
        "install -m 600 /dev/stdin " + quote(config) + " <<'DDNS_CERT_CONFIG'",
        *[key + "=" + quote(value) for key, value in values.items()],
        "DDNS_CERT_CONFIG",
        "client_tmp=$(mktemp " + quote(profile + "/.client.XXXXXX") + ")",
        "trap 'rm -f \"$client_tmp\"' EXIT",
        "curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 60 "
        + quote(endpoint.rstrip("/") + "/client/cert-sync.sh") + ' -o "$client_tmp"',
        'bash -n "$client_tmp"',
        'install -m 700 "$client_tmp" ' + quote(script),
    ]
    run = "DDNS_CLIENT_CONFIG=" + quote(config) + " /bin/bash " + quote(script)
    cron = [
        "install -d -m 755 /etc/cron.d",
        "install -m 644 /dev/stdin " + quote(cron_file) + " <<'DDNS_CERT_CRON'",
        "SHELL=/bin/sh", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "17 */6 * * * root " + run,
        "DDNS_CERT_CRON",
    ]
    cron_check = 'command -v crontab >/dev/null || { echo "Install and enable cron first." >&2; exit 1; }'
    return {"once": "\n".join(setup + [run, ")"]),
            "cron": "\n".join(setup[:3] + [cron_check] + setup[3:] + cron + [run, ")"])}

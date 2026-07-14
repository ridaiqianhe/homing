#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

bash -n get-cert.sh deploy/check.sh

grep -q '^Flask==3\.1\.3$' requirements.txt
grep -q '^waitress==3\.0\.2$' requirements.txt
grep -q '^USER app:app$' Dockerfile
grep -q 'read_only: true' docker-compose.yml
grep -q '127.0.0.1:8787:8787' docker-compose.yml

if command -v docker >/dev/null 2>&1; then
  docker compose config >/dev/null
  docker build --check .
else
  echo '[check] Docker CLI unavailable; skipped Compose rendering and image build checks' >&2
fi

echo '[check] deployment static checks passed'

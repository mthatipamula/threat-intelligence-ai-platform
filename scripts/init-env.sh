#!/usr/bin/env bash
# Creates .env with random secrets (never printed). On an existing .env, only adds keys that are missing.
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
gen() { openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c "$1"; }
if [[ ! -f .env ]]; then
  sed "s/^POSTGRES_PASSWORD=$/POSTGRES_PASSWORD=$(gen 24)/" .env.example > .env
  echo "Wrote .env. Add ABUSECH_AUTH_KEY and ANTHROPIC_API_KEY yourself if you have them."
fi
# Secrets for the optional MISP stack (docker compose --profile misp). MISP API keys are 40 characters.
added=0
for pair in MISP_ADMIN_KEY:40 MISP_ADMIN_PASSWORD:24 MISP_DB_PASSWORD:24 MISP_DB_ROOT_PASSWORD:24 MISP_REDIS_PASSWORD:24; do
  key=${pair%%:*}; len=${pair##*:}
  if ! grep -q "^$key=." .env; then
    sed -i '' "/^$key=/d" .env 2>/dev/null || sed -i "/^$key=/d" .env
    echo "$key=$(gen "$len")" >> .env
    added=$((added + 1))
  fi
done
[[ $added -gt 0 ]] && echo "Added $added MISP secret(s) to .env."
# Self-signed TLS certificate for the local MISP web server (misp-nginx expects cert.pem and key.pem).
if [[ ! -f data/misp-ssl/cert.pem ]]; then
  mkdir -p data/misp-ssl
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    -keyout data/misp-ssl/key.pem -out data/misp-ssl/cert.pem 2>/dev/null
  chmod 644 data/misp-ssl/cert.pem data/misp-ssl/key.pem  # nginx in the container runs as a non-root user
  echo "Created a self-signed certificate for the local MISP (data/misp-ssl)."
fi
exit 0

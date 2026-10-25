#!/usr/bin/env bash
# Creates .env with a random database password (never printed). Leaves an existing .env alone.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -f .env ]]; then echo ".env already exists; leaving it alone."; exit 0; fi
umask 077
pw=$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 24)
sed "s/^POSTGRES_PASSWORD=$/POSTGRES_PASSWORD=$pw/" .env.example > .env
echo "Wrote .env. Add ABUSECH_AUTH_KEY yourself if you have one."

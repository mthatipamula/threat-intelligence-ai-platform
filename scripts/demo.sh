#!/usr/bin/env bash
# One command for a demo: starts Postgres, prepares whatever is missing, builds the UI, and serves the console.
# Safe to rerun: each step is skipped when already done. Usage: ./scripts/demo.sh [port]   (default 8000)
set -euo pipefail
cd "$(dirname "$0")/.."
PORT="${1:-8000}"
step() { printf "\n\033[1m==> %s\033[0m\n" "$1"; }
json() { python3 -c "import json,sys; print(json.load(sys.stdin)['$1'])"; }

step "Docker"
docker info >/dev/null 2>&1 || { echo "Docker isn't running. Start Docker Desktop and rerun."; exit 1; }
[[ -f .env ]] || ./scripts/init-env.sh
docker compose up -d --wait >/dev/null
echo "Postgres is up."

step "Python dependencies"
./tip --help >/dev/null 2>&1 || { UV=$(command -v uv || echo "$HOME/.local/bin/uv"); "$UV" sync; }
./tip db init >/dev/null

state=$(./tip doctor --json)
step "Threat intelligence"
if [[ $(echo "$state" | json intel_objects) -lt 1000 ]]; then ./tip collect || echo "Some collectors failed (see above); continuing."; else echo "Already collected."; fi

step "Synthetic logs"
[[ $(echo "$state" | json logs) == "True" ]] && echo "Attack week present." || ./tip logs generate
[[ $(echo "$state" | json baseline) == "True" ]] && echo "Normal week present." || ./tip logs baseline

step "Report library"
if [[ $(echo "$state" | json library_chunks) -eq 0 ]]; then ./tip library build; else echo "Already built."; fi

step "Web console"
if [[ ! -f web/dist/index.html || -n "$(find web/src web/index.html -newer web/dist/index.html -print -quit)" ]]; then
  command -v npm >/dev/null || { echo "npm not found: install Node.js 20+ and rerun."; exit 1; }
  (cd web && { [[ -d node_modules ]] || npm install --silent; } && npm run build --silent)
else
  echo "Up to date."
fi

step "Ready"
./tip doctor
if lsof -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "Port $PORT is already in use (a previous ./tip serve?). Stop it, or run: ./scripts/demo.sh 8001"; exit 1
fi
echo
echo "Open http://localhost:$PORT   (screens: #/world  #/investigate  #/detections  #/briefs  #/trust)"
echo "Clear earlier runs first with: ./tip reset"
exec ./tip serve --port "$PORT"

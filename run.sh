#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Vulnify one-command launcher for Linux / macOS.
#   ./run.sh            set up everything and start backend + frontend
#   ./run.sh --sample   force offline sample data (no network needed)
# Mirrors run.bat so the project deploys the same everywhere.
# ---------------------------------------------------------------------------
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

SAMPLE_FLAG=""
[ "${1:-}" = "--sample" ] && SAMPLE_FLAG="--sample"

# --- pick a python ----------------------------------------------------------
PY=""
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
done
[ -z "$PY" ] && { echo "ERROR: Python 3 is required but was not found."; exit 1; }
command -v node >/dev/null 2>&1 || { echo "ERROR: Node.js is required but was not found."; exit 1; }
command -v npm  >/dev/null 2>&1 || { echo "ERROR: npm is required but was not found."; exit 1; }

echo "==> Setting up backend (Python venv + dependencies)…"
[ -d backend/.venv ] || "$PY" -m venv backend/.venv
# shellcheck disable=SC1091
source backend/.venv/bin/activate
python -m pip install -q --upgrade pip >/dev/null 2>&1 || true
python -m pip install -q -r backend/requirements.txt

echo "==> Ensuring vulnerability feeds are available…"
python scripts/ensure_data.py $SAMPLE_FLAG

if [ ! -d frontend/node_modules ]; then
  echo "==> Installing frontend dependencies (first run only)…"
  ( cd frontend && npm install )
fi

echo "==> Starting Vulnify…"
( cd backend && python app.py ) &
BACK_PID=$!
( cd frontend && npm run dev ) &
FRONT_PID=$!

cleanup() { kill "$BACK_PID" "$FRONT_PID" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

sleep 3
URL="http://localhost:5173"
if   command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL" >/dev/null 2>&1 || true
elif command -v open     >/dev/null 2>&1; then open "$URL"      >/dev/null 2>&1 || true
fi

cat <<EOF

  Vulnify is running.
    Frontend : $URL
    Backend  : http://127.0.0.1:5001

  Press Ctrl+C to stop both.
EOF

wait

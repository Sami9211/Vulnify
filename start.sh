#!/usr/bin/env bash
# Start backend + frontend for demo
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"

if [ ! -f "$ROOT/data/CVE-2025.json" ]; then
  echo "Data missing. Run: ./scripts/download_data.sh"
  exit 1
fi

cd "$ROOT/backend"
source .venv/bin/activate
python app.py &
BACK_PID=$!

cd "$ROOT/frontend"
npm run dev &
FRONT_PID=$!

echo ""
echo "Backend:  http://127.0.0.1:5001"
echo "Frontend: http://localhost:5173"
echo "Press Ctrl+C to stop"

trap "kill $BACK_PID $FRONT_PID 2>/dev/null" EXIT
wait

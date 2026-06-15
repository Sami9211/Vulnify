#!/usr/bin/env bash
# Download offline vulnerability feeds for Vulnify (Linux / macOS).
# Thin wrapper around the cross-platform Python downloader so there is a single
# source of truth and no curl/xz/gunzip dependency.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

PY=""
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
done
[ -z "$PY" ] && { echo "Python 3 is required."; exit 1; }

exec "$PY" "$ROOT/scripts/download_data.py" "$@"

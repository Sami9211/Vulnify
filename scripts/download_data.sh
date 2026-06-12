#!/usr/bin/env bash
# Download offline vulnerability feeds for Vulnify
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA="$ROOT/data"
mkdir -p "$DATA"

echo "==> Downloading CISA KEV catalogue..."
curl -fsSL -o "$DATA/known_exploited_vulnerabilities.json" \
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

echo "==> Downloading EPSS scores (latest)..."
DATE=$(date +%Y-%m-%d)
EPSS_URL="https://epss.empiricalsecurity.com/epss_scores-${DATE}.csv.gz"
if ! curl -fsSL -o "$DATA/epss_scores-${DATE}.csv.gz" "$EPSS_URL"; then
  DATE="2026-06-02"
  EPSS_URL="https://epss.empiricalsecurity.com/epss_scores-${DATE}.csv.gz"
  curl -fsSL -o "$DATA/epss_scores-${DATE}.csv.gz" "$EPSS_URL"
fi
gunzip -kf "$DATA/epss_scores-${DATE}.csv.gz" || true
mv -f "$DATA/epss_scores-${DATE}.csv" "$DATA/epss_scores-${DATE}.csv" 2>/dev/null || \
  cp "$DATA/epss_scores-${DATE}.csv" "$DATA/epss_scores-latest.csv" 2>/dev/null || true

# Symlink latest EPSS for loader glob
LATEST=$(ls -t "$DATA"/epss_scores-*.csv 2>/dev/null | head -1)
if [ -n "$LATEST" ]; then
  cp "$LATEST" "$DATA/epss_scores-latest.csv"
fi

echo "==> Downloading NVD CVE 2025 (FKIE reconstruction, ~50MB compressed)..."
CVE_URL="https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-2025.json.xz"
if [ ! -f "$DATA/CVE-2025.json" ]; then
  curl -fsSL -o "$DATA/CVE-2025.json.xz" "$CVE_URL"
  xz -d -k -f "$DATA/CVE-2025.json.xz"
fi

echo "==> Optional: CVE 2024 (uncomment if needed)"
# curl -fsSL -o "$DATA/CVE-2024.json.xz" "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-2024.json.xz"
# xz -d -k -f "$DATA/CVE-2024.json.xz"

echo ""
echo "Data files in $DATA:"
ls -lh "$DATA"
echo "Done."

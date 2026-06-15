#!/usr/bin/env python3
"""Cross-platform downloader for Vulnify's offline feeds.

Pure standard library (urllib + lzma + gzip), so it runs the same on Windows,
Linux and macOS without curl/xz/gunzip. Downloads:

  * CISA KEV catalogue          -> data/known_exploited_vulnerabilities.json
  * FIRST EPSS scores (latest)  -> data/epss_scores-latest.csv
  * NVD CVE feed (FKIE mirror)  -> data/CVE-<year>.json

Exit code is non-zero if any *required* feed could not be fetched, so callers
(run.sh / run.bat / ensure_data.py) can fall back to sample data.
"""
from __future__ import annotations

import argparse
import gzip
import lzma
import sys
import urllib.error
import urllib.request
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-{date}.csv.gz"
CVE_URL = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-{year}.json.xz"

UA = "Vulnify-Downloader/1.0"
TIMEOUT = 60


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return resp.read()


def download_kev() -> bool:
    print("==> CISA KEV catalogue…")
    try:
        DATA.mkdir(parents=True, exist_ok=True)
        (DATA / "known_exploited_vulnerabilities.json").write_bytes(_get(KEV_URL))
        print("    ok")
        return True
    except (urllib.error.URLError, OSError) as e:
        print(f"    FAILED: {e}")
        return False


def download_epss() -> bool:
    print("==> FIRST EPSS scores…")
    DATA.mkdir(parents=True, exist_ok=True)
    # EPSS publishes one file per day; try the last few days for resilience.
    for delta in range(0, 5):
        d = (date.today() - timedelta(days=delta)).isoformat()
        try:
            blob = _get(EPSS_URL.format(date=d))
            csv_bytes = gzip.decompress(blob)
            (DATA / "epss_scores-latest.csv").write_bytes(csv_bytes)
            print(f"    ok ({d})")
            return True
        except (urllib.error.URLError, OSError, EOFError):
            continue
    print("    FAILED: no recent EPSS file reachable")
    return False


def download_cve(year: int) -> bool:
    print(f"==> NVD CVE {year} (FKIE mirror, large)…")
    DATA.mkdir(parents=True, exist_ok=True)
    try:
        blob = _get(CVE_URL.format(year=year))
        json_bytes = lzma.decompress(blob)
        (DATA / f"CVE-{year}.json").write_bytes(json_bytes)
        print(f"    ok ({len(json_bytes) // (1024 * 1024)} MB)")
        return True
    except (urllib.error.URLError, OSError, lzma.LZMAError) as e:
        print(f"    FAILED: {e}")
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description="Download Vulnify offline feeds.")
    ap.add_argument("--years", default="2025", help="comma-separated CVE years (default 2025)")
    args = ap.parse_args()
    years = [int(y) for y in str(args.years).split(",") if y.strip()]

    kev_ok = download_kev()
    epss_ok = download_epss()
    cve_ok = any(download_cve(y) for y in years)

    print()
    if kev_ok and epss_ok and cve_ok:
        print("All feeds downloaded into", DATA)
        return 0
    print("One or more feeds could not be downloaded.")
    return 1


if __name__ == "__main__":
    sys.exit(main())

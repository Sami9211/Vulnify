#!/usr/bin/env python3
"""Guarantee Vulnify has feeds to run on — cross-platform, no shell required.

Used by run.sh / run.bat so the dashboard is never empty on first launch:

  1. If a CVE feed + KEV + EPSS already exist, do nothing.
  2. Otherwise try to download the real feeds (download_data.py).
  3. If that fails (offline / blocked / rate-limited), generate realistic
     *sample* feeds so the demo still works end-to-end.

Pass --sample to skip the download attempt and go straight to sample data.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
SCRIPTS = ROOT / "scripts"


def has_data() -> bool:
    cve = list(DATA.glob("CVE-*.json"))
    kev = (DATA / "known_exploited_vulnerabilities.json").exists()
    epss = list(DATA.glob("epss_scores*.csv")) or list(DATA.glob("epss_scores*.csv.gz"))
    return bool(cve and kev and epss)


def run(script: str, *args: str) -> int:
    return subprocess.call([sys.executable, str(SCRIPTS / script), *args])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", action="store_true", help="skip download, use sample data")
    ap.add_argument("--force", action="store_true", help="regenerate even if data exists")
    args = ap.parse_args()

    if has_data() and not args.force:
        print("Data feeds already present — nothing to do.")
        return 0

    if not args.sample:
        print("No feeds found. Attempting to download real NVD / KEV / EPSS data…\n")
        if run("download_data.py") == 0 and has_data():
            return 0
        print("\nDownload unavailable — falling back to generated sample data.\n")

    rc = run("generate_sample_data.py", "--force")
    if rc == 0 and has_data():
        print("\nSample feeds ready. The dashboard will populate with demo data.")
        return 0
    print("Could not prepare any data feeds.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Generate realistic *sample* offline feeds for Vulnify.

This lets the dashboard and analyzer run end-to-end without downloading the
real ~50 MB NVD feed or hitting any network — ideal for a quick one-click demo,
CI, or when `scripts/download_data.sh` cannot reach the live sources.

It writes, into ./data (repo root):
  - CVE-<year>.json   (NVD 2.0 shaped records)
  - known_exploited_vulnerabilities.json  (CISA KEV shaped)
  - epss_scores-sample.csv                (FIRST EPSS shaped)

The output is clearly marked as synthetic in every description so it can never
be mistaken for real advisories.
"""
from __future__ import annotations

import argparse
import csv
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"

# (vendor, product, CPE part 'a' app / 'o' os)
PRODUCTS: list[tuple[str, str, str]] = [
    ("microsoft", "365_apps", "a"),
    ("microsoft", "windows_server_2022", "o"),
    ("microsoft", "windows_10", "o"),
    ("microsoft", "edge", "a"),
    ("adobe", "acrobat_reader_dc", "a"),
    ("cisco", "ios_xe", "o"),
    ("vmware", "vsphere", "a"),
    ("google", "chrome", "a"),
    ("openssl", "openssl", "a"),
    ("apache", "http_server", "a"),
    ("zoom", "zoom", "a"),
    ("wordpress", "wordpress", "a"),
    ("moodle", "moodle", "a"),
    ("mozilla", "firefox", "a"),
    ("fortinet", "fortios", "o"),
    ("paloaltonetworks", "pan-os", "o"),
    ("sap", "netweaver", "a"),
    ("siemens", "simatic_s7", "o"),
    ("huawei", "router_firmware", "o"),
    ("tenda", "ac15_firmware", "o"),
    ("dlink", "dir-825_firmware", "o"),
    ("totolink", "x5000r_firmware", "o"),
    ("ivanti", "connect_secure", "a"),
    ("atlassian", "confluence", "a"),
    ("redhat", "enterprise_linux", "o"),
    ("oracle", "mysql", "a"),
    ("postgresql", "postgresql", "a"),
    ("gitlab", "gitlab", "a"),
    ("jetbrains", "teamcity", "a"),
    ("qnap", "qts", "o"),
]

# CWE -> human description fragment (kept in sync with cwe_categories.json themes)
CWES: list[tuple[str, str]] = [
    ("CWE-79", "improper neutralization of input during web page generation (XSS)"),
    ("CWE-89", "SQL injection via an unauthenticated parameter"),
    ("CWE-78", "OS command injection through a crafted request"),
    ("CWE-787", "an out-of-bounds write leading to memory corruption"),
    ("CWE-125", "an out-of-bounds read disclosing adjacent memory"),
    ("CWE-416", "a use-after-free triggered by a malformed object"),
    ("CWE-22", "path traversal allowing access to arbitrary files"),
    ("CWE-287", "an authentication bypass in the login flow"),
    ("CWE-502", "insecure deserialization of attacker-controlled data"),
    ("CWE-918", "server-side request forgery (SSRF)"),
    ("CWE-434", "unrestricted upload of a file with a dangerous type"),
    ("CWE-269", "improper privilege management enabling escalation"),
    ("CWE-94", "code injection through an unsanitized template"),
    ("CWE-352", "cross-site request forgery on a state-changing action"),
    ("CWE-400", "uncontrolled resource consumption causing denial of service"),
]

CVSS_VECTORS = [
    (9.8, "CRITICAL", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    (9.1, "CRITICAL", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    (8.8, "HIGH", "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    (7.5, "HIGH", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    (6.5, "MEDIUM", "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
    (5.4, "MEDIUM", "AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"),
    (4.3, "MEDIUM", "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    (3.1, "LOW", "AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"),
]


def _cve(year: int, seq: int, rnd: random.Random) -> dict:
    vendor, product, part = rnd.choice(PRODUCTS)
    cwe, cwe_text = rnd.choice(CWES)
    base, sev, vector = rnd.choice(CVSS_VECTORS)
    # jitter the score a touch so histograms look natural
    score = round(min(10.0, max(0.1, base + rnd.uniform(-0.3, 0.3))), 1)
    days_ago = rnd.randint(0, 360)
    published = (datetime(year, 12, 31) - timedelta(days=days_ago)).replace(
        hour=rnd.randint(0, 23), minute=rnd.randint(0, 59)
    )
    cve_id = f"CVE-{year}-{10000 + seq}"
    pretty = product.replace("_", " ").title()
    return {
        "cve": {
            "id": cve_id,
            "sourceIdentifier": "sample@vulnify.local",
            "published": published.isoformat(),
            "lastModified": published.isoformat(),
            "vulnStatus": rnd.choice(["Analyzed", "Modified", "Awaiting Analysis"]),
            "descriptions": [
                {
                    "lang": "en",
                    "value": (
                        f"[SAMPLE DATA] {vendor.title()} {pretty} is affected by "
                        f"{cwe_text}. This is synthetic data generated for the Vulnify "
                        f"demo and does not describe a real vulnerability."
                    ),
                }
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "source": "sample@vulnify.local",
                        "type": "Primary",
                        "cvssData": {
                            "version": "3.1",
                            "vectorString": f"CVSS:3.1/{vector}",
                            "baseScore": score,
                            "baseSeverity": sev,
                        },
                    }
                ]
            },
            "weaknesses": [
                {
                    "source": "sample@vulnify.local",
                    "type": "Primary",
                    "description": [{"lang": "en", "value": cwe}],
                }
            ],
            "configurations": [
                {
                    "nodes": [
                        {
                            "operator": "OR",
                            "negate": False,
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": f"cpe:2.3:{part}:{vendor}:{product}:*:*:*:*:*:*:*:*",
                                    "matchCriteriaId": f"SAMPLE-{seq}",
                                }
                            ],
                        }
                    ]
                }
            ],
            "references": [
                {
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "source": "sample@vulnify.local",
                    "tags": ["Vendor Advisory"],
                }
            ],
        }
    }


def generate(year: int, count: int, seed: int = 1337) -> tuple[list[dict], list[dict], list[dict]]:
    rnd = random.Random(seed)
    records = [_cve(year, i, rnd) for i in range(count)]

    # Mark ~8% as KEV (actively exploited), biased toward higher severity.
    kev_entries: list[dict] = []
    epss_rows: list[dict] = []
    for rec in records:
        cve = rec["cve"]
        cve_id = cve["id"]
        score = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
        cpe = cve["configurations"][0]["nodes"][0]["cpeMatch"][0]["criteria"]
        _, _, vendor, product, *_ = cpe.split(":")

        # EPSS: correlate loosely with CVSS so the buckets look realistic.
        if score >= 9:
            epss = round(rnd.uniform(0.2, 0.95), 5)
        elif score >= 7:
            epss = round(rnd.uniform(0.03, 0.6), 5)
        elif score >= 4:
            epss = round(rnd.uniform(0.002, 0.15), 5)
        else:
            epss = round(rnd.uniform(0.0001, 0.03), 5)
        epss_rows.append(
            {"cve": cve_id, "epss": epss, "percentile": round(rnd.uniform(0.1, 0.999), 5)}
        )

        if (score >= 8.5 and rnd.random() < 0.4) or rnd.random() < 0.04:
            added = (datetime(year, 12, 31) - timedelta(days=rnd.randint(0, 300))).date()
            kev_entries.append(
                {
                    "cveID": cve_id,
                    "vendorProject": vendor.title(),
                    "product": product.replace("_", " ").title(),
                    "vulnerabilityName": f"{vendor.title()} {product.replace('_', ' ').title()} Vulnerability",
                    "dateAdded": added.isoformat(),
                    "shortDescription": cve["descriptions"][0]["value"],
                    "requiredAction": "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.",
                    "dueDate": (added + timedelta(days=21)).isoformat(),
                    "knownRansomwareCampaignUse": rnd.choice(["Known", "Unknown", "Unknown"]),
                    "notes": "Synthetic KEV entry for the Vulnify demo.",
                }
            )

    return records, kev_entries, epss_rows


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate sample Vulnify feeds.")
    ap.add_argument("--year", type=int, default=2025)
    ap.add_argument("--count", type=int, default=600, help="number of sample CVEs")
    ap.add_argument("--force", action="store_true", help="overwrite existing real feeds")
    args = ap.parse_args()

    DATA.mkdir(parents=True, exist_ok=True)
    cve_path = DATA / f"CVE-{args.year}.json"
    if cve_path.exists() and not args.force:
        print(f"{cve_path} already exists; pass --force to overwrite. Skipping.")
        return

    records, kev_entries, epss_rows = generate(args.year, args.count)

    cve_path.write_text(json.dumps({"vulnerabilities": records}, indent=0), encoding="utf-8")

    kev_path = DATA / "known_exploited_vulnerabilities.json"
    kev_path.write_text(
        json.dumps(
            {
                "title": "Vulnify Sample KEV Catalog (synthetic)",
                "catalogVersion": "SAMPLE",
                "dateReleased": datetime.utcnow().isoformat(),
                "count": len(kev_entries),
                "vulnerabilities": kev_entries,
            },
            indent=0,
        ),
        encoding="utf-8",
    )

    epss_path = DATA / "epss_scores-sample.csv"
    with epss_path.open("w", newline="", encoding="utf-8") as f:
        f.write(f"#model_version:v2025.03.14,score_date:{datetime.utcnow().date()}T00:00:00+0000\n")
        writer = csv.DictWriter(f, fieldnames=["cve", "epss", "percentile"])
        writer.writeheader()
        writer.writerows(epss_rows)

    print(f"Wrote {len(records)} sample CVEs -> {cve_path.name}")
    print(f"Wrote {len(kev_entries)} sample KEV entries -> {kev_path.name}")
    print(f"Wrote {len(epss_rows)} EPSS rows -> {epss_path.name}")
    print("\nSample feeds ready. Start the backend to see the dashboard populate.")


if __name__ == "__main__":
    main()

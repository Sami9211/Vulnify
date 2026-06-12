"""Global analytics from real CVE, KEV, and EPSS data for the admin dashboard."""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from typing import Any

from .config import VENDOR_COUNTRIES_FILE
from .loader import (
    cpe_vendor_product,
    extract_cvss,
    extract_cpe_matches,
    load_cve_records,
    load_epss,
    load_kev,
    load_kev_details,
)
from .ranker import urgency_score


def load_vendor_countries() -> dict[str, str]:
    with open(VENDOR_COUNTRIES_FILE, encoding="utf-8") as f:
        return {k.lower(): v for k, v in json.load(f).items()}


def vendor_to_country(vendor: str, mapping: dict[str, str]) -> str:
    return mapping.get(vendor.lower(), "Other / Unknown")


class AnalyticsEngine:
    """Compute dashboard metrics from loaded vulnerability feeds."""

    def __init__(self) -> None:
        self._cache: dict[str, Any] | None = None
        self._vendor_countries = load_vendor_countries()

    def invalidate(self) -> None:
        self._cache = None

    def compute(self, year: int | None = None) -> dict[str, Any]:
        if self._cache is not None and year is None:
            return self._cache

        kev_set = load_kev()
        kev_details = load_kev_details()
        epss_map = load_epss()
        cve_items = load_cve_records(year=year)

        severity_buckets = Counter()
        vendor_counts = Counter()
        country_counts = Counter()
        country_kev = Counter()
        monthly = Counter()
        top_epss: list[dict] = []

        total_with_cvss = 0
        cvss_sum = 0.0
        kev_in_dataset = 0
        high_epss = 0

        from .loader import _cve_body

        for item in cve_items:
            cve = _cve_body(item)
            cve_id = (cve.get("id") or "").upper()
            if not cve_id:
                continue

            cvss = extract_cvss(item)
            if cvss is not None:
                total_with_cvss += 1
                cvss_sum += cvss
                if cvss >= 9.0:
                    severity_buckets["Critical"] += 1
                elif cvss >= 7.0:
                    severity_buckets["High"] += 1
                elif cvss >= 4.0:
                    severity_buckets["Medium"] += 1
                else:
                    severity_buckets["Low"] += 1

            epss = epss_map.get(cve_id, {}).get("epss", 0)
            if epss >= 0.5:
                high_epss += 1

            in_kev = cve_id in kev_set
            if in_kev:
                kev_in_dataset += 1

            published = cve.get("published") or cve.get("lastModified") or ""
            if published and len(published) >= 7:
                monthly[published[:7]] += 1

            cpe_list = extract_cpe_matches(item)
            vendors_seen: set[str] = set()
            for cpe in cpe_list[:5]:
                vp = cpe_vendor_product(cpe)
                if not vp:
                    continue
                vendor, _ = vp
                if vendor in vendors_seen:
                    continue
                vendors_seen.add(vendor)
                vendor_counts[vendor] += 1
                country = vendor_to_country(vendor, self._vendor_countries)
                country_counts[country] += 1
                if in_kev:
                    country_kev[country] += 1

            if epss > 0.3 or in_kev:
                top_epss.append(
                    {
                        "cve_id": cve_id,
                        "epss": epss,
                        "cvss": cvss,
                        "kev": in_kev,
                        "urgency": urgency_score(epss, in_kev, cvss),
                    }
                )

        top_epss.sort(key=lambda x: -x["urgency"])
        top_epss = top_epss[:50]

        kev_by_vendor = Counter()
        for entry in kev_details:
            vendor = (entry.get("vendorProject") or "unknown").lower()
            kev_by_vendor[vendor] += 1

        result = {
            "summary": {
                "total_cves": len(cve_items),
                "total_kev_catalog": len(kev_set),
                "kev_in_year": kev_in_dataset,
                "high_epss_count": high_epss,
                "avg_cvss": round(cvss_sum / total_with_cvss, 2) if total_with_cvss else 0,
                "with_cvss": total_with_cvss,
            },
            "severity_distribution": [
                {"name": k, "value": v}
                for k, v in sorted(
                    severity_buckets.items(),
                    key=lambda x: ["Critical", "High", "Medium", "Low"].index(x[0])
                    if x[0] in ["Critical", "High", "Medium", "Low"]
                    else 99,
                )
            ],
            "cve_timeline": [
                {"month": m, "count": c}
                for m, c in sorted(monthly.items())[-18:]
            ],
            "top_vendors": [
                {"vendor": v, "count": c}
                for v, c in vendor_counts.most_common(15)
            ],
            "by_country": [
                {
                    "country": country,
                    "vulnerabilities": count,
                    "kev_exploited": country_kev.get(country, 0),
                }
                for country, count in country_counts.most_common(20)
            ],
            "kev_by_vendor": [
                {"vendor": v, "count": c}
                for v, c in kev_by_vendor.most_common(12)
            ],
            "top_threats": top_epss[:20],
            "kev_recent": [
                {
                    "cve_id": e.get("cveID"),
                    "vendor": e.get("vendorProject"),
                    "product": e.get("product"),
                    "description": (e.get("shortDescription") or "")[:200],
                    "date_added": e.get("dateAdded"),
                    "ransomware": e.get("knownRansomwareCampaignUse", "Unknown"),
                }
                for e in sorted(
                    kev_details,
                    key=lambda x: x.get("dateAdded") or "",
                    reverse=True,
                )[:15]
            ],
        }

        if year is None:
            self._cache = result
        return result

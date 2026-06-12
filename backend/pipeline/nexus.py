"""Nexus dashboard: OpenCTI-style live feed + filterable geo/sector/industry analytics.

All metrics are computed from real offline feeds (NVD CVE, CISA KEV, FIRST EPSS).
A flat record index is built once, then every dashboard request filters and
aggregates over it so industry / vendor / country / severity / status / date /
threat-type filters stay fully interactive.
"""
from __future__ import annotations

import json
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any

from .analytics import load_vendor_countries, vendor_to_country
from .config import (
    CWE_CATEGORIES_FILE,
    INDUSTRY_TAXONOMY_FILE,
    SECTOR_TAXONOMY_FILE,
    VENDOR_LOCATIONS_FILE,
)
from .loader import (
    _cve_body,
    cpe_vendor_product,
    extract_cpe_matches,
    extract_cvss,
    extract_cwes,
    extract_description,
    extract_product_names,
    extract_published,
    extract_vuln_status,
    load_cve_records,
    load_epss,
    load_kev,
    load_kev_details,
)
from .ranker import urgency_score

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Unscored"]


def _load_json(path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _parse_ts(iso: str | None) -> datetime | None:
    if not iso:
        return None
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None


def _cvss_severity(cvss: float | None) -> str:
    if cvss is None:
        return "Unscored"
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    return "Low"


def _cwe_to_type(cwe_id: str, cwe_map: dict[str, str]) -> str:
    if cwe_id in cwe_map:
        return cwe_map[cwe_id]
    try:
        num = int(cwe_id.replace("CWE-", ""))
        if num < 200:
            return "Architecture & Design"
        if num < 400:
            return "Access Control & Authentication"
        if num < 600:
            return "Input Validation & Injection"
        if num < 800:
            return "Memory & Resource Management"
        return "Other Weakness"
    except ValueError:
        return "Other Weakness"


def _simplify_status(vuln_status: str) -> str:
    s = (vuln_status or "").lower()
    if "analyz" in s or "modified" in s:
        return "Analyzed"
    if "await" in s or "received" in s or "undergoing" in s:
        return "Awaiting Analysis"
    if "reject" in s:
        return "Rejected"
    return "Other"


def _epss_bucket(epss: float) -> str:
    if epss >= 0.5:
        return "Very High (>50%)"
    if epss >= 0.25:
        return "High (25-50%)"
    if epss >= 0.1:
        return "Moderate (10-25%)"
    if epss >= 0.01:
        return "Low (1-10%)"
    return "Minimal (<1%)"


class NexusEngine:
    """Real-data Nexus analytics with a filterable record index and live replay."""

    def __init__(self) -> None:
        self._records: list[dict] | None = None
        self._kev_records: list[dict] = []
        self._filter_options: dict[str, Any] = {}
        self._totals: dict[str, Any] = {}
        self._vendor_countries = load_vendor_countries()
        self._cwe_map = _load_json(CWE_CATEGORIES_FILE)
        self._sector_tax = _load_json(SECTOR_TAXONOMY_FILE)
        self._vendor_locs = _load_json(VENDOR_LOCATIONS_FILE)
        self._industry_tax = _load_json(INDUSTRY_TAXONOMY_FILE)
        self._replay_queue: list[dict] = []
        self._replay_cursor = 0
        self._stream_started = 0.0
        self._inputs_per_second = 0.0
        self._total_processed = 0
        self._confirmed_revealed = 0
        self._kev_reveal_cursor = 0

    # ---- classification helpers -------------------------------------------------

    def _classify_sector(self, vendor: str, product: str) -> str:
        vendor_l = vendor.lower()
        product_l = product.lower()
        vendor_sectors = self._sector_tax.get("vendor_sectors", {})
        if vendor_l in vendor_sectors:
            return vendor_sectors[vendor_l]
        for sector, kws in self._sector_tax.get("product_keywords", {}).items():
            if any(kw in product_l or kw in vendor_l for kw in kws):
                return sector
        return "enterprise"

    def _classify_industry(self, vendor: str, products: list[str]) -> str:
        vendor_l = vendor.lower()
        vendor_map = self._industry_tax.get("vendor_industry", {})
        if vendor_l in vendor_map:
            return vendor_map[vendor_l]
        haystack = " ".join(products).lower() + " " + vendor_l
        for industry, kws in self._industry_tax.get("product_keywords", {}).items():
            if any(kw in haystack for kw in kws):
                return industry
        return self._industry_tax.get("default", "Technology & General IT")

    def _vendor_location(self, vendor: str) -> dict[str, str]:
        loc = self._vendor_locs.get(vendor.lower())
        if loc:
            return loc
        return {
            "country": vendor_to_country(vendor, self._vendor_countries),
            "city": "Unknown",
            "region": "Unknown",
        }

    # ---- index build ------------------------------------------------------------

    def _ensure_index(self) -> None:
        if self._records is not None:
            return

        kev_set = load_kev()
        kev_details = load_kev_details()
        kev_map = {
            e["cveID"].upper(): e for e in kev_details if e.get("cveID")
        }
        epss_map = load_epss()
        cve_items = load_cve_records()

        self._build_replay_queue(cve_items, kev_set)

        records: list[dict] = []
        for item in cve_items:
            cve = _cve_body(item)
            cve_id = (cve.get("id") or "").upper()
            if not cve_id:
                continue

            cvss = extract_cvss(item)
            cwes = extract_cwes(item)
            threat_type = _cwe_to_type(cwes[0], self._cwe_map) if cwes else "Unclassified"

            cpe_list = extract_cpe_matches(item)
            vendor = "unknown"
            product = ""
            for cpe in cpe_list:
                vp = cpe_vendor_product(cpe)
                if vp:
                    vendor, product = vp
                    break
            products = extract_product_names(item)

            loc = self._vendor_location(vendor)
            in_kev = cve_id in kev_set
            published = extract_published(item) or ""
            month = published[:7] if len(published) >= 7 else "unknown"
            epss = epss_map.get(cve_id, {}).get("epss", 0.0)
            kev_entry = kev_map.get(cve_id)

            records.append(
                {
                    "cve_id": cve_id,
                    "vendor": vendor,
                    "product": product.replace("_", " ") if product else "unknown",
                    "country": loc["country"],
                    "city": loc["city"],
                    "region": loc.get("region", ""),
                    "org_type": self._classify_sector(vendor, product),
                    "industry": self._classify_industry(vendor, products or [product]),
                    "severity": _cvss_severity(cvss),
                    "cvss": cvss,
                    "epss": epss,
                    "threat_type": threat_type,
                    "kev": in_kev,
                    "status": "Actively Exploited"
                    if in_kev
                    else _simplify_status(extract_vuln_status(item)),
                    "ransomware": (kev_entry or {}).get("knownRansomwareCampaignUse")
                    if in_kev
                    else None,
                    "date_added": (kev_entry or {}).get("dateAdded") if in_kev else None,
                    "month": month,
                    "description": extract_description(item)[:200],
                }
            )

        self._records = records
        self._kev_records = self._build_kev_records(kev_details)
        self._build_filter_options(records)

    def _build_kev_records(self, kev_details: list[dict]) -> list[dict]:
        out = []
        for entry in sorted(
            kev_details, key=lambda x: x.get("dateAdded") or "", reverse=True
        ):
            vendor = (entry.get("vendorProject") or "unknown").lower()
            loc = self._vendor_location(vendor)
            product = (entry.get("product") or "").lower()
            out.append(
                {
                    "cve_id": entry.get("cveID"),
                    "vendor": entry.get("vendorProject"),
                    "vendor_key": vendor,
                    "product": entry.get("product"),
                    "industry": self._classify_industry(vendor, [product]),
                    "org_type": self._classify_sector(vendor, product),
                    "country": loc["country"],
                    "city": loc["city"],
                    "location_label": f"{loc['city']}, {loc['country']}",
                    "date_added": entry.get("dateAdded"),
                    "ransomware": entry.get("knownRansomwareCampaignUse", "Unknown"),
                    "description": entry.get("shortDescription"),
                    "status": "Actively Exploited",
                }
            )
        return out

    def _build_filter_options(self, records: list[dict]) -> None:
        industries = Counter(r["industry"] for r in records)
        countries = Counter(r["country"] for r in records)
        vendors = Counter(r["vendor"] for r in records if r["vendor"] != "unknown")
        threat_types = Counter(r["threat_type"] for r in records)
        statuses = Counter(r["status"] for r in records)
        months = sorted({r["month"] for r in records if r["month"] != "unknown"})

        sector_labels = self._sector_tax.get("sector_labels", {})
        self._filter_options = {
            "industries": [i for i, _ in industries.most_common()],
            "countries": [c for c, _ in countries.most_common(40)],
            "vendors": [v for v, _ in vendors.most_common(50)],
            "threat_types": [t for t, _ in threat_types.most_common()],
            "severities": SEVERITY_ORDER,
            "statuses": [s for s, _ in statuses.most_common()],
            "org_types": [
                {"id": k, "label": sector_labels.get(k, k)}
                for k in ("academic", "social_organization", "small_business", "enterprise")
            ],
            "date_range": {
                "min": months[0] if months else None,
                "max": months[-1] if months else None,
            },
        }
        self._totals = {
            "total_cves": len(records),
            "total_kev": sum(1 for r in records if r["kev"]),
        }

    # ---- filtering + aggregation ------------------------------------------------

    def _apply_filters(self, records: list[dict], f: dict) -> list[dict]:
        industry = f.get("industry")
        org_type = f.get("org_type")
        vendor = (f.get("vendor") or "").lower()
        country = f.get("country")
        severity = f.get("severity")
        status = f.get("status")
        threat_type = f.get("threat_type")
        date_from = f.get("date_from")
        date_to = f.get("date_to")
        search = (f.get("search") or "").upper()

        out = []
        for r in records:
            if industry and r["industry"] != industry:
                continue
            if org_type and r["org_type"] != org_type:
                continue
            if vendor and r["vendor"].lower() != vendor:
                continue
            if country and r["country"] != country:
                continue
            if severity and r["severity"] != severity:
                continue
            if status and r["status"] != status:
                continue
            if threat_type and r["threat_type"] != threat_type:
                continue
            if date_from and r["month"] != "unknown" and r["month"] < date_from:
                continue
            if date_to and r["month"] != "unknown" and r["month"] > date_to:
                continue
            if search and search not in (
                f"{r['cve_id']} {r['vendor']} {r['product']} {r['threat_type']}".upper()
            ):
                continue
            out.append(r)
        return out

    def query(self, f: dict | None = None) -> dict[str, Any]:
        self._ensure_index()
        f = f or {}
        records = self._apply_filters(self._records or [], f)

        severity = Counter()
        threat = Counter()
        industry = Counter()
        industry_kev = Counter()
        country = Counter()
        country_kev = Counter()
        country_types: dict[str, Counter] = defaultdict(Counter)
        vendors = Counter()
        kev_by_vendor = Counter()
        monthly = Counter()
        epss_buckets = Counter()
        cvss_hist = Counter()
        org_counts = Counter()
        org_kev = Counter()
        org_types_by_type: dict[str, Counter] = defaultdict(Counter)
        location_index: dict[str, dict] = {}

        total_cvss = 0.0
        cvss_n = 0
        kev_count = 0
        critical = 0
        high = 0
        top_threats: list[dict] = []

        for r in records:
            sev = r["severity"]
            severity[sev] += 1
            if sev == "Critical":
                critical += 1
            elif sev == "High":
                high += 1

            threat[r["threat_type"]] += 1
            industry[r["industry"]] += 1
            country[r["country"]] += 1
            country_types[r["country"]][r["threat_type"]] += 1
            org_counts[r["org_type"]] += 1
            org_types_by_type[r["org_type"]][r["threat_type"]] += 1
            if r["month"] != "unknown":
                monthly[r["month"]] += 1
            epss_buckets[_epss_bucket(r["epss"])] += 1

            if r["cvss"] is not None:
                total_cvss += r["cvss"]
                cvss_n += 1
                cvss_hist[int(r["cvss"])] += 1

            if r["vendor"] != "unknown":
                vendors[r["vendor"]] += 1

            if r["kev"]:
                kev_count += 1
                industry_kev[r["industry"]] += 1
                country_kev[r["country"]] += 1
                org_kev[r["org_type"]] += 1
                if r["vendor"] != "unknown":
                    kev_by_vendor[r["vendor"]] += 1

            loc_key = f"{r['city']}|{r['country']}|{r['vendor']}"
            li = location_index.get(loc_key)
            if li is None:
                li = location_index[loc_key] = {
                    "city": r["city"],
                    "region": r["region"],
                    "country": r["country"],
                    "vendor": r["vendor"],
                    "cve_count": 0,
                    "kev_count": 0,
                    "types": Counter(),
                }
            li["cve_count"] += 1
            if r["kev"]:
                li["kev_count"] += 1
            li["types"][r["threat_type"]] += 1

            if r["epss"] > 0.3 or r["kev"]:
                top_threats.append(
                    {
                        "cve_id": r["cve_id"],
                        "epss": round(r["epss"], 4),
                        "cvss": r["cvss"],
                        "kev": r["kev"],
                        "vendor": r["vendor"],
                        "country": r["country"],
                        "threat_type": r["threat_type"],
                        "urgency": urgency_score(r["epss"], r["kev"], r["cvss"]),
                    }
                )

        top_threats.sort(key=lambda x: -x["urgency"])

        sector_labels = self._sector_tax.get("sector_labels", {})
        org_sectors = [
            {
                "sector_id": k,
                "label": sector_labels.get(k, k),
                "total_vulnerabilities": org_counts.get(k, 0),
                "kev_exploited": org_kev.get(k, 0),
                "top_vulnerability_types": [
                    {"type": t, "count": c}
                    for t, c in org_types_by_type[k].most_common(6)
                ],
            }
            for k in ("academic", "social_organization", "small_business", "enterprise")
        ]

        country_matrix = []
        for c, tc in sorted(
            country_types.items(), key=lambda x: sum(x[1].values()), reverse=True
        )[:12]:
            total = sum(tc.values())
            country_matrix.append(
                {
                    "country": c,
                    "total": total,
                    "top_vulnerability_types": [
                        {"type": t, "count": n, "percent": round(100 * n / total, 1)}
                        for t, n in tc.most_common(8)
                    ],
                }
            )

        locations = []
        for li in sorted(
            location_index.values(), key=lambda x: x["cve_count"], reverse=True
        )[:25]:
            locations.append(
                {
                    "city": li["city"],
                    "region": li["region"],
                    "country": li["country"],
                    "vendor": li["vendor"],
                    "location_label": f"{li['city']}, {li['country']}",
                    "cve_count": li["cve_count"],
                    "kev_count": li["kev_count"],
                    "top_vulnerability_types": [
                        {"type": t, "count": c} for t, c in li["types"].most_common(5)
                    ],
                }
            )

        # KEV confirmed feed honoring compatible filters
        kev_feed = self._filter_kev_feed(f)

        return {
            "ingestion": {
                "inputs_per_second": self._inputs_per_second,
                "queue_total": len(self._replay_queue),
                "data_sources": ["NVD CVE", "CISA KEV", "FIRST EPSS"],
            },
            "summary": {
                "total_cves": len(records),
                "total_kev": kev_count,
                "critical": critical,
                "high": high,
                "avg_cvss": round(total_cvss / cvss_n, 2) if cvss_n else 0,
                "countries_tracked": len([c for c in country if c != "Other / Unknown"]),
                "industries_tracked": len(industry),
                "grand_total_cves": self._totals.get("total_cves", 0),
            },
            "severity_distribution": [
                {"name": k, "value": severity.get(k, 0)}
                for k in SEVERITY_ORDER
                if severity.get(k, 0) > 0
            ],
            "threat_type_distribution": [
                {"type": t, "count": c} for t, c in threat.most_common(12)
            ],
            "industry_distribution": [
                {"industry": i, "count": c, "kev": industry_kev.get(i, 0)}
                for i, c in industry.most_common(12)
            ],
            "by_country": [
                {"country": c, "vulnerabilities": n, "kev_exploited": country_kev.get(c, 0)}
                for c, n in country.most_common(15)
            ],
            "top_vendors": [
                {"vendor": v, "count": c} for v, c in vendors.most_common(15)
            ],
            "kev_by_vendor": [
                {"vendor": v, "count": c} for v, c in kev_by_vendor.most_common(12)
            ],
            "epss_distribution": [
                {"bucket": b, "count": epss_buckets.get(b, 0)}
                for b in [
                    "Minimal (<1%)",
                    "Low (1-10%)",
                    "Moderate (10-25%)",
                    "High (25-50%)",
                    "Very High (>50%)",
                ]
            ],
            "cvss_histogram": [
                {"score": str(i), "count": cvss_hist.get(i, 0)} for i in range(0, 11)
            ],
            "cve_timeline": [
                {"month": m, "count": c} for m, c in sorted(monthly.items())[-18:]
            ],
            "org_sectors": org_sectors,
            "country_vulnerability_matrix": country_matrix,
            "locations": locations,
            "top_threats": top_threats[:20],
            "confirmed_feed": kev_feed[:100],
            "filters_applied": {k: v for k, v in f.items() if v},
        }

    def _filter_kev_feed(self, f: dict) -> list[dict]:
        industry = f.get("industry")
        org_type = f.get("org_type")
        vendor = (f.get("vendor") or "").lower()
        country = f.get("country")
        search = (f.get("search") or "").upper()
        date_from = f.get("date_from")
        date_to = f.get("date_to")

        out = []
        for r in self._kev_records:
            if industry and r["industry"] != industry:
                continue
            if org_type and r["org_type"] != org_type:
                continue
            if vendor and (r.get("vendor_key") or "") != vendor:
                continue
            if country and r["country"] != country:
                continue
            if date_from and (r.get("date_added") or "")[:7] < date_from:
                continue
            if date_to and (r.get("date_added") or "")[:7] > date_to:
                continue
            if search and search not in (
                f"{r['cve_id']} {r.get('vendor') or ''} {r.get('product') or ''}".upper()
            ):
                continue
            out.append(r)
        return out

    def filter_options(self) -> dict[str, Any]:
        self._ensure_index()
        return self._filter_options

    # ---- live stream replay (unchanged behaviour) -------------------------------

    def _build_replay_queue(self, cve_items: list[dict], kev_set: set[str]) -> None:
        dated: list[tuple[datetime, dict]] = []
        for item in cve_items:
            cve = _cve_body(item)
            cve_id = (cve.get("id") or "").upper()
            if not cve_id:
                continue
            ts = _parse_ts(extract_published(item))
            if not ts:
                continue
            cvss = extract_cvss(item)
            cwes = extract_cwes(item)
            vuln_type = _cwe_to_type(cwes[0], self._cwe_map) if cwes else _cvss_severity(cvss)
            vendor = "unknown"
            for cpe in extract_cpe_matches(item)[:3]:
                vp = cpe_vendor_product(cpe)
                if vp:
                    vendor = vp[0]
                    break
            loc = self._vendor_location(vendor)
            in_kev = cve_id in kev_set
            dated.append(
                (
                    ts,
                    {
                        "id": cve_id,
                        "timestamp": ts.isoformat(),
                        "status": "confirmed" if in_kev else "pending",
                        "source": "CISA KEV" if in_kev else "NVD",
                        "vendor": vendor,
                        "country": loc["country"],
                        "city": loc["city"],
                        "vuln_type": vuln_type,
                        "cvss": cvss,
                        "description": extract_description(item)[:160],
                    },
                )
            )

        if not dated:
            self._replay_queue = []
            self._inputs_per_second = 0.0
            return

        dated.sort(key=lambda x: x[0])
        max_ts = dated[-1][0]
        window_start = max_ts - timedelta(days=21)
        self._replay_queue = [e for t, e in dated if t >= window_start]

        hour_counts: Counter[str] = Counter()
        for t, _ in dated:
            if t >= max_ts - timedelta(hours=24):
                hour_counts[t.strftime("%Y-%m-%d %H")] += 1
        if hour_counts:
            self._inputs_per_second = round(max(hour_counts.values()) / 3600.0, 4)
        else:
            span = (max_ts - window_start).total_seconds() or 1
            self._inputs_per_second = round(len(self._replay_queue) / span, 4)

        self._replay_cursor = 0
        self._stream_started = time.time()

    def get_stream_batch(self, batch_size: int = 8) -> dict[str, Any]:
        """Advance the live replay by one batch.

        Counters share one consistent model so the dashboard never desyncs:
        - new_inputs: real CVEs streamed this tick (incoming feed).
        - confirmed_updates: real CISA KEV records revealed progressively this
          tick (confirmed feed); each is unique and never re-sent.
        - confirmed_count == number of KEV records revealed so far == the count
          the confirmed feed accumulates, so the stat and the table stay equal.
        - pending_count + confirmed_count == total_processed (identity).
        """
        if not self._replay_queue:
            return {
                "inputs_per_second": 0,
                "new_inputs": [],
                "confirmed_updates": [],
                "total_processed": 0,
                "pending_count": 0,
                "confirmed_count": 0,
                "kev_catalog_total": len(self._kev_records),
                "queue_total": 0,
            }

        new_inputs: list[dict] = []
        for _ in range(batch_size):
            if self._replay_cursor >= len(self._replay_queue):
                self._replay_cursor = 0
            new_inputs.append(self._replay_queue[self._replay_cursor])
            self._replay_cursor += 1
        self._total_processed += len(new_inputs)

        # Progressively reveal unique, real KEV records (never repeat, never loop).
        # Front-load the first tick so the confirmed feed starts populated, then
        # reveal a few per tick afterwards.
        reveal_n = 24 if self._kev_reveal_cursor == 0 else max(1, batch_size // 2)
        start = self._kev_reveal_cursor
        end = min(start + reveal_n, len(self._kev_records))
        revealed = self._kev_records[start:end]
        self._kev_reveal_cursor = end
        self._confirmed_revealed += len(revealed)

        confirmed_updates = [
            {
                "cve_id": r["cve_id"],
                "status": "confirmed",
                "source": "CISA KEV",
                "vendor": r["vendor"],
                "product": r["product"],
                "country": r["country"],
                "city": r["city"],
                "location_label": r["location_label"],
                "date_added": r["date_added"],
                "ransomware": r["ransomware"],
                "description": (r.get("description") or "")[:180],
                "vuln_type": "Known Exploited",
            }
            for r in revealed
        ]

        pending_count = max(0, len(self._replay_queue) - self._replay_cursor)

        return {
            "inputs_per_second": self._inputs_per_second,
            "new_inputs": new_inputs,
            "confirmed_updates": confirmed_updates,
            "total_processed": self._total_processed,
            "pending_count": pending_count,
            "confirmed_count": self._confirmed_revealed,
            "kev_catalog_total": len(self._kev_records),
            "queue_total": len(self._replay_queue),
        }


_nexus = NexusEngine()


def get_nexus_dashboard(filters: dict | None = None) -> dict[str, Any]:
    return _nexus.query(filters)


def get_nexus_filters() -> dict[str, Any]:
    return _nexus.filter_options()


def get_nexus_stream(batch_size: int = 5) -> dict[str, Any]:
    _nexus._ensure_index()
    return _nexus.get_stream_batch(batch_size=batch_size)

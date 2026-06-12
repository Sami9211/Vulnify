"""Orchestrate the full Vulnify analysis pipeline."""
from __future__ import annotations

from typing import Any

from .analytics import AnalyticsEngine
from .nexus import get_nexus_dashboard, get_nexus_filters, get_nexus_stream
from .loader import load_epss, load_kev, load_kev_details
from .matcher import match_cves_to_assets
from .normalizer import normalize_assets
from .ranker import enrich_and_rank

_analytics = AnalyticsEngine()


def run_analysis(asset_text: str, year: int | None = None) -> dict[str, Any]:
    normalized, failed = normalize_assets(asset_text)
    if not normalized:
        return {
            "success": False,
            "error": "No assets could be normalized. Check product names.",
            "failed_assets": failed,
            "results": [],
        }

    matches = match_cves_to_assets(normalized, year=year)
    kev_set = load_kev()
    epss_map = load_epss()
    kev_detail_map = {
        entry["cveID"].upper(): entry for entry in load_kev_details() if entry.get("cveID")
    }
    ranked = enrich_and_rank(matches, kev_set, epss_map, kev_detail_map)

    kev_count = sum(1 for r in ranked if r["kev"])
    critical = sum(1 for r in ranked if (r.get("cvss") or 0) >= 9)
    high = sum(1 for r in ranked if 7 <= (r.get("cvss") or 0) < 9)
    confirmed = sum(1 for r in ranked if r["status"] == "confirmed")
    review = sum(1 for r in ranked if r["status"] == "review")
    false_positive = sum(1 for r in ranked if r["status"] == "false_positive")

    return {
        "success": True,
        "assets_normalized": [
            {
                "original": a.original_name,
                "version": a.version,
                "cpe": a.cpe,
                "vendor": a.vendor,
                "product": a.product,
                "match_score": a.match_score,
                "match_method": a.match_method,
            }
            for a in normalized
        ],
        "failed_assets": failed,
        "results": ranked,
        "summary": {
            "total_assets": len(normalized) + len(failed),
            "matched_cves": len(ranked),
            "kev_count": kev_count,
            "critical_cvss_count": critical,
            "high_cvss_count": high,
            "confirmed_count": confirmed,
            "review_count": review,
            "false_positive_count": false_positive,
        },
    }


def get_dashboard_analytics(year: int | None = None) -> dict[str, Any]:
    return _analytics.compute(year=year)


def get_nexus_analytics(filters: dict | None = None) -> dict[str, Any]:
    return get_nexus_dashboard(filters)


def get_nexus_filter_options() -> dict[str, Any]:
    return get_nexus_filters()


def get_nexus_live_stream(batch_size: int = 5) -> dict[str, Any]:
    return get_nexus_stream(batch_size=batch_size)

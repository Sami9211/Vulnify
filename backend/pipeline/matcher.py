"""Match CVE records to normalized assets via CPE."""
from __future__ import annotations

from typing import Any

from .loader import (
    _cve_body,
    extract_cpe_matches,
    extract_cvss,
    extract_cwes,
    extract_description,
    extract_references,
    load_cve_records,
)
from .normalizer import NormalizedAsset


def cpe_match_precision(asset: NormalizedAsset, cpe_strings: list[str]) -> str | None:
    """Return 'exact', 'wildcard', or None for how an asset matches CPE strings."""
    vendor = asset.vendor.lower()
    product = asset.product.lower()
    wildcard_hit = False
    for cpe in cpe_strings:
        cpe_lower = cpe.lower()
        if f":{vendor}:{product}:" in cpe_lower:
            return "exact"
        if (
            f":{vendor}:" in cpe_lower
            and product.replace("_", "") in cpe_lower.replace("_", "")
        ):
            wildcard_hit = True
    return "wildcard" if wildcard_hit else None


def match_cves_to_assets(
    assets: list[NormalizedAsset],
    cve_items: list[dict] | None = None,
    year: int | None = None,
) -> list[dict[str, Any]]:
    if cve_items is None:
        cve_items = load_cve_records(year=year)

    results: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    for item in cve_items:
        cve = _cve_body(item)
        cve_id = cve.get("id") or cve.get("CVE_data_meta", {}).get("ID", "")
        if not cve_id:
            continue
        cve_id = cve_id.upper()

        cpe_list = extract_cpe_matches(item)
        if not cpe_list:
            continue

        precomputed = None

        for asset in assets:
            precision = cpe_match_precision(asset, cpe_list)
            if precision is None:
                continue
            key = (cve_id, asset.vendor, asset.product)
            if key in seen:
                continue
            seen.add(key)

            if precomputed is None:
                precomputed = {
                    "cvss": extract_cvss(item),
                    "description": extract_description(item),
                    "cwes": extract_cwes(item),
                    "references": extract_references(item),
                }

            results.append(
                {
                    "cve_id": cve_id,
                    "affected_asset": asset.display_name,
                    "original_asset": asset.original_name,
                    "vendor": asset.vendor,
                    "product": asset.product,
                    "cvss": precomputed["cvss"],
                    "description": precomputed["description"],
                    "cwes": precomputed["cwes"],
                    "references": precomputed["references"],
                    "cpe_matches": cpe_list[:3],
                    "cpe_precision": precision,
                    "normalization_method": asset.match_method,
                    "normalization_score": asset.match_score,
                }
            )

    return results

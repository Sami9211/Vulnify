"""Map informal asset names to CPE identifiers using fuzzy matching."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from rapidfuzz import fuzz, process

from .config import CPE_DICTIONARY_FILE, FUZZY_MATCH_THRESHOLD


@dataclass
class NormalizedAsset:
    original_name: str
    version: str | None
    display_name: str
    cpe: str
    vendor: str
    product: str
    match_score: float
    match_method: str


def load_cpe_dictionary() -> dict[str, str]:
    with open(CPE_DICTIONARY_FILE, encoding="utf-8") as f:
        return json.load(f)


def parse_asset_line(line: str) -> tuple[str, str | None] | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if "|" in line:
        parts = [p.strip() for p in line.split("|", 1)]
        return parts[0], parts[1] if len(parts) > 1 else None
    if "," in line:
        parts = [p.strip() for p in line.split(",", 1)]
        return parts[0], parts[1] if len(parts) > 1 else None
    return line, None


def parse_asset_list(text: str) -> list[tuple[str, str | None]]:
    assets: list[tuple[str, str | None]] = []
    for line in text.splitlines():
        parsed = parse_asset_line(line)
        if parsed:
            assets.append(parsed)
    return assets


def cpe_to_vendor_product(cpe: str) -> tuple[str, str]:
    parts = cpe.split(":")
    vendor = parts[3] if len(parts) > 3 else "unknown"
    product = parts[4] if len(parts) > 4 else "unknown"
    return vendor, product


def normalize_asset(
    name: str,
    version: str | None,
    dictionary: dict[str, str] | None = None,
) -> NormalizedAsset | None:
    dictionary = dictionary or load_cpe_dictionary()
    keys = list(dictionary.keys())

    # Exact match (case-insensitive)
    for key, cpe in dictionary.items():
        if key.lower() == name.lower():
            vendor, product = cpe_to_vendor_product(cpe)
            display = f"{name}" + (f" ({version})" if version else "")
            return NormalizedAsset(
                original_name=name,
                version=version,
                display_name=display,
                cpe=cpe,
                vendor=vendor,
                product=product,
                match_score=100.0,
                match_method="exact",
            )

    # Fuzzy match on dictionary keys
    result = process.extractOne(
        name,
        keys,
        scorer=fuzz.token_sort_ratio,
    )
    if result and result[1] >= FUZZY_MATCH_THRESHOLD:
        matched_key, score, _ = result
        cpe = dictionary[matched_key]
        vendor, product = cpe_to_vendor_product(cpe)
        display = f"{name}" + (f" ({version})" if version else "")
        return NormalizedAsset(
            original_name=name,
            version=version,
            display_name=display,
            cpe=cpe,
            vendor=vendor,
            product=product,
            match_score=float(score),
            match_method="fuzzy",
        )

    # Try stripping version numbers from name and fuzzy again
    stripped = re.sub(r"\s+\d+[\d.]*.*$", "", name).strip()
    if stripped != name:
        return normalize_asset(stripped, version, dictionary)

    return None


def normalize_assets(text: str) -> tuple[list[NormalizedAsset], list[dict]]:
    dictionary = load_cpe_dictionary()
    normalized: list[NormalizedAsset] = []
    failed: list[dict] = []

    for name, version in parse_asset_list(text):
        asset = normalize_asset(name, version, dictionary)
        if asset:
            normalized.append(asset)
        else:
            failed.append({"name": name, "version": version, "reason": "no CPE match"})

    return normalized, failed

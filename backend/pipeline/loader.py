"""Load NVD CVE JSON, CISA KEV, and EPSS feeds from local files."""
from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Any

import pandas as pd

from .config import CVE_FILES, DATA_DIR, EPSS_GLOB, KEV_FILE


class DataLoadError(Exception):
    pass


def _first_existing(paths: list[Path]) -> Path | None:
    for p in paths:
        if p.exists():
            return p
    return None


def load_kev() -> set[str]:
    if not KEV_FILE.exists():
        raise DataLoadError(f"KEV file not found: {KEV_FILE}")
    with open(KEV_FILE, encoding="utf-8") as f:
        data = json.load(f)
    return {entry["cveID"] for entry in data.get("vulnerabilities", [])}


def load_kev_details() -> list[dict[str, Any]]:
    if not KEV_FILE.exists():
        return []
    with open(KEV_FILE, encoding="utf-8") as f:
        data = json.load(f)
    return data.get("vulnerabilities", [])


def load_epss() -> dict[str, dict[str, float]]:
    files = sorted(DATA_DIR.glob(EPSS_GLOB))
    if not files:
        gz_files = sorted(DATA_DIR.glob("epss_scores-*.csv.gz"))
        if gz_files:
            with gzip.open(gz_files[-1], "rt", encoding="utf-8") as f:
                df = pd.read_csv(f, comment="#")
        else:
            raise DataLoadError(
                f"No EPSS file in {DATA_DIR}. Run scripts/download_data.sh"
            )
    else:
        df = pd.read_csv(files[-1], comment="#")

    df.columns = [c.strip().lower() for c in df.columns]
    result: dict[str, dict[str, float]] = {}
    for _, row in df.iterrows():
        cve = str(row["cve"]).strip().upper()
        result[cve] = {
            "epss": float(row.get("epss", 0) or 0),
            "percentile": float(row.get("percentile", 0) or 0),
        }
    return result


def load_cve_records(year: int | None = None) -> list[dict[str, Any]]:
    """Load CVE records from FKIE/NVD JSON files."""
    paths: list[Path] = []
    if year:
        paths = [DATA_DIR / f"CVE-{year}.json"]
    else:
        paths = list(CVE_FILES)

    cve_path = _first_existing(paths)
    if not cve_path:
        available = list(DATA_DIR.glob("CVE-*.json"))
        if not available:
            raise DataLoadError(
                f"No CVE JSON in {DATA_DIR}. Run scripts/download_data.sh"
            )
        cve_path = sorted(available)[-1]

    with open(cve_path, encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict) and "CVE_Items" in data:
        return data["CVE_Items"]
    if isinstance(data, dict) and "cve_items" in data:
        return data["cve_items"]
    if isinstance(data, dict) and "vulnerabilities" in data:
        return [v.get("cve", v) for v in data["vulnerabilities"]]
    if isinstance(data, list):
        return data
    raise DataLoadError(f"Unrecognized CVE JSON structure in {cve_path}")


def _cve_body(item: dict) -> dict:
    """Return the CVE record whether wrapped or flat (FKIE/NVD 2.0)."""
    if "cve" in item and isinstance(item["cve"], dict):
        return item["cve"]
    return item


def extract_cvss(item: dict) -> float | None:
    """Extract best available CVSS base score from NVD 2.0 or legacy format."""
    body = _cve_body(item)
    metrics = body.get("metrics") or item.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key, [])
        if arr:
            data = arr[0].get("cvssData", arr[0])
            score = data.get("baseScore")
            if score is not None:
                return float(score)
    return None


def extract_description(item: dict) -> str:
    cve = _cve_body(item)
    descs = cve.get("descriptions", item.get("descriptions", []))
    for d in descs:
        if d.get("lang") == "en":
            return d.get("value", "")
    if descs:
        return descs[0].get("value", "")
    return "No description available."


def extract_cpe_matches(item: dict) -> list[str]:
    """Return CPE match strings from configuration nodes."""
    cve = _cve_body(item)
    configs = cve.get("configurations") or item.get("configurations") or []

    cpe_list: list[str] = []
    nodes_list = configs if isinstance(configs, list) else [configs]

    def walk_nodes(nodes: list) -> None:
        for node in nodes:
            if not isinstance(node, dict):
                continue
            for match in node.get("cpeMatch", []) or []:
                criteria = match.get("criteria") or match.get("cpe23Uri")
                if criteria:
                    cpe_list.append(criteria.lower())
            if node.get("children"):
                walk_nodes(node["children"])
            if node.get("nodes"):
                walk_nodes(node["nodes"])

    for cfg in nodes_list:
        if isinstance(cfg, dict):
            walk_nodes(cfg.get("nodes", [cfg]))
    return cpe_list


def extract_cwes(item: dict) -> list[str]:
    """Extract CWE IDs from NVD weakness descriptions."""
    cve = _cve_body(item)
    cwes: list[str] = []
    for weakness in cve.get("weaknesses", []) or []:
        for desc in weakness.get("description", []) or []:
            if desc.get("lang") != "en":
                continue
            value = (desc.get("value") or "").strip()
            if value.upper().startswith("CWE-"):
                cwe_id = value.split()[0].upper()
                if cwe_id not in cwes:
                    cwes.append(cwe_id)
    return cwes


def extract_published(item: dict) -> str | None:
    cve = _cve_body(item)
    return cve.get("published") or cve.get("lastModified")


def extract_vuln_status(item: dict) -> str:
    cve = _cve_body(item)
    return cve.get("vulnStatus") or "Unknown"


def extract_product_names(item: dict, limit: int = 6) -> list[str]:
    """Return product slugs referenced in a CVE's CPE configurations."""
    names: list[str] = []
    for cpe in extract_cpe_matches(item):
        parts = cpe.split(":")
        if len(parts) >= 5:
            product = parts[4].replace("_", " ")
            if product and product not in names:
                names.append(product)
        if len(names) >= limit:
            break
    return names


def extract_references(item: dict, limit: int = 6) -> list[dict[str, Any]]:
    """Extract reference URLs and tags from an NVD CVE record."""
    cve = _cve_body(item)
    refs: list[dict[str, Any]] = []
    seen: set[str] = set()
    for ref in cve.get("references", []) or []:
        url = ref.get("url")
        if not url or url in seen:
            continue
        seen.add(url)
        tags = ref.get("tags", []) or []
        label = tags[0] if tags else _ref_label_from_url(url)
        refs.append({"url": url, "label": label, "tags": tags})
        if len(refs) >= limit:
            break
    return refs


def _ref_label_from_url(url: str) -> str:
    lowered = url.lower()
    if "patch" in lowered or "security" in lowered or "advisory" in lowered:
        return "Advisory"
    if "github.com" in lowered:
        return "GitHub"
    if "exploit" in lowered:
        return "Exploit"
    return "Reference"


def cpe_vendor_product(cpe: str) -> tuple[str, str] | None:
    """Parse vendor:product from cpe:2.3:a:vendor:product:..."""
    parts = cpe.split(":")
    if len(parts) >= 5:
        return parts[3], parts[4]
    return None


def data_status() -> dict[str, Any]:
    epss_files = list(DATA_DIR.glob(EPSS_GLOB)) + list(DATA_DIR.glob("epss_scores-*.csv.gz"))
    cve_files = list(DATA_DIR.glob("CVE-*.json"))
    return {
        "data_dir": str(DATA_DIR),
        "kev_loaded": KEV_FILE.exists(),
        "epss_loaded": len(epss_files) > 0,
        "cve_files": [f.name for f in cve_files],
        "kev_path": str(KEV_FILE) if KEV_FILE.exists() else None,
    }

"""Paths and constants for the Vulnify pipeline."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"
BACKEND_DATA = Path(__file__).resolve().parents[1] / "data"

CVE_FILES = [
    DATA_DIR / "CVE-2025.json",
    DATA_DIR / "CVE-2024.json",
]
KEV_FILE = DATA_DIR / "known_exploited_vulnerabilities.json"
EPSS_GLOB = "epss_scores*.csv"

CPE_DICTIONARY_FILE = BACKEND_DATA / "cpe_dictionary.json"
VENDOR_COUNTRIES_FILE = BACKEND_DATA / "vendor_countries.json"
CWE_CATEGORIES_FILE = BACKEND_DATA / "cwe_categories.json"
SECTOR_TAXONOMY_FILE = BACKEND_DATA / "sector_taxonomy.json"
VENDOR_LOCATIONS_FILE = BACKEND_DATA / "vendor_locations.json"
INDUSTRY_TAXONOMY_FILE = BACKEND_DATA / "industry_taxonomy.json"

# User-defined live threat-intel connectors (AlienVault OTX, custom HTTP feeds).
# Written at runtime; kept out of version control (see .gitignore).
CONNECTORS_FILE = BACKEND_DATA / "connectors.json"

# Urgency weights (stretch goal: combined score)
KEV_BOOST = 1000.0
EPSS_WEIGHT = 100.0
CVSS_WEIGHT = 10.0

FUZZY_MATCH_THRESHOLD = 75

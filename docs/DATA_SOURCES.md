# Data Sources: Complete Reference

Every dataset used in this project is **pre-downloaded and local**. No live vulnerability APIs are called at runtime (per hackathon rules).

---

## 1. NVD CVE Data (Primary vulnerability database)

| Field | Value |
|-------|--------|
| **Official page** | https://nvd.nist.gov/vuln/data-feeds |
| **Our source** | Fraunhofer FKIE community reconstruction |
| **GitHub** | https://github.com/fkie-cad/nvd-json-data-feeds |
| **Download** | https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-2025.json.xz |
| **Local path** | `data/CVE-2025.json` |
| **Format** | JSON (NVD 2.0 style, FKIE per-year files) |
| **Size** | ~214 MB uncompressed (2025) |

**Why FKIE?** NIST retired legacy 1.1 JSON feeds in August 2025. FKIE mirrors NVD in the same practical offline format.

**Fields we use:**
- `cve.id`: CVE identifier
- `descriptions`: English summary
- `metrics`: CVSS v3.1 / v3.0 / v2 base scores
- `configurations` / `cpeMatch`: affected CPE strings for matching

**Code:** `backend/pipeline/loader.py` → `load_cve_records()`, `extract_cvss()`, `extract_cpe_matches()`

---

## 2. CISA Known Exploited Vulnerabilities (KEV)

| Field | Value |
|-------|--------|
| **Catalogue** | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| **JSON URL** | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| **Local path** | `data/known_exploited_vulnerabilities.json` |
| **Format** | JSON |
| **Size** | ~1.4 MB |
| **Update** | Weekdays (US Eastern) |

**Fields we use:**
- `cveID`: matched against our CVE list
- `vendorProject`, `product`, `shortDescription`
- `dateAdded`, `knownRansomwareCampaignUse`

**Urgency rule:** KEV membership adds a large boost to `urgency_score` so exploited CVEs rank first.

**Code:** `loader.load_kev()`, `loader.load_kev_details()`, `ranker.urgency_score()`

---

## 3. EPSS (Exploit Prediction Scoring System)

| Field | Value |
|-------|--------|
| **Project** | https://www.first.org/epss/ |
| **Download pattern** | `https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz` |
| **Example** | https://epss.empiricalsecurity.com/epss_scores-2026-06-02.csv.gz |
| **Local path** | `data/epss_scores-latest.csv` (copied from dated file) |
| **Format** | CSV with header comment lines (`#`) |
| **Columns** | `cve`, `epss` (0 to 1), `percentile` |
| **Size** | ~10 MB uncompressed |
| **Update** | Daily |

**Meaning:** EPSS estimates probability of exploitation in the wild within 30 days. Higher = more urgent in practice than CVSS alone.

**Code:** `loader.load_epss()` → dict keyed by CVE ID

---

## 4. CPE Normalisation Dictionary (Built by us)

| Field | Value |
|-------|--------|
| **Reference** | NVD CPE Dictionary https://nvd.nist.gov/vuln/data-feeds |
| **Our file** | `backend/data/cpe_dictionary.json` |
| **Entries** | 30+ informal product names → `cpe:2.3:...` URIs |

**Examples:**
- `Office 365` → `cpe:2.3:a:microsoft:365_apps:...`
- `Windows Server 2022` → `cpe:2.3:o:microsoft:windows_server_2022:...`

**Fuzzy matching:** `rapidfuzz` token_sort_ratio, threshold 75%  
**Code:** `backend/pipeline/normalizer.py`

---

## 5. Vendor → Country / Location Mapping (Analytics enrichment)

| Field | Value |
|-------|--------|
| **Files** | `backend/data/vendor_countries.json`, `backend/data/vendor_locations.json` |
| **Purpose** | Dashboard "by country" chart, **world threat map**, vendor origin table |
| **Method** | Maps CPE vendor slug to headquarters country and city/region |

**Important for judges:** This is **vendor origin**, not GPS of attacks. True attack geolocation would need separate threat-intel feeds (e.g. honeypots, ISAC reports). We label this clearly in the UI.

---

## 6. Industry & Sector Taxonomies (Built by us)

| Field | Value |
|-------|--------|
| **Files** | `backend/data/industry_taxonomy.json`, `backend/data/sector_taxonomy.json` |
| **Purpose** | Industry filter (Healthcare, Finance, Retail, Government, Telecom, Manufacturing, ...) and org-sector breakdown (academic, social org, SMB, enterprise) |
| **Method** | Match CVE vendor and product names against curated vendor lists and keyword sets |

**Honest note for judges:** Industry/sector is **not** a field inside the CVE. It is a heuristic over real vendor/product names, so we present it as a best-effort classification, not ground truth.

**Code:** `pipeline/nexus.py` → `_classify_industry()`, sector classification

---

## 7. CWE → Weakness Category (Threat-type labels)

| Field | Value |
|-------|--------|
| **File** | `backend/data/cwe_categories.json` |
| **Purpose** | Human-readable "threat type" / weakness categories used in charts and the country matrix |
| **Method** | Maps CWE identifiers from NVD `weaknesses` to readable labels |

---

## 8. World Map Geography (Offline vector)

| Field | Value |
|-------|--------|
| **Source** | world-atlas / Natural Earth (TopoJSON) |
| **Local path** | `frontend/public/world-110m.json` |
| **Purpose** | Renders the interactive **world threat map** choropleth via react-simple-maps |
| **Note** | Bundled locally so the map renders fully offline |

---

## Download script

`scripts/download_data.sh` automates all downloads. Re-run to refresh before demo.

---

## Libraries (Python)

| Package | Purpose | Install |
|---------|---------|---------|
| pandas | EPSS CSV, export | `pip install pandas` |
| rapidfuzz | Fuzzy name matching | `pip install rapidfuzz` |
| flask + flask-cors | REST API | `pip install flask flask-cors` |
| tabulate | CLI tables | `pip install tabulate` |

## Libraries (Frontend)

| Package | Purpose |
|---------|---------|
| React 19 + Vite | UI |
| Recharts | Donut, radial gauges, gradient bars, area/line charts |
| react-simple-maps | World threat map choropleth |
| lucide-react | Icons |

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Data file status |
| GET | `/api/dashboard` | Global analytics JSON |
| POST | `/api/analyze` | Body: `{ "assets": "..." }` → findings with trust score, mitigation, links |
| GET | `/api/analyze/sample` | Run hackathon sample list |
| POST | `/api/analyze/export` | CSV download |
| GET | `/api/sample-assets` | Raw sample file text |
| GET | `/api/nexus` | Filterable dashboard analytics (accepts industry, vendor, country, severity, status, threat_type, date_from, date_to, q query params) |
| GET | `/api/nexus/filters` | Available filter options (industries, countries, vendors, threat types, statuses, date range) |
| GET | `/api/nexus/stream` | Live ingestion batch (incoming disclosures + confirmed KEV) |

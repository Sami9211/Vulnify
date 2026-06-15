# Vulnify

**CyberHack 2026 · Hackathon Project 1**

Two things in one platform:

1. **Stack analyzer** - paste your software asset list and get a **prioritised, plain-English list of CVEs** that actually affect your stack, each with a CVSS score, EPSS probability, KEV flag, **trust score**, **recommended mitigation**, and **direct links to NVD/MITRE**.
2. **Nexus dashboard** - a SOC-style vulnerability intelligence console with a live ingestion feed, an interactive **world threat map**, and fully filterable analytics (by industry, vendor, country, severity, status, threat type, date).

The core analytics are computed from **real offline feeds** (NVD CVE, CISA KEV,
FIRST EPSS). You can *optionally* layer on **live** threat intelligence via
pluggable connectors (AlienVault OTX or any custom HTTP feed) — see below.

## Quick start — one click

The fastest way to see the dashboard, on any OS:

**Windows** — double-click **`run.bat`** (or run it in a terminal).
**Linux / macOS** — `./run.sh`

The launcher creates the Python venv, installs backend + frontend dependencies,
makes sure data feeds exist (downloading the real ones, or generating realistic
**sample** feeds if the network is unavailable), starts both servers and opens
the dashboard at **http://localhost:5173**.

> Want a guaranteed-offline demo with zero network? `run.bat --sample` /
> `./run.sh --sample` forces generated sample data.

## Quick start — manual

### 1. Get data (one-time)

```bash
python3 scripts/download_data.py          # real NVD / KEV / EPSS feeds (cross-platform)
# or, fully offline:
python3 scripts/generate_sample_data.py   # realistic synthetic feeds
```

### 2. Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

API runs at **http://127.0.0.1:5001**. Configurable via env vars:
`VULNIFY_HOST`, `VULNIFY_PORT`, `VULNIFY_DEBUG` (debug is **off** by default).

### 3. Frontend dashboard

```bash
cd frontend
npm install
npm run dev
```

Open **http://localhost:5173**

### 4. CLI (demo / judges)

```bash
source backend/.venv/bin/activate
python run_analysis.py data/sample_asset_list.txt
```

## Live connectors (optional)

Open **Live connectors** in the sidebar to stream real-time intelligence onto
the dashboard:

| Connector | What it does |
|-----------|--------------|
| **AlienVault OTX** | Pulls community **pulses** + indicators from [OTX](https://otx.alienvault.com). Paste your free OTX API key in the connector form. |
| **Custom HTTP** | Point Vulnify at any JSON endpoint; it auto-detects the item list (or set a dotted `items_path`) and renders events, tags and targeted regions. |
| **Demo feed** | Built-in synthetic OTX-style data — works offline, no key required. |

API keys are stored server-side only (in `backend/data/connectors.json`, which
is git-ignored) and are **never** returned to the browser — the API exposes
only a masked hint. If a live source is unreachable, the panel transparently
falls back to the demo feed so the dashboard is never empty.

## Features

### Stack analyzer
| Feature | Description |
|--------|-------------|
| **Prioritised findings** | Paste an asset list, get a ranked CVE table with KPI cards, filter chips and search |
| **Fuzzy normalisation** | Maps informal names ("Office 365") to CPE via rapidfuzz |
| **Trust score** | 0-100 confidence that a finding genuinely applies to your asset (CPE precision + normalisation quality + KEV/CVSS/EPSS signals) |
| **Risk summary + mitigation** | Plain-English impact and recommended remediation (CISA KEV required actions when available) |
| **CVE documentation links** | Direct links to NVD and MITRE for every finding |
| **CSV export** | `POST /api/analyze/export` |

### Nexus dashboard (separate page per sidebar item)
| Page | Description |
|------|-------------|
| **Overview** | Headline KPIs, severity donut, risk gauges, global threat map |
| **Live feed** | Real-time ingestion: incoming NVD disclosures + confirmed CISA KEV exploitations, with synced processed/queue/confirmed counters |
| **Threat analysis** | Severity donut, weakness categories, disclosure timeline, EPSS likelihood, highest-urgency table |
| **Geographic** | Interactive world choropleth map, ranked countries, per-country weakness matrix, vendor origin table |
| **Industries** | Vulnerabilities mapped to Healthcare, Finance, Retail, Government, Telecom, Manufacturing, etc. |
| **Org sectors** | Academic, social orgs, small business, enterprise breakdown |
| **Vendors** | Most affected vendors and most actively exploited (KEV) vendors |
| **Confirmed exploits** | Filterable CISA KEV table |

### Cross-cutting
| Feature | Description |
|--------|-------------|
| **Hover-expand sidebar** | Collapsed rail that expands on hover; each item opens a dedicated page |
| **Global filters** | Industry, vendor, country, severity, status, threat type, date range and search; every chart, map and table updates instantly |
| **Industry classification** | Vendors/products mapped to industry sectors via a curated taxonomy |
| **World threat map** | Offline vector choropleth (react-simple-maps + bundled topojson), zoom/pan/hover |
| **Professional visuals** | Gradient bars, donut with centered total, radial risk gauges |

## Project structure

```
├── run.bat / run.sh           # one-click cross-platform launchers
├── backend/
│   ├── app.py                 # Flask REST API
│   ├── pipeline/              # loader, normalizer, matcher, ranker, analytics,
│   │                          #   nexus, connectors, service
│   └── data/
│       ├── cpe_dictionary.json        # informal name → CPE
│       ├── vendor_countries.json      # vendor → HQ country
│       ├── vendor_locations.json      # vendor → city/region/country
│       ├── sector_taxonomy.json       # vendor/product → org sector
│       ├── industry_taxonomy.json     # vendor/product → industry
│       ├── cwe_categories.json        # CWE id → weakness label
│       └── connectors.json            # saved live connectors (git-ignored, may hold keys)
├── frontend/                  # React + Vite + Recharts + react-simple-maps
│   ├── public/world-110m.json # offline world topojson for the map
│   └── src/components/        # Nexus, Analyzer, Connectors, Sidebar, FilterBar, WorldMap
├── data/                      # Downloaded or generated feeds (not in git)
├── docs/
│   ├── PITCH.md               # 5-minute jury presentation script
│   ├── ARCHITECTURE.md
│   ├── TECH_STACK.md
│   └── DATA_SOURCES.md
├── scripts/
│   ├── download_data.py       # cross-platform real-feed downloader
│   ├── generate_sample_data.py# offline synthetic feeds
│   └── ensure_data.py         # used by the launchers (download → sample fallback)
└── run_analysis.py            # CLI
```

## Pitch & documentation

Read **`docs/PITCH.md`** for your 5-minute jury script and talking points.  
Read **`docs/DATA_SOURCES.md`** for every URL, licence, and field used.

## Evaluation alignment

- ✅ Loads NVD, KEV, EPSS (3+ feeds)
- ✅ 30+ product normalisation dictionary + fuzzy match
- ✅ CPE-based CVE filtering
- ✅ EPSS + KEV ranking with combined urgency score + trust score
- ✅ Plain-English risk summaries, mitigation, NVD/MITRE links + CSV export
- ✅ Multi-page filterable dashboard with world threat map and live ingestion feed
- ✅ Sample asset list from hackathon guide Section 10

## Known limitations (say these to judges)

1. **Silent misses**: wrong CPE mapping = CVE never appears (no error).
2. **EPSS is predictive**: a low score does not mean safe.
3. **KEV is US-confirmed exploitation**: absence does not mean unexploited.
4. **Country analytics**: derived from vendor HQ mapping, not attack geolocation.
5. **Industry/sector**: a heuristic over vendor and product names, not a field in the CVE.
6. **Trust score**: a confidence heuristic to triage findings, not a guarantee.

## Licence

Hackathon/educational use. CVE data from NIST/NVD; KEV from CISA; EPSS from FIRST.

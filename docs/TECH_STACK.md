# Vulnify - Tech Stack: One Page for Judges

## What we built

| Layer | Technology | Version / notes |
|-------|------------|-----------------|
| **Core language** | Python | 3.10+ |
| **Data processing** | pandas, stdlib json | In-memory, no database |
| **Fuzzy matching** | rapidfuzz | Normalises "Office 365" → CPE |
| **API** | Flask + flask-cors | Port 5001 |
| **CLI** | tabulate | `run_analysis.py` |
| **Frontend** | React 19 + TypeScript | Vite |
| **Charts** | Recharts | Donut, radial gauges, gradient bars, area |
| **Map** | react-simple-maps | Offline world choropleth (bundled topojson) |
| **Icons** | lucide-react | Sidebar / UI |
| **Dev proxy** | Vite | `/api` → Flask |

## Data (all offline, real)

| Feed | Source | Local file |
|------|--------|------------|
| CVE | FKIE NVD mirror | `data/CVE-2025.json` (~44k CVEs) |
| KEV | CISA | `data/known_exploited_vulnerabilities.json` |
| EPSS | FIRST / Empirical Security | `data/epss_scores-latest.csv` |

## Key algorithms

1. **Normalise** asset name → CPE (dictionary + fuzzy 75% threshold)
2. **Match** CVE if NVD `cpeMatch` contains `:vendor:product:`
3. **Rank** `urgency = 1000×KEV + 100×EPSS + 10×CVSS`
4. **Trust score** CPE precision + normalisation quality + KEV/CVSS/EPSS signals (0-100)
5. **Classify** each CVE into an industry and org sector from vendor/product taxonomies
6. **Index + query** build a flat record index once, then filter/aggregate per request for the dashboard

## Repository map

- `backend/pipeline/`: all business logic (loader, normalizer, matcher, ranker, analytics, nexus, service)
- `backend/data/`: cpe_dictionary, vendor_countries, vendor_locations, sector_taxonomy, industry_taxonomy, cwe_categories
- `frontend/src/components/Nexus.tsx`: multi-page dashboard (overview, live, threats, geo, industries, sectors, vendors, exploits)
- `frontend/src/components/WorldMap.tsx`: offline world threat map
- `frontend/src/components/Sidebar.tsx`, `FilterBar.tsx`, `Analyzer.tsx`
- `frontend/public/world-110m.json`: bundled map geography
- `docs/PITCH.md`: 5-minute script

## Commands to demo

```bash
./scripts/download_data.sh    # once
./start.sh                    # both servers
python run_analysis.py        # terminal demo
```

## Team talking points

- Solves **information overload** for SMB IT (brief Use Case 1)
- **Hardest part**: normalisation (silent misses if wrong CPE)
- **Differentiators**: trust score per finding, industry/sector filtering, offline world threat map, synced live ingestion feed
- **Honest limits**: EPSS predictive, KEV US-confirmed, countries = vendor HQ, industry = heuristic on vendor/product names

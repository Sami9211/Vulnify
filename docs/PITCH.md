# Jury Pitch Script: Vulnify

**Duration:** 5 minutes maximum  
**Audience:** Hackathon judges (technical + semi-technical)

---

## Opening (30 seconds)

> "Every day, dozens of new CVEs are published. A small IT team cannot read them all, and most do not even apply to their software. We built **Vulnify**: paste your asset list, get a **short, prioritised action list** with plain-English explanations, powered by **real NVD, CISA KEV, and EPSS data**, fully offline."

---

## The problem (45 seconds)

**One sentence (from the brief):**  
*A small IT administrator cannot filter hundreds of daily CVEs to the three or four that actually affect their systems.*

**Example (Use Case 1, Alex the sysadmin):**
- 40-person firm: Windows Server, M365, payroll app, Cisco router
- 47 new CVEs overnight, tool returns **4 relevant**, **1 in KEV**, patch that one first

**Hardest part we solved:** **Normalisation**. Users say "Office 365", NVD says `microsoft:365_apps`. We use a curated CPE dictionary + **rapidfuzz** fuzzy matching.

---

## Live demo flow (2 minutes)

1. **Open dashboard** (`http://localhost:5173`), show data status pills (KEV, EPSS, NVD)

2. **Nexus dashboard** - hover the sidebar to expand, then walk the pages:
   - **Overview**: headline KPIs, severity donut, two risk gauges, and the **global threat map**
   - **Live feed**: inputs/second from real NVD publication rates; incoming disclosures and confirmed CISA KEV exploitations stream in with synced **processed / queue / confirmed** counters
   - **Geographic**: zoom/pan the **world choropleth map**, ranked countries, per-country weakness matrix
   - **Industries**: filter the whole dashboard to **Healthcare** (or Finance, Retail, Government) and show every chart and the map re-compute instantly
   - **Vendors / Org sectors / Confirmed exploits**: more breakdowns

3. **Filters**: pick Industry = Healthcare + Severity = Critical and show the count collapse to the handful that matter

4. **Stack analyzer**
   - Click **"Run hackathon sample"** (Section 10 asset list)
   - Show the prioritised findings: KEV entries at top, **trust score** meter, **risk summary**, **recommended mitigation**, and **NVD/MITRE links** on each card
   - Export to CSV

5. **Optional:** `python run_analysis.py` in terminal for CLI proof

---

## Technical architecture (1 minute)

| Piece | What we used |
|-------|----------------|
| CVE data | NVD via FKIE `CVE-2025.json` (~44k CVEs) |
| Exploitation flag | CISA `known_exploited_vulnerabilities.json` |
| Exploit likelihood | FIRST EPSS daily CSV |
| Matching | CPE strings in NVD configurations |
| Ranking | `KEV boost + EPSS*100 + CVSS*10` |
| Trust score | CPE precision + normalisation quality + KEV/CVSS/EPSS signals (0-100) |
| Industry/sector | Curated vendor + product keyword taxonomies |
| Filterable analytics | Prebuilt in-memory record index, aggregated per request |
| Backend | Python, Flask, pandas, rapidfuzz |
| Frontend | React 19, Vite, Recharts, react-simple-maps |

**No live APIs.** All feeds pre-downloaded (`scripts/download_data.sh`). The world map geography is bundled locally, so the whole app runs offline.

---

## What we deliver (30 seconds)

- Prioritised CVE findings (CVSS, EPSS, KEV, trust score, risk summary, mitigation, NVD/MITRE links)
- 30+ product normalisation dictionary + fuzzy matching
- Multi-page SOC-style dashboard: live feed, world threat map, threat/industry/vendor/geo analytics
- Full filtering by industry, vendor, country, severity, status, threat type and date
- Working CLI + web UI + CSV export

---

## Limitations, say these clearly (30 seconds)

Judges reward honesty:

1. **Silent misses**: if we map "Office 365" to the wrong CPE, that CVE never appears. No error.
2. **EPSS is probability**, not proof. A low score does not mean safe.
3. **KEV = confirmed exploitation reported to CISA**. Not in KEV does not mean unexploited.
4. **Country chart** = vendor HQ from our mapping, **not** where attacks occurred geographically.

---

## Closing (15 seconds)

> "We turned a firehose of CVEs into an actionable, prioritised list for SMB admins, using the same signals enterprise SOCs use: **KEV, EPSS, and CVSS**, with a path to grow the normalisation dictionary over time. Thank you."

---

## Likely judge questions & answers

**Q: Why not call the NVD API?**  
A: Hackathon rule, offline feeds only. Ensures demo works without network.

**Q: How accurate is matching?**  
A: Depends on CPE normalisation. We test against the official sample list; fuzzy match helps informal names.

**Q: Where do countries come from?**  
A: We map CPE vendor (e.g. `microsoft`) to HQ country and aggregate CVE counts. Attack geo would need different intel sources.

**Q: What's the urgency formula?**  
A: KEV adds 1000 points, then EPSS*100 + CVSS*10. KEV always floats to top, then highest exploit probability.

**Q: What is the trust score?**  
A: A 0-100 confidence that the finding genuinely applies to the asset. It rewards an exact CPE match, a confident name normalisation, and the presence of CVSS/EPSS/KEV signals. It lets an admin separate confident findings from ones worth reviewing.

**Q: How is industry determined?**  
A: We classify each CVE's vendor and product names against a curated taxonomy (keywords like "hospital", "bank", "shop", "school"). It is a heuristic on real data, not a label inside the CVE, and we say so. It surfaces genuinely sector-specific software (e.g. OpenEMR and hospital-management apps under Healthcare).

**Q: Are the filters real-time over 44k CVEs?**  
A: Yes. We build a flat record index once, then filter and re-aggregate in memory per request, so industry/vendor/country/severity/date filters stay interactive.

**Q: Is the live feed fake?**  
A: No. It replays real NVD publications from the last 21 days and reveals real CISA KEV records progressively. The processed, queue and confirmed counters share one consistent model, so the confirmed count always matches the confirmed table.

---

## Files to show judges

- `docs/DATA_SOURCES.md`: every URL and field
- `backend/data/cpe_dictionary.json`: normalisation proof
- `data/sample_asset_list.txt`: official test input

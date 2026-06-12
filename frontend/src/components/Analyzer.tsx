import { useMemo, useState } from 'react';
import type { AnalysisResponse, CveResult } from '../api';
import { exportCsv } from '../api';

interface Props {
  assets: string;
  onAssetsChange: (v: string) => void;
  onAnalyze: () => void;
  onSample: () => void;
  onLoadSampleText: () => void;
  loading: boolean;
  result: AnalysisResponse | null;
}

type FilterKey = 'all' | 'confirmed' | 'review' | 'false_positive' | 'kev' | 'critical';

function severityClass(sev: string) {
  return `sev-${sev.toLowerCase()}`;
}

function statusMeta(status: CveResult['status']) {
  switch (status) {
    case 'confirmed':
      return { label: 'Confirmed', cls: 'st-confirmed' };
    case 'review':
      return { label: 'Needs review', cls: 'st-review' };
    default:
      return { label: 'Likely false positive', cls: 'st-false' };
  }
}

function trustClass(t: number) {
  if (t >= 75) return 'trust-high';
  if (t >= 50) return 'trust-mid';
  return 'trust-low';
}

function FindingCard({ row }: { row: CveResult }) {
  const [open, setOpen] = useState(false);
  const st = statusMeta(row.status);

  return (
    <div className={`finding-card ${severityClass(row.severity)}`}>
      <button
        type="button"
        className="finding-head"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
      >
        <span className="finding-rank">#{row.rank}</span>
        <div className="finding-id-block">
          <span className="finding-id">{row.cve_id}</span>
          <span className="finding-asset">{row.affected_asset}</span>
        </div>
        <div className="finding-badges">
          <span className={`badge sev ${severityClass(row.severity)}`}>
            {row.severity}
          </span>
          {row.kev && <span className="badge kev">KEV</span>}
          {row.ransomware === 'Known' && (
            <span className="badge ransom">Ransomware</span>
          )}
          <span className={`badge status ${st.cls}`}>{st.label}</span>
        </div>
        <div className="finding-metrics">
          <div className="metric-mini">
            <span className="mm-label">CVSS</span>
            <span className="mm-value">{row.cvss ?? '-'}</span>
          </div>
          <div className="metric-mini">
            <span className="mm-label">EPSS</span>
            <span className="mm-value">{(row.epss * 100).toFixed(1)}%</span>
          </div>
          <div className="metric-mini trust">
            <span className="mm-label">Trust</span>
            <span className={`mm-value ${trustClass(row.trust_score)}`}>
              {row.trust_score}%
            </span>
          </div>
        </div>
        <span className={`chevron ${open ? 'open' : ''}`}>⌄</span>
      </button>

      <div className="trust-bar-track">
        <div
          className={`trust-bar-fill ${trustClass(row.trust_score)}`}
          style={{ width: `${row.trust_score}%` }}
        />
      </div>

      {open && (
        <div className="finding-body">
          <div className="fb-grid">
            <div className="fb-section">
              <h4>Risk summary</h4>
              <p>{row.risk_summary}</p>
            </div>
            <div className="fb-section">
              <h4>Recommended mitigation</h4>
              <p>{row.mitigation}</p>
            </div>
          </div>

          <div className="fb-meta">
            {row.weakness && (
              <span className="fb-chip">
                Weakness: {row.weakness}
                {row.weakness_id ? ` (${row.weakness_id})` : ''}
              </span>
            )}
            <span className="fb-chip">Asset: {row.affected_asset}</span>
            {row.vendor && <span className="fb-chip">Vendor: {row.vendor}</span>}
            <span className="fb-chip">EPSS pct: {(row.epss_percentile * 100).toFixed(0)}%</span>
          </div>

          {row.description && (
            <div className="fb-section">
              <h4>Technical description</h4>
              <p className="fb-desc">{row.description}</p>
            </div>
          )}

          <div className="fb-links">
            <h4>CVE documentation &amp; references</h4>
            <div className="fb-link-row">
              <a href={row.cve_url} target="_blank" rel="noreferrer" className="doc-link primary">
                NVD full detail ↗
              </a>
              <a href={row.mitre_url} target="_blank" rel="noreferrer" className="doc-link">
                MITRE record ↗
              </a>
              {row.references.map((ref) => (
                <a
                  key={ref.url}
                  href={ref.url}
                  target="_blank"
                  rel="noreferrer"
                  className="doc-link ref"
                >
                  {ref.label} ↗
                </a>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export function Analyzer({
  assets,
  onAssetsChange,
  onAnalyze,
  onSample,
  onLoadSampleText,
  loading,
  result,
}: Props) {
  const [filter, setFilter] = useState<FilterKey>('all');
  const [search, setSearch] = useState('');
  const [limit, setLimit] = useState(40);
  const [exporting, setExporting] = useState(false);

  const rows = result?.results ?? [];

  const filtered = useMemo(() => {
    const q = search.trim().toUpperCase();
    return rows.filter((r) => {
      if (filter === 'confirmed' && r.status !== 'confirmed') return false;
      if (filter === 'review' && r.status !== 'review') return false;
      if (filter === 'false_positive' && r.status !== 'false_positive') return false;
      if (filter === 'kev' && !r.kev) return false;
      if (filter === 'critical' && r.severity !== 'Critical') return false;
      if (q) {
        const hay = `${r.cve_id} ${r.affected_asset} ${r.weakness ?? ''}`.toUpperCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [rows, filter, search]);

  const visible = filtered.slice(0, limit);

  const handleExport = async () => {
    setExporting(true);
    try {
      await exportCsv(assets || '');
    } catch {
      /* ignore */
    } finally {
      setExporting(false);
    }
  };

  const s = result?.summary;

  return (
    <div className="analyzer tab-panel">
      <div className="analyzer-input-bar panel">
        <div className="aib-left">
          <h2>Software stack input</h2>
          <p className="nexus-section-desc" style={{ margin: '0.25rem 0 0.75rem' }}>
            One product per line. Format: <code>Product Name | Version</code>
          </p>
          <textarea
            className="assets-input"
            value={assets}
            onChange={(e) => onAssetsChange(e.target.value)}
            placeholder="Microsoft 365 Apps for Business | Current&#10;Windows Server 2022 | 21H2&#10;Google Chrome | Latest"
          />
        </div>
        <div className="aib-actions">
          <button className="btn" onClick={onAnalyze} disabled={loading}>
            {loading ? 'Analyzing…' : 'Analyze my stack'}
          </button>
          <button className="btn secondary" onClick={onSample} disabled={loading}>
            Run hackathon sample
          </button>
          <button className="btn secondary" onClick={onLoadSampleText}>
            Load sample text
          </button>
          {rows.length > 0 && (
            <button className="btn secondary" onClick={handleExport} disabled={exporting}>
              {exporting ? 'Exporting…' : 'Export CSV'}
            </button>
          )}
          {result?.failed_assets && result.failed_assets.length > 0 && (
            <div className="aib-failed">
              Unmatched: {result.failed_assets.map((f) => f.name).join(', ')}
            </div>
          )}
        </div>
      </div>

      {loading && (
        <div className="loading">
          <div className="loading-spinner" />
          <p>Matching CVEs against NVD + EPSS + KEV…</p>
        </div>
      )}

      {!loading && result?.error && <div className="error-box">{result.error}</div>}

      {!loading && result?.success && s && (
        <>
          <div className="analyzer-kpis">
            <div className="kpi">
              <span className="kpi-label">Total findings</span>
              <span className="kpi-value">{s.matched_cves.toLocaleString()}</span>
            </div>
            <div className="kpi confirmed">
              <span className="kpi-label">Confirmed</span>
              <span className="kpi-value">{s.confirmed_count.toLocaleString()}</span>
            </div>
            <div className="kpi review">
              <span className="kpi-label">Needs review</span>
              <span className="kpi-value">{s.review_count.toLocaleString()}</span>
            </div>
            <div className="kpi false">
              <span className="kpi-label">Likely false positive</span>
              <span className="kpi-value">{s.false_positive_count.toLocaleString()}</span>
            </div>
            <div className="kpi kev">
              <span className="kpi-label">Actively exploited (KEV)</span>
              <span className="kpi-value">{s.kev_count.toLocaleString()}</span>
            </div>
            <div className="kpi critical">
              <span className="kpi-label">Critical</span>
              <span className="kpi-value">{s.critical_cvss_count.toLocaleString()}</span>
            </div>
          </div>

          <div className="analyzer-toolbar">
            <div className="filter-chips">
              {([
                ['all', 'All'],
                ['confirmed', 'Confirmed'],
                ['review', 'Needs review'],
                ['false_positive', 'False positive'],
                ['kev', 'KEV'],
                ['critical', 'Critical'],
              ] as [FilterKey, string][]).map(([key, label]) => (
                <button
                  key={key}
                  type="button"
                  className={`chip ${filter === key ? 'active' : ''}`}
                  onClick={() => {
                    setFilter(key);
                    setLimit(40);
                  }}
                >
                  {label}
                </button>
              ))}
            </div>
            <input
              className="finding-search"
              placeholder="Search CVE, asset, or weakness…"
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setLimit(40);
              }}
            />
          </div>

          <div className="findings-list">
            {visible.length === 0 ? (
              <p className="nexus-feed-empty">No findings match this filter.</p>
            ) : (
              visible.map((row) => <FindingCard key={`${row.cve_id}-${row.affected_asset}`} row={row} />)
            )}
          </div>

          {filtered.length > limit && (
            <div style={{ textAlign: 'center', marginTop: '1rem' }}>
              <button className="btn secondary" onClick={() => setLimit((l) => l + 40)}>
                Show more ({filtered.length - limit} remaining)
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  Cell,
  CartesianGrid,
  Pie,
  PieChart,
  PolarAngleAxis,
  RadialBar,
  RadialBarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type {
  NexusData,
  NexusStreamData,
  StreamConfirmed,
  StreamInput,
} from '../api';
import { useSmoothNumber } from '../hooks/useSmoothNumber';
import { WorldMap, type MapRow } from './WorldMap';

const SECTOR_COLORS: Record<string, string> = {
  academic: '#a78bfa',
  social_organization: '#06d6a0',
  small_business: '#ffb703',
  enterprise: '#7c5cff',
};

const SEVERITY_COLORS: Record<string, string> = {
  Critical: '#ff5c7c',
  High: '#ff9f43',
  Medium: '#ffd23f',
  Low: '#4cc9f0',
  Unscored: '#6b7280',
};

const SEVERITY_GRAD: Record<string, [string, string]> = {
  Critical: ['#ff7a93', '#e11d48'],
  High: ['#ffb168', '#f97316'],
  Medium: ['#ffe16b', '#eab308'],
  Low: ['#5ad7ff', '#0ea5e9'],
  Unscored: ['#9aa3c7', '#5b6488'],
};

const GRADIENTS: { id: string; from: string; to: string }[] = [
  { id: 'g-violet', from: '#a78bff', to: '#5a3fd4' },
  { id: 'g-cyan', from: '#22e0c8', to: '#0e7490' },
  { id: 'g-blue', from: '#5aa9ff', to: '#2563eb' },
  { id: 'g-amber', from: '#ffd66b', to: '#f59e0b' },
  { id: 'g-pink', from: '#ff6bd0', to: '#b5179e' },
  { id: 'g-green', from: '#4ade80', to: '#059669' },
];

const BAR_GRADS = GRADIENTS.map((g) => `url(#${g.id})`);

const CHART_TOOLTIP = {
  contentStyle: {
    background: 'rgba(13, 15, 32, 0.96)',
    border: '1px solid rgba(124, 92, 255, 0.35)',
    borderRadius: '12px',
    boxShadow: '0 10px 34px rgba(0, 0, 0, 0.5)',
    padding: '10px 12px',
    backdropFilter: 'blur(10px)',
  },
  labelStyle: { color: '#e8e9f3', fontWeight: 600, marginBottom: 4 },
  itemStyle: { color: '#c9cce4' },
};

const GRID = {
  strokeDasharray: '2 5',
  stroke: 'rgba(148, 152, 184, 0.12)',
  vertical: false,
};

const NUM_AXIS = {
  stroke: 'rgba(148, 152, 184, 0.25)',
  tickLine: false,
  axisLine: false,
  tick: { fontSize: 11, fill: '#9498b8' },
};

const CAT_AXIS = {
  tickLine: false,
  axisLine: false,
  tick: { fontSize: 10, fill: '#9498b8' },
};

function ChartDefs() {
  return (
    <defs>
      {GRADIENTS.map((g) => (
        <linearGradient key={g.id} id={g.id} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor={g.from} />
          <stop offset="100%" stopColor={g.to} />
        </linearGradient>
      ))}
      {Object.entries(SEVERITY_GRAD).map(([k, [a, b]]) => (
        <linearGradient key={k} id={`gs-${k}`} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor={a} />
          <stop offset="100%" stopColor={b} />
        </linearGradient>
      ))}
      <linearGradient id="g-area" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stopColor="#7c5cff" stopOpacity={0.55} />
        <stop offset="100%" stopColor="#7c5cff" stopOpacity={0.02} />
      </linearGradient>
      <linearGradient id="g-kev" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0%" stopColor="#ff7a93" stopOpacity={0.9} />
        <stop offset="100%" stopColor="#e11d48" stopOpacity={0.9} />
      </linearGradient>
    </defs>
  );
}

function SeverityDonut({
  data,
  height = 240,
}: {
  data: { name: string; value: number }[];
  height?: number;
}) {
  const total = data.reduce((s, d) => s + d.value, 0);
  return (
    <>
      <div className="chart-wrap donut-wrap" style={{ height }}>
        <ResponsiveContainer>
          <PieChart>
            <ChartDefs />
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              innerRadius="62%"
              outerRadius="92%"
              paddingAngle={2}
              cornerRadius={6}
              stroke="none"
              animationDuration={800}
            >
              {data.map((d) => (
                <Cell key={d.name} fill={`url(#gs-${d.name})`} />
              ))}
            </Pie>
            <Tooltip {...CHART_TOOLTIP} />
          </PieChart>
        </ResponsiveContainer>
        <div className="donut-center">
          <span className="donut-total">{total.toLocaleString()}</span>
          <span className="donut-sub">findings</span>
        </div>
      </div>
      <div className="chart-legend">
        {data.map((d) => (
          <span key={d.name}>
            <i style={{ background: SEVERITY_COLORS[d.name] }} />
            {d.name} · {d.value.toLocaleString()}
          </span>
        ))}
      </div>
    </>
  );
}

function Gauge({
  percent,
  display,
  sub,
  color,
  gradId,
}: {
  percent: number;
  display: string;
  sub: string;
  color: string;
  gradId: string;
}) {
  const pct = Math.max(0, Math.min(100, percent));
  return (
    <div className="gauge-wrap">
      <ResponsiveContainer width="100%" height={170}>
        <RadialBarChart
          innerRadius="72%"
          outerRadius="100%"
          data={[{ value: pct }]}
          startAngle={220}
          endAngle={-40}
        >
          <defs>
            <linearGradient id={gradId} x1="0" y1="0" x2="1" y2="1">
              <stop offset="0%" stopColor="#7c5cff" />
              <stop offset="100%" stopColor={color} />
            </linearGradient>
          </defs>
          <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
          <RadialBar
            background={{ fill: 'rgba(148,152,184,0.12)' }}
            dataKey="value"
            cornerRadius={12}
            fill={`url(#${gradId})`}
            animationDuration={900}
          />
        </RadialBarChart>
      </ResponsiveContainer>
      <div className="gauge-center">
        <span className="gauge-value" style={{ color }}>
          {display}
        </span>
        <span className="gauge-sub">{sub}</span>
      </div>
    </div>
  );
}

interface Props {
  data: NexusData;
  view: string;
}

function KpiCard({
  label,
  value,
  accent,
  sub,
}: {
  label: string;
  value: number;
  accent: string;
  sub?: string;
}) {
  const smooth = useSmoothNumber(value, 600);
  return (
    <div className="kpi-card" style={{ ['--accent' as string]: accent }}>
      <div className="kpi-label">{label}</div>
      <div className="kpi-value">{Math.round(smooth).toLocaleString()}</div>
      {sub && <div className="kpi-sub">{sub}</div>}
    </div>
  );
}

function Section({
  id,
  children,
}: {
  id: string;
  title?: string;
  desc?: string;
  children: ReactNode;
}) {
  return (
    <section id={id} className="nexus-section anchor">
      {children}
    </section>
  );
}

function LiveMetric({
  label,
  value,
  unit,
  pulse,
  numeric,
}: {
  label: string;
  value: string | number;
  unit?: string;
  pulse?: boolean;
  numeric?: number;
}) {
  const smooth = useSmoothNumber(numeric ?? 0, 500);
  const display =
    numeric !== undefined
      ? numeric < 1
        ? smooth.toFixed(3)
        : Math.round(smooth).toLocaleString()
      : value;
  return (
    <div className={`nexus-metric ${pulse ? 'pulse' : ''}`}>
      <div className="nexus-metric-label">{label}</div>
      <div className="nexus-metric-value">
        {display}
        {unit && <span className="nexus-metric-unit">{unit}</span>}
      </div>
    </div>
  );
}

function FeedList<T extends { id?: string; cve_id?: string }>({
  title,
  items,
  render,
  variant,
  newIds,
}: {
  title: string;
  items: T[];
  render: (item: T) => ReactNode;
  variant: 'incoming' | 'confirmed';
  newIds: Set<string>;
}) {
  const listRef = useRef<HTMLDivElement>(null);
  const prevLen = useRef(items.length);
  useEffect(() => {
    if (items.length > prevLen.current && listRef.current) {
      listRef.current.scrollTo({ top: 0, behavior: 'smooth' });
    }
    prevLen.current = items.length;
  }, [items.length]);

  const getKey = (item: T) => item.cve_id || item.id || '';

  return (
    <div className={`nexus-feed nexus-feed-${variant}`}>
      <div className="nexus-feed-header">
        <span className={`nexus-feed-dot ${variant}`} />
        {title}
        <span className="nexus-feed-count">{items.length}</span>
      </div>
      <div className="nexus-feed-list" ref={listRef}>
        {items.length === 0 ? (
          <div className="nexus-feed-empty">Waiting for data…</div>
        ) : (
          items.map((item) => {
            const key = getKey(item);
            const isNew = newIds.has(key);
            return (
              <div key={key} className={`nexus-feed-item${isNew ? ' is-new' : ''}`}>
                {render(item)}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

export function Nexus({ data, view }: Props) {
  const [stream, setStream] = useState<NexusStreamData | null>(null);
  const [incoming, setIncoming] = useState<StreamInput[]>([]);
  const [confirmed, setConfirmed] = useState<StreamConfirmed[]>([]);
  const [displayRate, setDisplayRate] = useState(data.ingestion.inputs_per_second);
  const [newIncomingIds, setNewIncomingIds] = useState<Set<string>>(new Set());
  const [newConfirmedIds, setNewConfirmedIds] = useState<Set<string>>(new Set());
  const seenIncoming = useRef(new Set<string>());
  const seenConfirmed = useRef(new Set<string>());

  const markNew = useCallback(
    (ids: string[], setter: React.Dispatch<React.SetStateAction<Set<string>>>) => {
      if (!ids.length) return;
      setter(new Set(ids));
      const t = setTimeout(() => setter(new Set()), 1200);
      return () => clearTimeout(t);
    },
    []
  );

  useEffect(() => {
    let mounted = true;
    let cleanupNew: (() => void) | undefined;

    const poll = async () => {
      try {
        const r = await fetch('/api/nexus/stream?batch=4');
        const batch: NexusStreamData = await r.json();
        if (!mounted) return;
        setStream(batch);
        setDisplayRate(batch.inputs_per_second);

        const freshIncoming: string[] = [];
        const freshConfirmed: string[] = [];

        if (batch.new_inputs.length) {
          setIncoming((prev) => {
            const next = [...batch.new_inputs];
            for (const p of prev) {
              if (!next.some((n) => n.id === p.id) && next.length < 60) next.push(p);
            }
            return next.slice(0, 60);
          });
          for (const p of batch.new_inputs) {
            if (!seenIncoming.current.has(p.id)) {
              seenIncoming.current.add(p.id);
              freshIncoming.push(p.id);
            }
          }
        }

        if (batch.confirmed_updates.length) {
          setConfirmed((prev) => dedupe([...batch.confirmed_updates, ...prev]));
          for (const c of batch.confirmed_updates) {
            if (!seenConfirmed.current.has(c.cve_id)) {
              seenConfirmed.current.add(c.cve_id);
              freshConfirmed.push(c.cve_id);
            }
          }
        }

        if (freshIncoming.length) {
          cleanupNew?.();
          cleanupNew = markNew(freshIncoming, setNewIncomingIds);
        }
        if (freshConfirmed.length) markNew(freshConfirmed, setNewConfirmedIds);
      } catch {
        /* ignore */
      }
    };

    poll();
    const id = setInterval(poll, 3500);
    return () => {
      mounted = false;
      clearInterval(id);
      cleanupNew?.();
    };
  }, [markNew]);

  const smoothRate = useSmoothNumber(displayRate, 700);
  const s = data.summary;
  const empty = s.total_cves === 0;
  const mapRows: MapRow[] = data.by_country.map((c) => ({
    country: c.country,
    value: c.vulnerabilities,
    kev: c.kev_exploited,
  }));

  const PAGE_TITLES: Record<string, { title: string; desc: string }> = {
    'sec-overview': {
      title: 'Overview',
      desc: 'The headline numbers and the most important analytics at a glance.',
    },
    'sec-live': {
      title: 'Live feed',
      desc: 'Real-time ingestion of NVD disclosures and confirmed CISA KEV exploitations.',
    },
    'sec-threats': {
      title: 'Threat analysis',
      desc: 'Severity, weakness categories, exploitation likelihood and disclosure trend.',
    },
    'sec-geo': {
      title: 'Geographic exposure',
      desc: 'Most affected countries and where vulnerable software originates.',
    },
    'sec-industries': {
      title: 'Industry exposure',
      desc: 'Vulnerabilities mapped to industry sectors via vendor and product classification.',
    },
    'sec-sectors': {
      title: 'Organization sectors',
      desc: 'Academic, social organizations, small business and enterprise breakdown.',
    },
    'sec-vendors': {
      title: 'Vendor exposure',
      desc: 'Vendors carrying the most disclosed and most actively exploited vulnerabilities.',
    },
    'sec-exploits': {
      title: 'Confirmed exploits',
      desc: 'Vulnerabilities with confirmed real-world exploitation (CISA KEV).',
    },
  };
  const page = PAGE_TITLES[view] ?? PAGE_TITLES['sec-overview'];

  return (
    <div className="nexus">
      <div className="nexus-page-head">
        <h2>{page.title}</h2>
        <p>{page.desc}</p>
      </div>

      <div className="view-anim" key={view}>
      {/* OVERVIEW */}
      {view === 'sec-overview' && (
      <section id="sec-overview" className="anchor nexus-overview">
        <div className="kpi-grid">
          <KpiCard
            label="Vulnerabilities in view"
            value={s.total_cves}
            accent="#7c5cff"
            sub={`of ${s.grand_total_cves.toLocaleString()} total`}
          />
          <KpiCard
            label="Actively exploited (KEV)"
            value={s.total_kev}
            accent="#ff5c7c"
            sub="CISA confirmed"
          />
          <KpiCard label="Critical" value={s.critical} accent="#ff9f43" sub="CVSS 9.0+" />
          <KpiCard label="High" value={s.high} accent="#ffd23f" sub="CVSS 7.0-8.9" />
          <KpiCard
            label="Avg CVSS"
            value={Math.round(s.avg_cvss)}
            accent="#06d6a0"
            sub={`exact ${s.avg_cvss}`}
          />
          <KpiCard
            label="Industries"
            value={s.industries_tracked}
            accent="#4cc9f0"
            sub={`${s.countries_tracked} countries`}
          />
        </div>
        {empty && (
          <div className="nexus-empty-banner">
            No vulnerabilities match the current filters. Try clearing or widening them.
          </div>
        )}

        <div className="chart-grid-3" style={{ marginTop: '1.25rem' }}>
          <div className="chart-card">
            <h3>Severity distribution</h3>
            <SeverityDonut data={data.severity_distribution} height={210} />
          </div>

          <div className="chart-card">
            <h3>Average risk level</h3>
            <Gauge
              percent={(s.avg_cvss / 10) * 100}
              display={s.avg_cvss.toFixed(1)}
              sub="avg CVSS / 10"
              color={
                s.avg_cvss >= 9
                  ? '#ff5c7c'
                  : s.avg_cvss >= 7
                    ? '#ff9f43'
                    : s.avg_cvss >= 4
                      ? '#ffd23f'
                      : '#4cc9f0'
              }
              gradId="g-gauge-cvss"
            />
            <div className="gauge-foot">
              <span>
                <em>{s.critical.toLocaleString()}</em> critical
              </span>
              <span>
                <em>{s.high.toLocaleString()}</em> high
              </span>
            </div>
          </div>

          <div className="chart-card">
            <h3>Severe findings share</h3>
            <Gauge
              percent={((s.critical + s.high) / Math.max(1, s.total_cves)) * 100}
              display={`${(((s.critical + s.high) / Math.max(1, s.total_cves)) * 100).toFixed(0)}%`}
              sub="critical + high"
              color="#f72585"
              gradId="g-gauge-sev"
            />
            <div className="gauge-foot">
              <span>
                <em>{s.total_kev.toLocaleString()}</em> actively exploited
              </span>
            </div>
          </div>
        </div>

        <div className="chart-card worldmap-card" style={{ marginTop: '1.25rem' }}>
          <h3>Global threat map</h3>
          <WorldMap data={mapRows} height={340} />
        </div>

        <div className="chart-card">
          <h3>Highest-urgency vulnerabilities</h3>
          <div className="table-wrap" style={{ maxHeight: 300 }}>
            <table>
              <thead>
                <tr>
                  <th>CVE</th>
                  <th>Type</th>
                  <th>Vendor</th>
                  <th>CVSS</th>
                  <th>EPSS</th>
                  <th>KEV</th>
                </tr>
              </thead>
              <tbody>
                {data.top_threats.slice(0, 10).map((t) => (
                  <tr key={t.cve_id}>
                    <td>
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${t.cve_id}`}
                        target="_blank"
                        rel="noreferrer"
                        className="cve-link"
                      >
                        {t.cve_id}
                      </a>
                    </td>
                    <td>{t.threat_type}</td>
                    <td>{t.vendor}</td>
                    <td>{t.cvss ?? '-'}</td>
                    <td>{(t.epss * 100).toFixed(1)}%</td>
                    <td>{t.kev ? <span className="badge kev">KEV</span> : '-'}</td>
                  </tr>
                ))}
                {data.top_threats.length === 0 && (
                  <tr>
                    <td colSpan={6} className="nexus-feed-empty">
                      No high-urgency items in this selection.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </section>
      )}

      {/* LIVE FEED */}
      {view === 'sec-live' && (
      <section id="sec-live" className="anchor nexus-live-panel">
        <div className="nexus-live-header">
          <h2>Live ingestion</h2>
          <span className="nexus-live-badge">Real NVD · KEV · EPSS</span>
        </div>
        <div className="nexus-metrics-row">
          <LiveMetric
            label="Inputs / second"
            value={smoothRate.toFixed(3)}
            unit="/s"
            pulse
            numeric={displayRate}
          />
          <LiveMetric label="Processed" value={0} numeric={stream?.total_processed ?? 0} />
          <LiveMetric
            label="Awaiting in queue"
            value={0}
            numeric={stream?.pending_count ?? 0}
          />
          <LiveMetric label="Confirmed (KEV)" value={0} numeric={confirmed.length} />
          <LiveMetric label="Total CVEs" value={0} numeric={data.summary.grand_total_cves} />
        </div>
        <div className="nexus-feeds-grid">
          <FeedList
            title="Incoming vulnerability inputs"
            variant="incoming"
            items={incoming}
            newIds={newIncomingIds}
            render={(item) => (
              <>
                <div className="nexus-feed-row-top">
                  <strong>{item.id}</strong>
                  <span
                    className={`badge ${item.status === 'confirmed' ? 'kev' : 'pending'}`}
                  >
                    {item.status}
                  </span>
                </div>
                <div className="nexus-feed-meta">
                  <span>{item.vuln_type}</span>
                  <span>CVSS {item.cvss ?? '-'}</span>
                  <span>{item.source}</span>
                </div>
                <div className="nexus-feed-location">
                  {item.city}, {item.country} · {item.vendor}
                </div>
                <div className="nexus-feed-desc">{item.description}</div>
                <div className="nexus-feed-time">{item.timestamp}</div>
              </>
            )}
          />
          <FeedList
            title="Confirmed exploitations (CISA KEV)"
            variant="confirmed"
            items={confirmed}
            newIds={newConfirmedIds}
            render={(item) => (
              <>
                <div className="nexus-feed-row-top">
                  <strong>{item.cve_id}</strong>
                  <span className="badge kev">confirmed</span>
                </div>
                <div className="nexus-feed-meta">
                  <span>{item.vuln_type}</span>
                  <span>{item.vendor}</span>
                  {item.product && <span>{item.product}</span>}
                </div>
                <div className="nexus-feed-location">{item.location_label}</div>
                <div className="nexus-feed-desc">{item.description}</div>
                {item.date_added && (
                  <div className="nexus-feed-time">Added {item.date_added}</div>
                )}
              </>
            )}
          />
        </div>
      </section>
      )}

      {/* THREAT ANALYSIS */}
      {view === 'sec-threats' && (
      <Section
        id="sec-threats"
        title="Threat analysis"
        desc="Severity, weakness categories, exploitation likelihood and trend over time for the current selection."
      >
        <div className="chart-grid-2">
          <div className="chart-card">
            <h3>Severity distribution</h3>
            <SeverityDonut data={data.severity_distribution} height={240} />
          </div>

          <div className="chart-card">
            <h3>Top weakness categories</h3>
            <div className="chart-wrap" style={{ height: 300 }}>
              <ResponsiveContainer>
                <BarChart
                  data={data.threat_type_distribution}
                  layout="vertical"
                  margin={{ left: 4, right: 16 }}
                >
                  <ChartDefs />
                  <CartesianGrid {...GRID} horizontal={false} vertical />
                  <XAxis type="number" {...NUM_AXIS} />
                  <YAxis type="category" dataKey="type" width={150} {...CAT_AXIS} />
                  <Tooltip {...CHART_TOOLTIP} cursor={{ fill: 'rgba(124,92,255,0.08)' }} />
                  <Bar dataKey="count" radius={[0, 8, 8, 0]} barSize={16} animationDuration={900}>
                    {data.threat_type_distribution.map((_, i) => (
                      <Cell key={i} fill={BAR_GRADS[i % BAR_GRADS.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        <div className="chart-grid-2">
          <div className="chart-card">
            <h3>Disclosure timeline</h3>
            <div className="chart-wrap" style={{ height: 220 }}>
              <ResponsiveContainer>
                <AreaChart data={data.cve_timeline} margin={{ left: 0, right: 12, top: 6 }}>
                  <ChartDefs />
                  <CartesianGrid {...GRID} />
                  <XAxis dataKey="month" {...NUM_AXIS} tick={{ fontSize: 10, fill: '#9498b8' }} />
                  <YAxis {...NUM_AXIS} />
                  <Tooltip {...CHART_TOOLTIP} />
                  <Area
                    type="monotone"
                    dataKey="count"
                    stroke="#a78bff"
                    strokeWidth={2.5}
                    fill="url(#g-area)"
                    dot={false}
                    activeDot={{ r: 4, fill: '#a78bff', stroke: '#0c0c1a', strokeWidth: 2 }}
                    animationDuration={900}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="chart-card">
            <h3>Exploitation likelihood (EPSS)</h3>
            <div className="chart-wrap" style={{ height: 220 }}>
              <ResponsiveContainer>
                <BarChart data={data.epss_distribution} margin={{ top: 6 }}>
                  <ChartDefs />
                  <CartesianGrid {...GRID} />
                  <XAxis
                    dataKey="bucket"
                    {...CAT_AXIS}
                    tick={{ fontSize: 9, fill: '#9498b8' }}
                    interval={0}
                    angle={-12}
                    textAnchor="end"
                    height={50}
                  />
                  <YAxis {...NUM_AXIS} />
                  <Tooltip {...CHART_TOOLTIP} cursor={{ fill: 'rgba(6,214,160,0.08)' }} />
                  <Bar dataKey="count" radius={[8, 8, 0, 0]} barSize={34} animationDuration={900}>
                    {data.epss_distribution.map((_, i) => (
                      <Cell
                        key={i}
                        fill={
                          [
                            'url(#g-cyan)',
                            'url(#g-green)',
                            'url(#g-amber)',
                            'url(#g-violet)',
                            'url(#gs-Critical)',
                          ][i] || 'url(#g-violet)'
                        }
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        <div className="chart-card">
          <h3>Highest-urgency vulnerabilities</h3>
          <div className="table-wrap" style={{ maxHeight: 320 }}>
            <table>
              <thead>
                <tr>
                  <th>CVE</th>
                  <th>Type</th>
                  <th>Vendor</th>
                  <th>Country</th>
                  <th>CVSS</th>
                  <th>EPSS</th>
                  <th>KEV</th>
                </tr>
              </thead>
              <tbody>
                {data.top_threats.map((t) => (
                  <tr key={t.cve_id}>
                    <td>
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${t.cve_id}`}
                        target="_blank"
                        rel="noreferrer"
                        className="cve-link"
                      >
                        {t.cve_id}
                      </a>
                    </td>
                    <td>{t.threat_type}</td>
                    <td>{t.vendor}</td>
                    <td>{t.country}</td>
                    <td>{t.cvss ?? '-'}</td>
                    <td>{(t.epss * 100).toFixed(1)}%</td>
                    <td>{t.kev ? <span className="badge kev">KEV</span> : '-'}</td>
                  </tr>
                ))}
                {data.top_threats.length === 0 && (
                  <tr>
                    <td colSpan={7} className="nexus-feed-empty">
                      No high-urgency items in this selection.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </Section>
      )}

      {/* GEOGRAPHIC */}
      {view === 'sec-geo' && (
      <Section
        id="sec-geo"
        title="Geographic exposure"
        desc="Most affected countries (by vendor headquarters in NVD CPE) and the dominant weakness types per region."
      >
        <div className="chart-card worldmap-card">
          <h3>Global threat map</h3>
          <p className="worldmap-hint">
            Color intensity reflects tracked vulnerabilities per country. Scroll to
            zoom, drag to pan, hover a country for detail.
          </p>
          <WorldMap data={mapRows} height={480} />
        </div>

        <div className="chart-card">
          <h3>Most affected countries</h3>
          <div className="ranked-bars">
            {data.by_country.slice(0, 12).map((c, i) => {
              const max = data.by_country[0]?.vulnerabilities || 1;
              return (
                <div key={c.country} className="ranked-bar-row">
                  <span className="ranked-bar-rank">{i + 1}</span>
                  <span className="ranked-bar-name">{c.country}</span>
                  <div className="ranked-bar-track">
                    <div
                      className="ranked-bar-fill"
                      style={{ width: `${(c.vulnerabilities / max) * 100}%` }}
                    />
                  </div>
                  <span className="ranked-bar-value">
                    {c.vulnerabilities.toLocaleString()}
                    {c.kev_exploited > 0 && (
                      <em className="ranked-bar-kev"> · {c.kev_exploited} KEV</em>
                    )}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        <div className="nexus-country-grid">
          {data.country_vulnerability_matrix.map((row, i) => (
            <div
              key={row.country}
              className="nexus-country-card"
              style={{ animationDelay: `${i * 0.04}s` }}
            >
              <div className="nexus-country-card-header">
                <h3>{row.country}</h3>
                <span className="nexus-total">{row.total.toLocaleString()} CVEs</span>
              </div>
              <table className="nexus-mini-table">
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Count</th>
                    <th>%</th>
                  </tr>
                </thead>
                <tbody>
                  {row.top_vulnerability_types.map((t) => (
                    <tr key={t.type}>
                      <td>{t.type}</td>
                      <td>{t.count.toLocaleString()}</td>
                      <td>{t.percent ?? '-'}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
        </div>

        <div className="chart-card">
          <h3>Where vulnerabilities originate</h3>
          <div className="table-wrap" style={{ maxHeight: 340 }}>
            <table>
              <thead>
                <tr>
                  <th>Location</th>
                  <th>Vendor</th>
                  <th>CVEs</th>
                  <th>KEV</th>
                  <th>Top types</th>
                </tr>
              </thead>
              <tbody>
                {data.locations.map((loc) => (
                  <tr key={loc.location_label + loc.vendor}>
                    <td>
                      <strong>{loc.location_label}</strong>
                      <div className="nexus-sub">{loc.region}</div>
                    </td>
                    <td>{loc.vendor}</td>
                    <td>{loc.cve_count.toLocaleString()}</td>
                    <td>
                      {loc.kev_count > 0 ? (
                        <span className="badge kev">{loc.kev_count}</span>
                      ) : (
                        '0'
                      )}
                    </td>
                    <td>
                      {loc.top_vulnerability_types
                        .map((t) => `${t.type} (${t.count})`)
                        .join(' · ')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </Section>
      )}

      {/* INDUSTRIES */}
      {view === 'sec-industries' && (
      <Section
        id="sec-industries"
        title="Industry exposure"
        desc="Vulnerabilities mapped to industry sectors via vendor and product classification (Healthcare, Finance, Retail, Government and more)."
      >
        <div className="chart-card">
          <h3>Vulnerabilities by industry</h3>
          <div className="chart-wrap" style={{ height: 380 }}>
            <ResponsiveContainer>
              <BarChart
                data={data.industry_distribution}
                layout="vertical"
                margin={{ left: 4, right: 16 }}
              >
                <ChartDefs />
                <CartesianGrid {...GRID} horizontal={false} vertical />
                <XAxis type="number" {...NUM_AXIS} />
                <YAxis type="category" dataKey="industry" width={170} {...CAT_AXIS} />
                <Tooltip {...CHART_TOOLTIP} cursor={{ fill: 'rgba(124,92,255,0.08)' }} />
                <Bar
                  dataKey="count"
                  name="Vulnerabilities"
                  radius={[0, 8, 8, 0]}
                  barSize={15}
                  animationDuration={900}
                >
                  {data.industry_distribution.map((_, i) => (
                    <Cell key={i} fill={BAR_GRADS[i % BAR_GRADS.length]} />
                  ))}
                </Bar>
                <Bar
                  dataKey="kev"
                  name="KEV exploited"
                  fill="url(#g-kev)"
                  radius={[0, 8, 8, 0]}
                  barSize={15}
                  animationDuration={900}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </Section>
      )}

      {/* ORG SECTORS */}
      {view === 'sec-sectors' && (
      <Section
        id="sec-sectors"
        title="Organization sector breakdown"
        desc="Academic · Social orgs · Small business · Enterprise"
      >
        <div className="nexus-sectors-grid">
          {data.org_sectors.map((sector) => (
            <div
              key={sector.sector_id}
              className="nexus-sector-card"
              style={{ borderColor: SECTOR_COLORS[sector.sector_id] || '#7c5cff' }}
            >
              <h3 style={{ color: SECTOR_COLORS[sector.sector_id] }}>{sector.label}</h3>
              <div className="nexus-sector-stats">
                <div>
                  <span className="label">Vulnerabilities</span>
                  <span className="value">
                    {sector.total_vulnerabilities.toLocaleString()}
                  </span>
                </div>
                <div>
                  <span className="label">KEV exploited</span>
                  <span className="value kev">{sector.kev_exploited}</span>
                </div>
              </div>
              <div className="chart-wrap" style={{ height: 200 }}>
                <ResponsiveContainer>
                  <BarChart
                    data={sector.top_vulnerability_types.slice(0, 6)}
                    layout="vertical"
                    margin={{ left: 4, right: 12 }}
                  >
                    <CartesianGrid {...GRID} horizontal={false} vertical />
                    <XAxis type="number" {...NUM_AXIS} />
                    <YAxis type="category" dataKey="type" width={130} {...CAT_AXIS} tick={{ fontSize: 9, fill: '#9498b8' }} />
                    <Tooltip {...CHART_TOOLTIP} cursor={{ fill: 'rgba(124,92,255,0.06)' }} />
                    <Bar
                      dataKey="count"
                      fill={SECTOR_COLORS[sector.sector_id] || '#7c5cff'}
                      radius={[0, 8, 8, 0]}
                      barSize={13}
                      animationDuration={900}
                    />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          ))}
        </div>
      </Section>
      )}

      {/* VENDORS */}
      {view === 'sec-vendors' && (
      <Section
        id="sec-vendors"
        title="Vendor exposure"
        desc="Vendors carrying the most disclosed vulnerabilities and the most actively exploited (KEV) products."
      >
        <div className="chart-grid-2">
          <div className="chart-card">
            <h3>Most affected vendors</h3>
            <div className="chart-wrap" style={{ height: 360 }}>
              <ResponsiveContainer>
                <BarChart data={data.top_vendors} layout="vertical" margin={{ left: 4, right: 16 }}>
                  <ChartDefs />
                  <CartesianGrid {...GRID} horizontal={false} vertical />
                  <XAxis type="number" {...NUM_AXIS} />
                  <YAxis type="category" dataKey="vendor" width={120} {...CAT_AXIS} />
                  <Tooltip {...CHART_TOOLTIP} cursor={{ fill: 'rgba(124,92,255,0.08)' }} />
                  <Bar dataKey="count" fill="url(#g-green)" radius={[0, 8, 8, 0]} barSize={15} animationDuration={900} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="chart-card">
            <h3>Actively exploited by vendor (KEV)</h3>
            <div className="chart-wrap" style={{ height: 360 }}>
              <ResponsiveContainer>
                <BarChart data={data.kev_by_vendor} layout="vertical" margin={{ left: 4, right: 16 }}>
                  <ChartDefs />
                  <CartesianGrid {...GRID} horizontal={false} vertical />
                  <XAxis type="number" {...NUM_AXIS} />
                  <YAxis type="category" dataKey="vendor" width={120} {...CAT_AXIS} />
                  <Tooltip {...CHART_TOOLTIP} cursor={{ fill: 'rgba(255,92,124,0.08)' }} />
                  <Bar dataKey="count" fill="url(#g-kev)" radius={[0, 8, 8, 0]} barSize={15} animationDuration={900} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      </Section>
      )}

      {/* CONFIRMED EXPLOITS */}
      {view === 'sec-exploits' && (
      <Section
        id="sec-exploits"
        title="Confirmed attacks (CISA KEV)"
        desc="Vulnerabilities with confirmed real-world exploitation, filtered to your current selection."
      >
        <div className="chart-card">
        <div className="table-wrap" style={{ maxHeight: 460 }}>
          <table>
            <thead>
              <tr>
                <th>CVE</th>
                <th>Industry</th>
                <th>Location</th>
                <th>Vendor / Product</th>
                <th>Date</th>
                <th>Ransomware</th>
              </tr>
            </thead>
            <tbody>
              {data.confirmed_feed.slice(0, 60).map((row) => (
                <tr key={row.cve_id}>
                  <td>
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${row.cve_id}`}
                      target="_blank"
                      rel="noreferrer"
                      className="cve-link"
                    >
                      {row.cve_id}
                    </a>
                  </td>
                  <td>{row.industry}</td>
                  <td>{row.location_label}</td>
                  <td>
                    {row.vendor} / {row.product}
                  </td>
                  <td>{row.date_added}</td>
                  <td>
                    <span
                      className={`badge ${row.ransomware === 'Known' ? 'kev' : ''}`}
                    >
                      {row.ransomware}
                    </span>
                  </td>
                </tr>
              ))}
              {data.confirmed_feed.length === 0 && (
                <tr>
                  <td colSpan={6} className="nexus-feed-empty">
                    No confirmed exploits match the current filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        </div>
      </Section>
      )}
      </div>
    </div>
  );
}

function dedupe(items: StreamConfirmed[]): StreamConfirmed[] {
  const seen = new Set<string>();
  return items
    .filter((x) => {
      if (seen.has(x.cve_id)) return false;
      seen.add(x.cve_id);
      return true;
    })
    .slice(0, 400);
}

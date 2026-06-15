import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  deleteConnector,
  fetchConnectorLive,
  fetchConnectors,
  saveConnector,
  testConnector,
  type ConnectorConfig,
  type ConnectorType,
  type LiveResult,
} from '../api';

const REFRESH_MS = 25000;

function relativeTime(iso: string | null): string {
  if (!iso) return '';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return iso;
  const diff = Date.now() - t;
  const mins = Math.round(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.round(hrs / 24)}d ago`;
}

interface FormState {
  open: boolean;
  type: string;
  values: Record<string, string>;
}

export function Connectors() {
  const [types, setTypes] = useState<ConnectorType[]>([]);
  const [connectors, setConnectors] = useState<ConnectorConfig[]>([]);
  const [selected, setSelected] = useState<string>('demo');
  const [live, setLive] = useState<LiveResult | null>(null);
  const [liveLoading, setLiveLoading] = useState(false);
  const [liveError, setLiveError] = useState<string | null>(null);
  const [testMsg, setTestMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [form, setForm] = useState<FormState>({ open: false, type: 'alienvault_otx', values: {} });
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const loadConnectors = useCallback(async () => {
    try {
      const data = await fetchConnectors();
      setTypes(data.types);
      setConnectors(data.connectors);
      setSelected((cur) =>
        data.connectors.some((c) => c.id === cur) ? cur : data.connectors[0]?.id ?? 'demo'
      );
    } catch {
      /* leave as-is */
    }
  }, []);

  useEffect(() => {
    // Load the connector list once on mount (async fetch, sets state on resolve).
    // eslint-disable-next-line react-hooks/set-state-in-effect
    loadConnectors();
  }, [loadConnectors]);

  const loadLive = useCallback(async (id: string) => {
    if (!id) return;
    setLiveLoading(true);
    setLiveError(null);
    try {
      const data = await fetchConnectorLive(id, true);
      setLive(data);
    } catch (e) {
      setLive(null);
      setLiveError(e instanceof Error ? e.message : 'Failed to fetch live data');
    } finally {
      setLiveLoading(false);
    }
  }, []);

  useEffect(() => {
    // Fetch live data whenever the selected connector changes.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    loadLive(selected);
  }, [selected, loadLive]);

  useEffect(() => {
    if (pollRef.current) clearInterval(pollRef.current);
    if (autoRefresh && selected) {
      pollRef.current = setInterval(() => loadLive(selected), REFRESH_MS);
    }
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [autoRefresh, selected, loadLive]);

  const selectedConfig = connectors.find((c) => c.id === selected);
  const activeType = useMemo(
    () => types.find((t) => t.id === form.type),
    [types, form.type]
  );

  const openAdd = () => {
    const t = types.find((x) => x.id !== 'demo') ?? types[0];
    const defaults: Record<string, string> = {};
    t?.fields.forEach((f) => {
      if (f.default !== undefined) defaults[f.key] = String(f.default);
    });
    setForm({ open: true, type: t?.id ?? 'alienvault_otx', values: defaults });
    setTestMsg(null);
  };

  const changeType = (typeId: string) => {
    const t = types.find((x) => x.id === typeId);
    const defaults: Record<string, string> = {};
    t?.fields.forEach((f) => {
      if (f.default !== undefined) defaults[f.key] = String(f.default);
    });
    setForm({ open: true, type: typeId, values: defaults });
  };

  const submitForm = async () => {
    setBusy(true);
    setTestMsg(null);
    try {
      const payload: Record<string, unknown> = {
        type: form.type,
        name: form.values.name,
        ...form.values,
      };
      const res = await saveConnector(payload);
      if (!res.success) {
        setTestMsg({ ok: false, text: res.error || 'Could not save connector' });
        return;
      }
      await loadConnectors();
      if (res.connector) setSelected(res.connector.id);
      setForm((f) => ({ ...f, open: false }));
    } finally {
      setBusy(false);
    }
  };

  const runTest = async (id: string) => {
    setBusy(true);
    setTestMsg(null);
    try {
      const res = await testConnector(id);
      setTestMsg({ ok: res.ok, text: res.message });
      if (res.ok) loadLive(id);
    } finally {
      setBusy(false);
    }
  };

  const removeConnector = async (id: string) => {
    setBusy(true);
    try {
      await deleteConnector(id);
      await loadConnectors();
    } finally {
      setBusy(false);
    }
  };

  const stats = live?.stats;

  return (
    <div className="connectors">
      <div className="connectors-bar">
        <div className="connectors-pills">
          {connectors.map((c) => (
            <button
              key={c.id}
              type="button"
              className={`conn-pill${selected === c.id ? ' active' : ''}`}
              onClick={() => setSelected(c.id)}
            >
              <span className={`conn-dot ${c.type}`} />
              {c.name}
            </button>
          ))}
        </div>
        <div className="connectors-actions">
          <button type="button" className="btn secondary" onClick={openAdd}>
            + Add connector
          </button>
        </div>
      </div>

      {form.open && activeType && (
        <div className="chart-card conn-form">
          <div className="conn-form-head">
            <h3>Configure a live connector</h3>
            <button
              type="button"
              className="conn-close"
              onClick={() => setForm((f) => ({ ...f, open: false }))}
              aria-label="close"
            >
              ×
            </button>
          </div>

          <div className="conn-form-grid">
            <label className="filter-field">
              <span>Connector type</span>
              <select value={form.type} onChange={(e) => changeType(e.target.value)}>
                {types
                  .filter((t) => t.id !== 'demo')
                  .map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.label}
                    </option>
                  ))}
              </select>
            </label>

            <label className="filter-field">
              <span>Display name</span>
              <input
                type="text"
                placeholder={activeType.label}
                value={form.values.name ?? ''}
                onChange={(e) =>
                  setForm((f) => ({ ...f, values: { ...f.values, name: e.target.value } }))
                }
              />
            </label>

            {activeType.fields.map((field) => (
              <label className="filter-field" key={field.key}>
                <span>
                  {field.label}
                  {field.required ? ' *' : ''}
                </span>
                {field.type === 'select' ? (
                  <select
                    value={form.values[field.key] ?? String(field.default ?? '')}
                    onChange={(e) =>
                      setForm((f) => ({
                        ...f,
                        values: { ...f.values, [field.key]: e.target.value },
                      }))
                    }
                  >
                    {(field.options ?? []).map((o) => (
                      <option key={o} value={o}>
                        {o}
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    type={field.type === 'secret' ? 'password' : field.type === 'number' ? 'number' : 'text'}
                    placeholder={field.type === 'secret' ? '••••••••' : ''}
                    value={form.values[field.key] ?? ''}
                    onChange={(e) =>
                      setForm((f) => ({
                        ...f,
                        values: { ...f.values, [field.key]: e.target.value },
                      }))
                    }
                  />
                )}
              </label>
            ))}
          </div>

          <p className="conn-form-hint">{activeType.description}</p>

          <div className="conn-form-foot">
            <button type="button" className="btn" onClick={submitForm} disabled={busy}>
              {busy ? 'Saving…' : 'Save connector'}
            </button>
            <button
              type="button"
              className="btn secondary"
              onClick={() => setForm((f) => ({ ...f, open: false }))}
            >
              Cancel
            </button>
            {testMsg && (
              <span className={`conn-test-msg ${testMsg.ok ? 'ok' : 'err'}`}>{testMsg.text}</span>
            )}
          </div>
        </div>
      )}

      {selectedConfig && (
        <div className="conn-toolbar">
          <div className="conn-toolbar-meta">
            <span className="conn-source-badge">{selectedConfig.label}</span>
            {selectedConfig.type === 'alienvault_otx' && (
              <span className="conn-keyhint">
                {selectedConfig.api_key_set
                  ? `API key ${selectedConfig.api_key_hint}`
                  : 'No API key set'}
              </span>
            )}
            {selectedConfig.type === 'custom_http' && selectedConfig.url && (
              <span className="conn-keyhint">{selectedConfig.url}</span>
            )}
            {live?.fetched_at && (
              <span className="conn-updated">Updated {relativeTime(live.fetched_at)}</span>
            )}
          </div>
          <div className="conn-toolbar-actions">
            <label className="conn-auto">
              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
              />
              Auto-refresh
            </label>
            <button
              type="button"
              className="btn secondary"
              onClick={() => loadLive(selected)}
              disabled={liveLoading}
            >
              {liveLoading ? 'Refreshing…' : 'Refresh'}
            </button>
            <button
              type="button"
              className="btn secondary"
              onClick={() => runTest(selected)}
              disabled={busy}
            >
              Test
            </button>
            {selectedConfig.type !== 'demo' && (
              <button
                type="button"
                className="btn secondary conn-danger"
                onClick={() => removeConnector(selected)}
                disabled={busy}
              >
                Remove
              </button>
            )}
          </div>
        </div>
      )}

      {testMsg && !form.open && (
        <div className={`conn-banner ${testMsg.ok ? 'ok' : 'err'}`}>{testMsg.text}</div>
      )}

      {live?.degraded && (
        <div className="conn-banner warn">
          Live source unavailable — showing demo data. {live.degraded_reason}
        </div>
      )}

      {liveError && !live && <div className="error-box">{liveError}</div>}

      {stats && (
        <div className="kpi-grid conn-stats">
          <div className="kpi-card" style={{ ['--accent' as string]: '#00f5d4' }}>
            <div className="kpi-label">Live events</div>
            <div className="kpi-value">{stats.total_events.toLocaleString()}</div>
            <div className="kpi-sub">{live?.connector.label}</div>
          </div>
          <div className="kpi-card" style={{ ['--accent' as string]: '#7c5cff' }}>
            <div className="kpi-label">Indicators</div>
            <div className="kpi-value">{stats.total_indicators.toLocaleString()}</div>
            <div className="kpi-sub">IOCs across pulses</div>
          </div>
          <div className="kpi-card" style={{ ['--accent' as string]: '#ff9f43' }}>
            <div className="kpi-label">Top tag</div>
            <div className="kpi-value conn-kpi-text">{stats.top_tags[0]?.tag ?? '—'}</div>
            <div className="kpi-sub">{stats.top_tags[0]?.count ?? 0} mentions</div>
          </div>
          <div className="kpi-card" style={{ ['--accent' as string]: '#ff5c7c' }}>
            <div className="kpi-label">Top region</div>
            <div className="kpi-value conn-kpi-text">{stats.top_countries[0]?.country ?? '—'}</div>
            <div className="kpi-sub">{stats.top_countries[0]?.count ?? 0} pulses</div>
          </div>
        </div>
      )}

      <div className="conn-live-grid">
        <div className="chart-card conn-feed-card">
          <h3>Live intelligence feed</h3>
          {liveLoading && !live ? (
            <div className="loading">
              <div className="loading-spinner" />
              <p>Fetching live threat intelligence…</p>
            </div>
          ) : live && live.events.length > 0 ? (
            <div className="conn-events">
              {live.events.map((ev) => (
                <a
                  key={ev.id}
                  className="conn-event"
                  href={ev.url ?? undefined}
                  target="_blank"
                  rel="noreferrer"
                >
                  <div className="conn-event-top">
                    <strong>{ev.title}</strong>
                    {ev.timestamp && (
                      <span className="conn-event-time">{relativeTime(ev.timestamp)}</span>
                    )}
                  </div>
                  <div className="conn-event-sub">{ev.subtitle}</div>
                  {ev.description && <p className="conn-event-desc">{ev.description}</p>}
                  <div className="conn-event-metrics">
                    {ev.metrics.map((m, i) => (
                      <span key={i} className="conn-metric">
                        <em>{m.label}</em> {m.value}
                      </span>
                    ))}
                  </div>
                  {(ev.tags.length > 0 || ev.countries.length > 0) && (
                    <div className="conn-event-tags">
                      {ev.tags.map((t) => (
                        <span key={t} className="conn-tag">
                          #{t}
                        </span>
                      ))}
                      {ev.countries.slice(0, 4).map((c) => (
                        <span key={c} className="conn-tag geo">
                          {c}
                        </span>
                      ))}
                    </div>
                  )}
                </a>
              ))}
            </div>
          ) : (
            <div className="nexus-feed-empty">No live events yet. Configure a connector and test it.</div>
          )}
        </div>

        <div className="conn-side">
          <div className="chart-card">
            <h3>Top tags</h3>
            <div className="ranked-bars">
              {(stats?.top_tags ?? []).slice(0, 10).map((t, i) => {
                const max = stats?.top_tags[0]?.count || 1;
                return (
                  <div key={t.tag} className="ranked-bar-row conn-rank-row">
                    <span className="ranked-bar-rank">{i + 1}</span>
                    <span className="ranked-bar-name">#{t.tag}</span>
                    <div className="ranked-bar-track">
                      <div
                        className="ranked-bar-fill"
                        style={{ width: `${(t.count / max) * 100}%` }}
                      />
                    </div>
                    <span className="ranked-bar-value">{t.count}</span>
                  </div>
                );
              })}
              {(!stats || stats.top_tags.length === 0) && (
                <div className="nexus-feed-empty">No tags</div>
              )}
            </div>
          </div>

          <div className="chart-card">
            <h3>Targeted regions</h3>
            <div className="ranked-bars">
              {(stats?.top_countries ?? []).slice(0, 8).map((c, i) => {
                const max = stats?.top_countries[0]?.count || 1;
                return (
                  <div key={c.country} className="ranked-bar-row conn-rank-row">
                    <span className="ranked-bar-rank">{i + 1}</span>
                    <span className="ranked-bar-name">{c.country}</span>
                    <div className="ranked-bar-track">
                      <div
                        className="ranked-bar-fill geo"
                        style={{ width: `${(c.count / max) * 100}%` }}
                      />
                    </div>
                    <span className="ranked-bar-value">{c.count}</span>
                  </div>
                );
              })}
              {(!stats || stats.top_countries.length === 0) && (
                <div className="nexus-feed-empty">No region data</div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

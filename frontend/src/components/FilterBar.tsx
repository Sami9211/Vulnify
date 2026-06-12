import type { NexusFilterOptions, NexusFilters } from '../api';

interface Props {
  options: NexusFilterOptions | null;
  filters: NexusFilters;
  onChange: (next: NexusFilters) => void;
  loading?: boolean;
}

const FIELD_LABELS: Record<keyof NexusFilters, string> = {
  industry: 'Industry',
  vendor: 'Vendor',
  country: 'Country / region',
  severity: 'Severity',
  status: 'Status',
  threat_type: 'Threat type',
  org_type: 'Org type',
  date_from: 'From',
  date_to: 'To',
  search: 'Search',
};

export function FilterBar({ options, filters, onChange, loading }: Props) {
  const set = (key: keyof NexusFilters, value: string) => {
    const next = { ...filters };
    if (value) next[key] = value;
    else delete next[key];
    onChange(next);
  };

  const activeKeys = (Object.keys(filters) as (keyof NexusFilters)[]).filter(
    (k) => filters[k]
  );

  const monthOptions = buildMonthOptions(
    options?.date_range.min ?? null,
    options?.date_range.max ?? null
  );

  return (
    <div className={`filterbar${loading ? ' is-loading' : ''}`}>
      <div className="filterbar-head">
        <span className="filterbar-title">
          <svg
            viewBox="0 0 24 24"
            width="16"
            height="16"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.8"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M4 4h16l-6 8v6l-4 2v-8L4 4z" />
          </svg>
          Filters
        </span>
        {activeKeys.length > 0 && (
          <button
            type="button"
            className="filterbar-clear"
            onClick={() => onChange({})}
          >
            Clear all ({activeKeys.length})
          </button>
        )}
        {loading && <span className="filterbar-spinner" />}
      </div>

      <div className="filterbar-controls">
        <label className="filter-field">
          <span>{FIELD_LABELS.industry}</span>
          <select
            value={filters.industry ?? ''}
            onChange={(e) => set('industry', e.target.value)}
          >
            <option value="">All industries</option>
            {options?.industries.map((i) => (
              <option key={i} value={i}>
                {i}
              </option>
            ))}
          </select>
        </label>

        <label className="filter-field">
          <span>{FIELD_LABELS.vendor}</span>
          <select
            value={filters.vendor ?? ''}
            onChange={(e) => set('vendor', e.target.value)}
          >
            <option value="">All vendors</option>
            {options?.vendors.map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
        </label>

        <label className="filter-field">
          <span>{FIELD_LABELS.country}</span>
          <select
            value={filters.country ?? ''}
            onChange={(e) => set('country', e.target.value)}
          >
            <option value="">All countries</option>
            {options?.countries.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </label>

        <label className="filter-field">
          <span>{FIELD_LABELS.severity}</span>
          <select
            value={filters.severity ?? ''}
            onChange={(e) => set('severity', e.target.value)}
          >
            <option value="">Any severity</option>
            {options?.severities.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>

        <label className="filter-field">
          <span>{FIELD_LABELS.status}</span>
          <select
            value={filters.status ?? ''}
            onChange={(e) => set('status', e.target.value)}
          >
            <option value="">Any status</option>
            {options?.statuses.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>

        <label className="filter-field">
          <span>{FIELD_LABELS.threat_type}</span>
          <select
            value={filters.threat_type ?? ''}
            onChange={(e) => set('threat_type', e.target.value)}
          >
            <option value="">Any threat type</option>
            {options?.threat_types.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </label>

        <label className="filter-field">
          <span>{FIELD_LABELS.date_from}</span>
          <select
            value={filters.date_from ?? ''}
            onChange={(e) => set('date_from', e.target.value)}
          >
            <option value="">Earliest</option>
            {monthOptions.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
        </label>

        <label className="filter-field">
          <span>{FIELD_LABELS.date_to}</span>
          <select
            value={filters.date_to ?? ''}
            onChange={(e) => set('date_to', e.target.value)}
          >
            <option value="">Latest</option>
            {monthOptions.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
        </label>

        <label className="filter-field filter-field-search">
          <span>{FIELD_LABELS.search}</span>
          <input
            type="text"
            placeholder="CVE, vendor, product…"
            value={filters.search ?? ''}
            onChange={(e) => set('search', e.target.value)}
          />
        </label>
      </div>

      {activeKeys.length > 0 && (
        <div className="filterbar-chips">
          {activeKeys.map((k) => (
            <span key={k} className="filter-chip">
              <em>{FIELD_LABELS[k]}:</em> {filters[k]}
              <button type="button" onClick={() => set(k, '')} aria-label="remove">
                ×
              </button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function buildMonthOptions(min: string | null, max: string | null): string[] {
  if (!min || !max) return [];
  const out: string[] = [];
  const [sy, sm] = min.split('-').map(Number);
  const [ey, em] = max.split('-').map(Number);
  let y = sy;
  let m = sm;
  let guard = 0;
  while ((y < ey || (y === ey && m <= em)) && guard < 240) {
    out.push(`${y}-${String(m).padStart(2, '0')}`);
    m += 1;
    if (m > 12) {
      m = 1;
      y += 1;
    }
    guard += 1;
  }
  return out;
}

// API base. Defaults to the dev-server proxy ('/api'); override for a static
// deploy by setting VITE_API_BASE (e.g. http://127.0.0.1:5001/api) at build time.
const API = (import.meta.env.VITE_API_BASE as string | undefined)?.replace(/\/$/, '') || '/api';

const OFFLINE_MSG =
  'Cannot reach the Vulnify backend. Make sure it is running on http://127.0.0.1:5001 ' +
  '(start it with run.sh / run.bat, or `python backend/app.py`).';

export class ApiError extends Error {
  status: number;
  constructor(message: string, status = 0) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

async function request(path: string, init?: RequestInit): Promise<Response> {
  try {
    return await fetch(`${API}${path}`, init);
  } catch {
    // DNS / connection refused / proxy could not connect to the backend
    throw new ApiError(OFFLINE_MSG);
  }
}

// Read a response body once, tolerating empty and non-JSON payloads.
async function readBody(r: Response): Promise<unknown> {
  let text: string;
  try {
    text = await r.text();
  } catch {
    return null;
  }
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return { __nonJson: text.slice(0, 200) };
  }
}

function bodyError(body: unknown): string | null {
  if (body && typeof body === 'object' && 'error' in body) {
    const e = (body as { error?: unknown }).error;
    if (typeof e === 'string' && e) return e;
  }
  return null;
}

function isUsable(body: unknown): boolean {
  return !!body && typeof body === 'object' && !('__nonJson' in (body as object));
}

// Strict GET: throws a clear ApiError on any non-OK / empty / non-JSON response.
async function getJSON<T>(path: string): Promise<T> {
  const r = await request(path);
  const body = await readBody(r);
  if (!r.ok) throw new ApiError(bodyError(body) || `Backend error (${r.status}).`, r.status);
  if (!isUsable(body)) throw new ApiError(OFFLINE_MSG, r.status);
  return body as T;
}

// Lenient send/GET for endpoints that report their own status in the JSON body
// (e.g. { success: false, error }). Returns the parsed body on any HTTP status,
// but still surfaces a clear error when the backend is unreachable.
async function sendJSON<T>(
  path: string,
  method: string,
  jsonBody?: unknown
): Promise<T> {
  const init: RequestInit = { method };
  if (jsonBody !== undefined) {
    init.headers = { 'Content-Type': 'application/json' };
    init.body = JSON.stringify(jsonBody);
  }
  const r = await request(path, init);
  const body = await readBody(r);
  if (!isUsable(body)) {
    throw new ApiError(bodyError(body) || (r.ok ? OFFLINE_MSG : `Backend error (${r.status}).`), r.status);
  }
  return body as T;
}

export interface HealthData {
  status: string;
  data: {
    kev_loaded: boolean;
    epss_loaded: boolean;
    cve_files: string[];
  };
}

export interface CveReference {
  url: string;
  label: string;
  tags: string[];
}

export interface CveResult {
  rank: number;
  cve_id: string;
  affected_asset: string;
  original_asset?: string;
  vendor?: string;
  product?: string;
  cvss: number | null;
  severity: string;
  epss: number;
  epss_percentile: number;
  kev: boolean;
  kev_flag: string;
  ransomware?: string | null;
  weakness?: string | null;
  weakness_id?: string | null;
  trust_score: number;
  status: 'confirmed' | 'review' | 'false_positive';
  urgency_score: number;
  risk_summary: string;
  mitigation: string;
  cve_url: string;
  mitre_url: string;
  references: CveReference[];
  description?: string;
}

export interface AnalysisResponse {
  success: boolean;
  results?: CveResult[];
  summary?: {
    total_assets: number;
    matched_cves: number;
    kev_count: number;
    critical_cvss_count: number;
    high_cvss_count: number;
    confirmed_count: number;
    review_count: number;
    false_positive_count: number;
  };
  assets_normalized?: Array<{
    original: string;
    cpe: string;
    match_score: number;
    match_method: string;
  }>;
  failed_assets?: Array<{ name: string; reason: string }>;
  error?: string;
}

export interface DashboardData {
  summary: {
    total_cves: number;
    total_kev_catalog: number;
    kev_in_year: number;
    high_epss_count: number;
    avg_cvss: number;
    with_cvss: number;
  };
  severity_distribution: { name: string; value: number }[];
  cve_timeline: { month: string; count: number }[];
  top_vendors: { vendor: string; count: number }[];
  by_country: {
    country: string;
    vulnerabilities: number;
    kev_exploited: number;
  }[];
  kev_by_vendor: { vendor: string; count: number }[];
  top_threats: Array<{
    cve_id: string;
    epss: number;
    cvss: number | null;
    kev: boolean;
    urgency: number;
  }>;
  kev_recent: Array<{
    cve_id: string;
    vendor: string;
    product: string;
    description: string;
    date_added: string;
    ransomware: string;
  }>;
}

export interface NexusVulnType {
  type: string;
  count: number;
  percent?: number;
}

export interface NexusCountryRow {
  country: string;
  total: number;
  top_vulnerability_types: NexusVulnType[];
}

export interface NexusLocation {
  city: string;
  region: string;
  country: string;
  vendor: string;
  location_label: string;
  cve_count: number;
  kev_count: number;
  top_vulnerability_types: NexusVulnType[];
}

export interface NexusSector {
  sector_id: string;
  label: string;
  total_vulnerabilities: number;
  kev_exploited: number;
  top_vulnerability_types: NexusVulnType[];
}

export interface NexusConfirmedRow {
  cve_id: string;
  vendor: string;
  product: string;
  industry: string;
  org_type: string;
  country: string;
  city: string;
  location_label: string;
  date_added: string;
  ransomware: string;
  description: string;
  status: string;
}

export interface NexusTopThreat {
  cve_id: string;
  epss: number;
  cvss: number | null;
  kev: boolean;
  vendor: string;
  country: string;
  threat_type: string;
  urgency: number;
}

export interface NexusData {
  ingestion: {
    inputs_per_second: number;
    queue_total: number;
    data_sources: string[];
  };
  summary: {
    total_cves: number;
    total_kev: number;
    critical: number;
    high: number;
    avg_cvss: number;
    countries_tracked: number;
    industries_tracked: number;
    grand_total_cves: number;
  };
  severity_distribution: { name: string; value: number }[];
  threat_type_distribution: { type: string; count: number }[];
  industry_distribution: { industry: string; count: number; kev: number }[];
  by_country: {
    country: string;
    vulnerabilities: number;
    kev_exploited: number;
  }[];
  top_vendors: { vendor: string; count: number }[];
  kev_by_vendor: { vendor: string; count: number }[];
  epss_distribution: { bucket: string; count: number }[];
  cvss_histogram: { score: string; count: number }[];
  cve_timeline: { month: string; count: number }[];
  org_sectors: NexusSector[];
  country_vulnerability_matrix: NexusCountryRow[];
  locations: NexusLocation[];
  top_threats: NexusTopThreat[];
  confirmed_feed: NexusConfirmedRow[];
  filters_applied: Record<string, string>;
}

export interface NexusFilters {
  industry?: string;
  org_type?: string;
  vendor?: string;
  country?: string;
  severity?: string;
  status?: string;
  threat_type?: string;
  date_from?: string;
  date_to?: string;
  search?: string;
}

export interface NexusFilterOptions {
  industries: string[];
  countries: string[];
  vendors: string[];
  threat_types: string[];
  severities: string[];
  statuses: string[];
  org_types: { id: string; label: string }[];
  date_range: { min: string | null; max: string | null };
}

export interface StreamInput {
  id: string;
  timestamp: string;
  status: string;
  source: string;
  vendor: string;
  country: string;
  city: string;
  vuln_type: string;
  cvss: number | null;
  description: string;
}

export interface StreamConfirmed {
  cve_id: string;
  status: string;
  source: string;
  vendor: string;
  product?: string;
  country: string;
  city: string;
  location_label: string;
  date_added?: string;
  ransomware?: string;
  description: string;
  vuln_type: string;
}

export interface NexusStreamData {
  inputs_per_second: number;
  new_inputs: StreamInput[];
  confirmed_updates: StreamConfirmed[];
  total_processed: number;
  pending_count: number;
  confirmed_count: number;
  kev_catalog_total?: number;
  queue_total?: number;
}

export async function fetchHealth(): Promise<HealthData> {
  return getJSON<HealthData>('/health');
}

export async function fetchDashboard(): Promise<DashboardData> {
  return getJSON<DashboardData>('/dashboard');
}

function filtersToQuery(filters?: NexusFilters): string {
  if (!filters) return '';
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(filters)) {
    if (v) params.set(k, v);
  }
  const s = params.toString();
  return s ? `?${s}` : '';
}

export async function fetchNexus(filters?: NexusFilters): Promise<NexusData> {
  return getJSON<NexusData>(`/nexus${filtersToQuery(filters)}`);
}

export async function fetchNexusFilters(): Promise<NexusFilterOptions> {
  return getJSON<NexusFilterOptions>('/nexus/filters');
}

export async function fetchNexusStream(): Promise<NexusStreamData> {
  return getJSON<NexusStreamData>('/nexus/stream?batch=8');
}

export async function analyzeAssets(assets: string): Promise<AnalysisResponse> {
  return sendJSON<AnalysisResponse>('/analyze', 'POST', { assets });
}

export async function analyzeSample(): Promise<AnalysisResponse> {
  return sendJSON<AnalysisResponse>('/analyze/sample', 'GET');
}

export async function exportCsv(assets: string): Promise<void> {
  const r = await request('/analyze/export', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ assets }),
  });
  if (!r.ok) {
    const body = await readBody(r);
    throw new ApiError(bodyError(body) || 'Export failed', r.status);
  }
  const blob = await r.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'cve_priority_report.csv';
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export async function fetchSampleAssets(): Promise<string> {
  try {
    const j = await getJSON<{ content?: string }>('/sample-assets');
    return j.content || '';
  } catch {
    return '';
  }
}

/* ----------------------- Live threat-intel connectors --------------------- */

export interface ConnectorField {
  key: string;
  label: string;
  type: 'text' | 'secret' | 'number' | 'select';
  required?: boolean;
  options?: string[];
  default?: string | number;
}

export interface ConnectorType {
  id: string;
  label: string;
  description: string;
  fields: ConnectorField[];
}

export interface ConnectorConfig {
  id: string;
  type: string;
  name: string;
  enabled: boolean;
  label: string;
  // custom_http
  url?: string;
  items_path?: string;
  title_field?: string;
  // alienvault_otx
  endpoint?: string;
  limit?: number;
  // masked secrets (never the raw value)
  api_key_set?: boolean;
  api_key_hint?: string;
  auth_header_set?: boolean;
  auth_header_hint?: string;
}

export interface ConnectorsList {
  types: ConnectorType[];
  connectors: ConnectorConfig[];
}

export interface LiveEvent {
  id: string;
  title: string;
  subtitle: string;
  description: string;
  timestamp: string | null;
  tags: string[];
  metrics: { label: string; value: string | number }[];
  countries: string[];
  url: string | null;
  severity: string | null;
  source: string;
}

export interface LiveResult {
  connector: ConnectorConfig;
  fetched_at: string;
  events: LiveEvent[];
  stats: {
    total_events: number;
    total_indicators: number;
    top_tags: { tag: string; count: number }[];
    top_countries: { country: string; count: number }[];
  };
  degraded?: boolean;
  degraded_reason?: string;
}

export async function fetchConnectors(): Promise<ConnectorsList> {
  return getJSON<ConnectorsList>('/connectors');
}

export async function saveConnector(
  payload: Record<string, unknown>
): Promise<{ success: boolean; connector?: ConnectorConfig; error?: string }> {
  return sendJSON('/connectors', 'POST', payload);
}

export async function deleteConnector(id: string): Promise<{ success: boolean }> {
  return sendJSON(`/connectors/${encodeURIComponent(id)}`, 'DELETE');
}

export async function testConnector(
  id: string
): Promise<{ ok: boolean; message: string; event_count?: number }> {
  return sendJSON(`/connectors/${encodeURIComponent(id)}/test`, 'POST');
}

export async function fetchConnectorLive(
  id: string,
  fallbackDemo = true
): Promise<LiveResult> {
  const q = fallbackDemo ? '?fallback=demo' : '';
  return getJSON<LiveResult>(`/connectors/${encodeURIComponent(id)}/live${q}`);
}

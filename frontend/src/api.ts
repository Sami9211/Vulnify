const API = '/api';

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
  const r = await fetch(`${API}/health`);
  return r.json();
}

export async function fetchDashboard(): Promise<DashboardData> {
  const r = await fetch(`${API}/dashboard`);
  if (!r.ok) throw new Error((await r.json()).error || 'Dashboard load failed');
  return r.json();
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
  const r = await fetch(`${API}/nexus${filtersToQuery(filters)}`);
  if (!r.ok) throw new Error((await r.json()).error || 'Nexus load failed');
  return r.json();
}

export async function fetchNexusFilters(): Promise<NexusFilterOptions> {
  const r = await fetch(`${API}/nexus/filters`);
  if (!r.ok) throw new Error((await r.json()).error || 'Filter load failed');
  return r.json();
}

export async function fetchNexusStream(): Promise<NexusStreamData> {
  const r = await fetch(`${API}/nexus/stream?batch=8`);
  if (!r.ok) throw new Error((await r.json()).error || 'Stream failed');
  return r.json();
}

export async function analyzeAssets(assets: string): Promise<AnalysisResponse> {
  const r = await fetch(`${API}/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ assets }),
  });
  return r.json();
}

export async function analyzeSample(): Promise<AnalysisResponse> {
  const r = await fetch(`${API}/analyze/sample`);
  return r.json();
}

export async function exportCsv(assets: string): Promise<void> {
  const r = await fetch(`${API}/analyze/export`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ assets }),
  });
  if (!r.ok) throw new Error('Export failed');
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
  const r = await fetch(`${API}/sample-assets`);
  const j = await r.json();
  return j.content || '';
}

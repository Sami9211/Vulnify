import { useCallback, useEffect, useRef, useState } from 'react';
import './App.css';
import {
  analyzeAssets,
  analyzeSample,
  fetchHealth,
  fetchNexus,
  fetchNexusFilters,
  fetchSampleAssets,
  type AnalysisResponse,
  type HealthData,
  type NexusData,
  type NexusFilterOptions,
  type NexusFilters,
} from './api';
import { Analyzer } from './components/Analyzer';
import { FilterBar } from './components/FilterBar';
import { Nexus } from './components/Nexus';
import { Sidebar } from './components/Sidebar';

type Tab = 'nexus' | 'analyzer';

function App() {
  const [tab, setTab] = useState<Tab>('nexus');
  const [health, setHealth] = useState<HealthData | null>(null);
  const [nexus, setNexus] = useState<NexusData | null>(null);
  const [nexusLoading, setNexusLoading] = useState(true);
  const [nexusRefreshing, setNexusRefreshing] = useState(false);
  const [nexusError, setNexusError] = useState<string | null>(null);
  const [filters, setFilters] = useState<NexusFilters>({});
  const [filterOptions, setFilterOptions] = useState<NexusFilterOptions | null>(null);
  const [view, setView] = useState<string>('sec-overview');
  const [assets, setAssets] = useState('');
  const [analysis, setAnalysis] = useState<AnalysisResponse | null>(null);
  const [analyzeLoading, setAnalyzeLoading] = useState(false);
  const nexusFetched = useRef(false);
  const searchTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    fetchHealth().then(setHealth).catch(() => setHealth(null));
    fetchNexusFilters().then(setFilterOptions).catch(() => setFilterOptions(null));
  }, []);

  const loadNexus = useCallback(async (f: NexusFilters, initial: boolean) => {
    if (initial) setNexusLoading(true);
    else setNexusRefreshing(true);
    setNexusError(null);
    try {
      const data = await fetchNexus(f);
      setNexus(data);
      nexusFetched.current = true;
    } catch (e) {
      setNexusError(e instanceof Error ? e.message : 'Failed to load Nexus');
    } finally {
      setNexusLoading(false);
      setNexusRefreshing(false);
    }
  }, []);

  useEffect(() => {
    if (!nexusFetched.current) loadNexus({}, true);
  }, [loadNexus]);

  const handleFilterChange = useCallback(
    (next: NexusFilters) => {
      setFilters(next);
      if (searchTimer.current) clearTimeout(searchTimer.current);
      searchTimer.current = setTimeout(() => loadNexus(next, false), 250);
    },
    [loadNexus]
  );

  const runAnalyze = async () => {
    setAnalyzeLoading(true);
    try {
      const res = await analyzeAssets(assets);
      setAnalysis(res);
    } catch (e) {
      setAnalysis({
        success: false,
        error: e instanceof Error ? e.message : 'Request failed',
      });
    } finally {
      setAnalyzeLoading(false);
    }
  };

  const runSample = async () => {
    setAnalyzeLoading(true);
    try {
      const res = await analyzeSample();
      setAnalysis(res);
    } catch (e) {
      setAnalysis({
        success: false,
        error: e instanceof Error ? e.message : 'Request failed',
      });
    } finally {
      setAnalyzeLoading(false);
    }
  };

  const loadSampleText = async () => {
    const text = await fetchSampleAssets();
    setAssets(text);
  };

  const navigateView = useCallback((id: string) => {
    setView(id);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }, []);

  return (
    <div className={`app${tab === 'nexus' ? ' app-with-sidebar' : ''}`}>
      {tab === 'nexus' && <Sidebar active={view} onNavigate={navigateView} />}
      <header className="header">
        <div className="header-brand">
          <div>
            <h1>
              <span>Vulnify</span>
            </h1>
            <p>
              Live vulnerability intelligence
            </p>
          </div>
        </div>
        <nav className="nav">
          <button
            type="button"
            className={tab === 'nexus' ? 'active' : ''}
            onClick={() => setTab('nexus')}
          >
            Nexus dashboard
          </button>
          <button
            type="button"
            className={tab === 'analyzer' ? 'active' : ''}
            onClick={() => setTab('analyzer')}
          >
            Stack analyzer
          </button>
        </nav>
      </header>

      <main className="main">
        {health && (
          <div className="status-bar">
            <div
              className={`status-pill ${health.data.kev_loaded ? 'ok' : 'err'}`}
            >
              CISA KEV {health.data.kev_loaded ? 'loaded' : 'missing'}
            </div>
            <div
              className={`status-pill ${health.data.epss_loaded ? 'ok' : 'err'}`}
            >
              EPSS {health.data.epss_loaded ? 'loaded' : 'missing'}
            </div>
            <div
              className={`status-pill ${
                health.data.cve_files.length ? 'ok' : 'err'
              }`}
            >
              NVD CVE: {health.data.cve_files.join(', ') || 'missing'}
            </div>
          </div>
        )}

        {tab === 'nexus' && (
          <div className="tab-panel">
            {nexusLoading && (
              <div className="loading">
                <div className="loading-spinner" />
                <p>Building Nexus analytics from real vulnerability feeds…</p>
              </div>
            )}
            {nexusError && <div className="error-box">{nexusError}</div>}
            {!nexusLoading && view !== 'sec-live' && (
              <FilterBar
                options={filterOptions}
                filters={filters}
                onChange={handleFilterChange}
                loading={nexusRefreshing}
              />
            )}
            {nexus && !nexusLoading && <Nexus data={nexus} view={view} />}
          </div>
        )}

        {tab === 'analyzer' && (
          <div className="tab-panel">
            <Analyzer
              assets={assets}
              onAssetsChange={setAssets}
              onAnalyze={runAnalyze}
              onSample={runSample}
              onLoadSampleText={loadSampleText}
              loading={analyzeLoading}
              result={analysis}
            />
          </div>
        )}
      </main>

      <footer className="footer">
        Vulnify · NVD (FKIE) · CISA KEV · FIRST EPSS · All metrics from offline feeds
      </footer>
    </div>
  );
}

export default App;

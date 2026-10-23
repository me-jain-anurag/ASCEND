import { useState, useEffect, useCallback } from 'react';
import {
  Shield, Activity, AlertTriangle, Network as NetworkIcon,
  RefreshCw, ShieldCheck, TrendingDown, Home, Target, BookOpen,
  Sun, Moon, Bug
} from 'lucide-react';
import { api } from './api';
import type {
  NetworkData, PathsResponse, VerifyData,
  RemediationData, StatusData, AttackPath
} from './types';
import NetworkGraph from './components/NetworkGraph';
import PathList from './components/PathList';
import RemediationPanel from './components/RemediationPanel';
import Sidebar from './components/Sidebar';
import DocsPanel from './components/DocsPanel';
import TechniquesPanel from './components/TechniquesPanel';
import InfoTooltip from './components/InfoTooltip';
import type { KnowledgeData } from './types';

type Tab = 'overview' | 'network' | 'paths' | 'techniques' | 'remediation' | 'docs';

const TABS: Tab[] = ['overview', 'network', 'paths', 'techniques', 'remediation', 'docs'];

/**
 * The visible tab lives in the URL hash rather than in component state alone.
 *
 * Without this, opening Attack Paths left the URL unchanged, so browser Back
 * navigated away from the app instead of returning to the overview, and the
 * only route home was a reload — which discards the verification results you
 * just spent ten seconds producing.
 *
 * The browser already keeps hash history, so Back and Forward work for free,
 * and a tab becomes linkable and refresh-safe.
 */
function tabFromHash(): Tab {
  const raw = window.location.hash.replace(/^#\/?/, '');
  return (TABS as string[]).includes(raw) ? (raw as Tab) : 'overview';
}
type Scenario = 'default' | 'benign';

const SCENARIO_TIPS: Record<Scenario, string> = {
  default:
    'Adversary: an attacker with a low-privilege foothold on the entry host. ' +
    'ASCEND finds every escalation route to the crown jewel, runs each one in ' +
    'the lab, and ranks the fixes that break them.',
  benign:
    'Benign look-alike: an admin doing legitimate work that resembles an ' +
    'attack step (e.g. normal SSH use). ASCEND should report no attack path. ' +
    'Not available yet: this lab variant has not been built.',
};

/** "22 Oct 2026, 14:27 UTC" — the collector writes ISO timestamps in UTC. */
function formatUtc(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString('en-GB', {
    day: 'numeric', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit', timeZone: 'UTC',
  }) + ' UTC';
}

/** The responses whose verified/partial counts change after a verify run. */
function fetchRunCounts(sc: Scenario) {
  return Promise.all([
    api.get<StatusData>('/api/status'),
    api.post<PathsResponse>('/api/enumerate', { scenario: sc }),
  ]);
}

// ─── Loading / Error helpers ──────────────────────────────────────────────────
function Loader({ text = 'Loading…' }: { text?: string }) {
  return (
    <div className="loading-overlay">
      <div className="spinner" />
      {text}
    </div>
  );
}
function ErrorMsg({ msg }: { msg: string }) {
  return (
    <div className="error-banner">
      <AlertTriangle size={14} />
      {msg}
    </div>
  );
}

// ─── Overview tab ─────────────────────────────────────────────────────────────
function OverviewTab({
  status, paths, verifyData, onSwitchTab
}: {
  status: StatusData;
  paths: PathsResponse | null;
  verifyData: VerifyData | null;
  onSwitchTab: (t: Tab) => void;
}) {
  const m = status.summary_metrics;
  const precisionValue = verifyData?.summary?.precision;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="stats-row">
        <StatCard label="Hosts Analysed" value={m.hosts_count} icon={<NetworkIcon size={14} />} />
        <StatCard label="Attack Vectors" value={m.vectors_count} icon={<AlertTriangle size={14} />} variant="warn" />
        <StatCard label="Attack Paths" value={m.enumerated_paths} icon={<Shield size={14} />} variant="danger" />
        <StatCard label="Verified Paths" value={m.verified_paths} icon={<ShieldCheck size={14} />} variant={m.verified_paths > 0 ? 'danger' : 'safe'} />
        <StatCard label="Chokepoints" value={m.chokepoints_identified} icon={<TrendingDown size={14} />} variant="safe" />
        {precisionValue != null && (
          <StatCard
            label="Precision"
            value={`${verifyData!.summary.paths_verified} of ${verifyData!.summary.paths_tested} proven`}
            icon={<Target size={14} />}
            variant={precisionValue > 0.5 ? 'danger' : 'default'}
            sub={`${(precisionValue * 100).toFixed(0)}% of enumerated paths execution-verified`}
            info={
              <InfoTooltip title="Execution precision">
                Fraction of enumerated paths proven end-to-end by running every
                step in the lab. Partial paths (a step the lab cannot execute)
                count against it. Distinct from config coverage, which only
                checks the configuration is present.
              </InfoTooltip>
            }
          />
        )}
        {m.eliminated_paths_count != null && m.eliminated_paths_count > 0 && (
          <StatCard label="Paths Eliminated" value={m.eliminated_paths_count} icon={<ShieldCheck size={14} />} variant="safe"
            sub={`${m.applied_fixes_count} fix${m.applied_fixes_count !== 1 ? 'es' : ''} applied`} />
        )}
      </div>

      {/* Scenario + Verification Summary */}
      <div className="two-col">
        <div className="card">
          <div className="card-header">
            <Activity size={16} color="var(--text-1)" />
            <h2>Active Scenario</h2>
          </div>
          <div className="card-body">
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 18, fontWeight: 700, color: 'var(--text-0)', marginBottom: 6 }}>
              <span className={`scenario-dot ${m.active_scenario === 'benign' ? 'benign' : 'adversary'}`} />
              {m.active_scenario === 'benign' ? 'Benign' : 'Default Adversary'}
            </div>
            {paths && (
              <div style={{ fontSize: 13, color: 'var(--text-1)', lineHeight: 1.6 }}>
                {paths.description || paths.name}
                <dl className="scenario-facts">
                  <dt>Entry → crown jewel</dt>
                  <dd>
                    <b style={{ color: 'var(--accent-partial)' }}>{paths.entry_point}</b> →{' '}
                    <b style={{ color: 'var(--accent-gap)' }}>{paths.crown_jewel}</b>
                  </dd>
                  {paths.algorithm && (
                    <>
                      <dt>Algorithm</dt>
                      <dd>{paths.algorithm}</dd>
                    </>
                  )}
                  {paths.facts_source && (
                    <>
                      <dt>Facts</dt>
                      <dd>
                        {paths.facts_source}
                        {paths.facts_collected_at && `, collected ${formatUtc(paths.facts_collected_at)}`}
                      </dd>
                    </>
                  )}
                  {paths.config_covered != null && paths.total_paths > 0 && (
                    <>
                      <dt>Config coverage</dt>
                      <dd>{paths.config_covered} of {paths.total_paths} paths</dd>
                    </>
                  )}
                  {paths.total_paths > 0 && (
                    <>
                      <dt>Execution-verified</dt>
                      <dd>
                        {paths.execution_verified == null
                          ? 'Not run yet'
                          : `${paths.execution_verified} of ${paths.total_paths} paths`
                            + (paths.execution_partial ? ` (${paths.execution_partial} partial)` : '')}
                      </dd>
                    </>
                  )}
                  {(paths.applied_fixes?.length ?? 0) > 0 && (
                    <>
                      <dt>Fixes applied</dt>
                      <dd>
                        {paths.applied_fixes!.length}, eliminating{' '}
                        {paths.eliminated_path_ids?.length ?? 0} path
                        {(paths.eliminated_path_ids?.length ?? 0) !== 1 ? 's' : ''}
                      </dd>
                    </>
                  )}
                </dl>
              </div>
            )}
          </div>
        </div>
        <div className="card">
          <div className="card-header">
            <ShieldCheck size={16} color="var(--accent-verified)" />
            <h2>Verification Summary</h2>
          </div>
          <div className="card-body">
            {verifyData ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                <div style={{ display: 'flex', gap: 16 }}>
                  <div>
                    <div style={{ fontSize: 24, fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--text-0)', lineHeight: 1 }}>
                      {verifyData.summary.paths_tested}
                    </div>
                    <div style={{ fontSize: 10, color: 'var(--text-2)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                      Tested
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: 24, fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--accent-verified)', lineHeight: 1 }}>
                      {verifyData.summary.paths_verified}
                    </div>
                    <div style={{ fontSize: 10, color: 'var(--text-2)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                      Verified
                    </div>
                  </div>
                  {/* Partial: every step we could run succeeded, but the path
                      contains at least one step this lab cannot execute. Not
                      proven, and not disproven either. Without this tile the
                      row reads "3 tested, 0 verified, 0 failed", and the three
                      paths appear to have vanished. */}
                  <div>
                    <div style={{ fontSize: 24, fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--accent-partial)', lineHeight: 1 }}>
                      {verifyData.summary.paths_partial ?? 0}
                    </div>
                    <div style={{ fontSize: 10, color: 'var(--text-2)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                      Partial
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: 24, fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--accent-gap)', lineHeight: 1 }}>
                      {verifyData.summary.paths_failed}
                    </div>
                    <div style={{ fontSize: 10, color: 'var(--text-2)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                      Failed
                    </div>
                  </div>
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-2)', lineHeight: 1.5 }}>
                  <strong>Partial</strong> = every step we could execute succeeded,
                  but the path contains a step this lab cannot run. Expand a path
                  to see which one, and why.
                </div>
                {/* Said once here rather than under every step: the API marks
                    each step's telemetry "not captured" until Falco is wired. */}
                {Object.values(verifyData.results).some(r =>
                  r.steps.some(s => s.evidence.telemetry?.startsWith('not captured'))) && (
                  <div style={{ fontSize: 11, color: 'var(--text-2)', lineHeight: 1.5 }}>
                    <strong>Telemetry</strong>: syscall-level capture is not built yet
                    (Falco integration pending), so steps show command output only.
                  </div>
                )}
                <div style={{ fontSize: 11, color: 'var(--text-2)' }}>
                  Run ID: <span style={{ fontFamily: 'var(--font-mono)' }}>{verifyData.execution_run_id}</span>
                </div>
              </div>
            ) : (
              <div style={{ color: 'var(--text-2)', fontSize: 13 }}>
                No verification data loaded yet.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Quick nav */}
      <div className="card">
        <div className="card-header">
          <Activity size={16} color="var(--accent-purple)" />
          <h2>Quick Navigation</h2>
        </div>
        <div className="card-body" style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          {(['network', 'paths', 'remediation'] as Tab[]).map(t => (
            <button key={t} id={`quick-nav-${t}`} className="btn btn-ghost" onClick={() => onSwitchTab(t)}>
              {t.charAt(0).toUpperCase() + t.slice(1)}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

function StatCard({
  label, value, icon, variant = 'default', sub, info
}: {
  label: string; value: string | number; icon?: React.ReactNode;
  variant?: 'default' | 'danger' | 'warn' | 'safe'; sub?: string;
  info?: React.ReactNode;
}) {
  return (
    <div className="stat-card">
      {icon && <div className="stat-icon">{icon}</div>}
      <div className="stat-label">{label}{info}</div>
      <div className={`stat-value${variant !== 'default' ? ` ${variant}` : ''}`}>{value}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  );
}

// ─── Root App ─────────────────────────────────────────────────────────────────
export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>(tabFromHash);

  // Colour theme. Persisted per-viewer; dark is the default. Applied as
  // data-theme on <html> so the CSS token overrides take effect globally.
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    try { return (localStorage.getItem('ascend-theme') as 'dark' | 'light') || 'dark'; }
    catch { return 'dark'; }
  });
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    try { localStorage.setItem('ascend-theme', theme); } catch { /* private mode */ }
  }, [theme]);

  // Back/Forward change the hash; mirror that into state.
  useEffect(() => {
    const onHashChange = () => setActiveTab(tabFromHash());
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  /**
   * Switch tabs by navigating. Assigning to location.hash adds a history entry,
   * and the listener above updates the state — so every tab change goes through
   * one path whether it came from the sidebar, a quick-nav button, the Home
   * button, or the browser's own Back.
   */
  const goToTab = useCallback((tab: Tab) => {
    if (tabFromHash() === tab) {
      setActiveTab(tab);      // already there; nothing to push
      return;
    }
    window.location.hash = tab;
  }, []);
  const [scenario, setScenario] = useState<Scenario>('default');

  // Data states
  const [network, setNetwork] = useState<NetworkData | null>(null);
  const [paths, setPaths] = useState<PathsResponse | null>(null);
  const [verifyData, setVerifyData] = useState<VerifyData | null>(null);
  const [remediation, setRemediation] = useState<RemediationData | null>(null);
  const [status, setStatus] = useState<StatusData | null>(null);
  const [knowledge, setKnowledge] = useState<KnowledgeData | null>(null);

  // UI states
  const [selectedPath, setSelectedPath] = useState<AttackPath | null>(null);
  const [appliedFixes, setAppliedFixes] = useState<string[]>([]);
  const [applying, setApplying] = useState<string | null>(null);

  // Loading / error
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [backendOnline, setBackendOnline] = useState(false);

  const fetchAll = useCallback(async (sc: Scenario = scenario) => {
    setLoading(true);
    setError(null);
    try {
      const [net, pth, rem, st, kn] = await Promise.all([
        api.get<NetworkData>('/api/network'),
        api.post<PathsResponse>('/api/enumerate', { scenario: sc }),
        api.get<RemediationData>('/api/remediation'),
        api.get<StatusData>('/api/status'),
        api.get<KnowledgeData>('/api/knowledge'),
      ]);
      setNetwork(net);
      setPaths(pth);
      setRemediation(rem);
      setStatus(st);
      setKnowledge(kn);
      setAppliedFixes(rem.applied_fixes ?? []);
      setBackendOnline(true);

      // Attempt verification run, but do not block the core dashboard if Docker is not ready
      try {
        const vfy = await api.post<VerifyData>('/api/verify');
        setVerifyData(vfy);
        // Status and paths were fetched above, before this run, so their
        // verified and partial counts describe the previous run (0 on first load).
        const [st2, pth2] = await fetchRunCounts(sc);
        setStatus(st2);
        setPaths(pth2);
      } catch (vErr) {
        console.warn('In-container verifier currently unavailable (requires Docker):', vErr);
        setVerifyData(null);
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      // Only suggest "the server is down" when nothing answered at all. A
      // 4xx/5xx means the server replied and already explained itself, and
      // telling the reader to check whether it is running sends them the
      // wrong way.
      const answered = /failed \(\d{3}/.test(msg);
      setError(
        answered
          ? msg
          : `Cannot reach backend: ${msg}. Is the API running on port 8000?`
      );
      setBackendOnline(false);
    } finally {
      setLoading(false);
    }
  }, [scenario]);

  useEffect(() => { fetchAll(scenario); }, [scenario]);

  const handleReset = async () => {
    setLoading(true);
    try {
      await api.post('/api/reset');
      setAppliedFixes([]);
      setSelectedPath(null);
      await fetchAll(scenario);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  };

  const handleScenarioChange = (sc: Scenario) => {
    setScenario(sc);
    setSelectedPath(null);
  };

  const handleApplyFix = async (fixId: string) => {
    setApplying(fixId);
    try {
      await api.post('/api/remediation/apply', { fix_id: fixId });
      await fetchAll(scenario);
      const st = await api.get<StatusData>('/api/status');
      setStatus(st);
      const applied = appliedFixes.includes(fixId)
        ? appliedFixes
        : [...appliedFixes, fixId];
      setAppliedFixes(applied);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to apply fix');
    } finally {
      setApplying(null);
    }
  };

  const verifiedPathIds = verifyData
    ? Object.entries(verifyData.results)
        .filter(([, r]) => r.overall_verified)
        .map(([id]) => id)
    : [];

  const partialPathIds = verifyData
    ? Object.entries(verifyData.results)
        .filter(([, r]) => r.status === 'partial')
        .map(([id]) => id)
    : [];

  return (
    <div className="shell">
      {/* ── Topbar ── */}
      <header className="topbar">
        <div className="topbar-logo">
          <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" style={{ color: 'var(--text-0)' }}>
            <path d="M12 2L2 7v10l10 5 10-5V7L12 2z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
            <path d="M12 22V12M2 7l10 5 10-5" stroke="#8D909C" strokeWidth="1.5" />
          </svg>
          <div>
            <div className="wordmark">ASCEND</div>
            <div className="tagline">Attack-Path Analysis</div>
          </div>
        </div>

        <div className="topbar-spacer" />

        {/* Scenario switcher */}
        <div className="scenario-tabs">
          {(['default', 'benign'] as Scenario[]).map(sc => (
            // The title sits on a wrapper: a disabled button gets no hover
            // events in some browsers, so its own title would never show.
            <span key={sc} title={SCENARIO_TIPS[sc]}>
              <button
                id={`scenario-${sc}`}
                className={`scenario-tab${scenario === sc ? ' active' : ''}`}
                onClick={() => handleScenarioChange(sc)}
                disabled={sc === 'benign'}
              >
                <span className={`scenario-dot ${sc === 'default' ? 'adversary' : 'benign'}`} />
                {sc === 'default' ? 'Adversary' : 'Benign'}
              </button>
            </span>
          ))}
        </div>

        <div className="scenario-badge">
          <span>Scenario: <b>{scenario}</b></span>
        </div>

        <div className="status-pill">
          <div className={`status-dot${backendOnline ? '' : ' offline'}`} />
          {backendOnline ? 'Backend Online' : 'Backend Offline'}
        </div>

        <button
          id="topbar-theme"
          className="btn btn-ghost"
          onClick={() => setTheme(t => (t === 'dark' ? 'light' : 'dark'))}
          title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          style={{ padding: '6px 10px' }}
        >
          {theme === 'dark' ? <Sun size={14} /> : <Moon size={14} />}
        </button>

        <button
          id="topbar-home"
          className="btn btn-ghost"
          onClick={() => goToTab('overview')}
          title="Back to overview"
          aria-label="Back to overview"
          disabled={activeTab === 'overview'}
          style={{ padding: '6px 10px' }}
        >
          <Home size={14} />
        </button>

        <button
          id="topbar-refresh"
          className="btn btn-ghost"
          onClick={() => fetchAll(scenario)}
          disabled={loading}
          style={{ padding: '6px 10px' }}
        >
          <RefreshCw size={14} className={loading ? 'spin-anim' : ''} />
        </button>
      </header>

      {/* ── Sidebar ── */}
      <Sidebar
        status={status}
        remediation={remediation}
        appliedFixes={appliedFixes}
        activeTab={activeTab}
        onTabChange={t => goToTab(t as Tab)}
        onReset={handleReset}
        loading={loading}
      />

      {/* ── Main ── */}
      <main className="main">
        <div className="main-content">
          {/* Error banner */}
          {error && <ErrorMsg msg={error} />}

          {/* ── Overview ── */}
          {activeTab === 'overview' && (
            loading && !status
              ? <Loader text="Connecting to ASCEND Analysis Core…" />
              : status
                ? <OverviewTab status={status} paths={paths} verifyData={verifyData} onSwitchTab={t => goToTab(t)} />
                : !error && <Loader text="Connecting…" />
          )}

          {/* ── Network ── */}
          {activeTab === 'network' && (
            <>
              <div className="page-header">
                <div className="section-heading">
                  <NetworkIcon size={20} color="var(--text-1)" />
                  <div>
                    <h1>Network Topology</h1>
                    <div className="subtitle">
                      {network ? `${network.hosts.length} hosts · ${network.reachability.length} reachability edges` : ''}
                    </div>
                  </div>
                </div>
              </div>
              {loading && !network ? <Loader /> : network ? (
                <div className="card">
                  <div className="card-body" style={{ padding: 0 }}>
                    <NetworkGraph
                      network={network}
                      activePath={selectedPath}
                      verifiedPathIds={verifiedPathIds}
                      partialPathIds={partialPathIds}
                    />
                  </div>
                </div>
              ) : null}

              {/* Host detail table */}
              {network && (
                <div className="card">
                  <div className="card-header">
                    <h2>Host Inventory</h2>
                  </div>
                  <div className="card-body" style={{ padding: 0 }}>
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Host</th><th>Role</th><th>OS</th>
                          <th>Asset Value</th><th>Vectors</th><th>Flags</th>
                        </tr>
                      </thead>
                      <tbody>
                        {network.hosts.map(h => (
                          <tr key={h.hostname}>
                            <td><span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-0)' }}>{h.hostname}</span></td>
                            <td><span className="tag tag-blue">{h.role}</span></td>
                            <td><span style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{h.os}</span></td>
                            <td><span style={{ fontWeight: 700, color: h.asset_value >= 80 ? 'var(--accent-gap)' : 'var(--text-1)' }}>{h.asset_value}</span></td>
                            <td>
                              <span className={`tag ${h.vectors.length > 0 ? 'tag-amber' : 'tag-green'}`}>
                                {h.vectors.length}
                              </span>
                            </td>
                            <td style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                              {h.is_entry_point && <span className="tag tag-amber">Entry</span>}
                              {h.is_crown_jewel && <span className="tag tag-red">Crown Jewel</span>}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </>
          )}

          {/* ── Attack Paths ── */}
          {activeTab === 'paths' && (
            <>
              <div className="page-header">
                <div className="section-heading">
                  <AlertTriangle size={20} color="var(--text-1)" />
                  <div>
                    <h1>Attack Paths</h1>
                    <div className="subtitle">
                      {paths ? `${paths.total_paths} path${paths.total_paths !== 1 ? 's' : ''} enumerated · scenario: ${paths.name}` : ''}
                    </div>
                  </div>
                </div>
                <div className="page-header-actions">
                  {selectedPath && (
                    <span style={{ fontSize: 11, color: 'var(--accent-partial)' }}>
                      Path highlighted in Network view
                    </span>
                  )}
                  <button
                    id="run-verify"
                    className="btn btn-primary"
                    onClick={() => {
                      setLoading(true);
                      setError(null);
                      api.post<VerifyData>('/api/verify')
                        .then(async vfy => {
                          setVerifyData(vfy);
                          const [st, pth] = await fetchRunCounts(scenario);
                          setStatus(st);
                          setPaths(pth);
                        })
                        .catch(err => {
                          const msg = err instanceof Error ? err.message : String(err);
                          setError(msg);
                        })
                        .finally(() => setLoading(false));
                    }}
                    disabled={loading}
                  >
                    <ShieldCheck size={13} /> Run Verifier
                  </button>
                </div>
              </div>

              {loading && !paths ? <Loader /> : paths ? (
                <PathList
                  paths={paths.paths}
                  verifyData={verifyData}
                  onSelectPath={setSelectedPath}
                  selectedPathId={selectedPath?.path_id}
                  tactics={Object.fromEntries(
                    (knowledge?.techniques ?? []).map(t => [t.attack_id, t.tactic]),
                  )}
                />
              ) : null}
            </>
          )}

          {/* ── Techniques & CVEs ── */}
          {activeTab === 'techniques' && (
            <>
              <div className="page-header">
                <div className="section-heading">
                  <Bug size={20} color="var(--text-1)" />
                  <div>
                    <h1>Techniques &amp; CVEs</h1>
                    <div className="subtitle">
                      {knowledge
                        ? `${knowledge.demonstrated_count} ATT&CK techniques demonstrated · ${knowledge.cves.length} anchor CVEs`
                        : 'What each technique and vulnerability is'}
                    </div>
                  </div>
                </div>
              </div>
              {loading && !knowledge ? <Loader /> : knowledge ? (
                <TechniquesPanel data={knowledge} />
              ) : null}
            </>
          )}

          {/* ── Remediation ── */}
          {activeTab === 'remediation' && (
            <>
              <div className="page-header">
                <div className="section-heading">
                  <Shield size={20} color="var(--text-1)" />
                  <div>
                    <h1>Remediation</h1>
                    <div className="subtitle">Chokepoint analysis & ranked fixes</div>
                  </div>
                </div>
              </div>
              {loading && !remediation ? (
                <Loader />
              ) : remediation ? (
                <RemediationPanel
                  data={remediation}
                  appliedFixes={appliedFixes}
                  onApply={handleApplyFix}
                  applying={applying}
                  verifiedPathIds={verifiedPathIds}
                  hasVerifyRun={!!verifyData}
                />
              ) : null}
            </>
          )}

          {/* ── Docs / Methodology ── */}
          {activeTab === 'docs' && (
            <>
              <div className="page-header">
                <div className="section-heading">
                  <BookOpen size={20} color="var(--text-1)" />
                  <div>
                    <h1>Methodology</h1>
                    <div className="subtitle">How every figure on this dashboard is calculated</div>
                  </div>
                </div>
              </div>
              <div className="card">
                <div className="card-body">
                  <DocsPanel />
                </div>
              </div>
            </>
          )}
        </div>
      </main>

      <style>{`
        @keyframes spin-anim { to { transform: rotate(360deg); } }
        .spin-anim { animation: spin-anim 0.7s linear infinite; }
      `}</style>
    </div>
  );
}

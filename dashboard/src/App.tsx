import { useState, useEffect, useCallback } from 'react';
import {
  Shield, Activity, AlertTriangle, Network as NetworkIcon,
  RefreshCw, ShieldCheck, Target, TrendingDown
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

type Tab = 'overview' | 'network' | 'paths' | 'remediation';
type Scenario = 'default' | 'benign';

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
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="stats-row">
        <StatCard label="Hosts Analysed" value={m.hosts_count} icon={<NetworkIcon size={14} />} />
        <StatCard label="Attack Vectors" value={m.vectors_count} icon={<AlertTriangle size={14} />} variant="warn" />
        <StatCard label="Attack Paths" value={m.enumerated_paths} icon={<Shield size={14} />} variant="danger" />
        <StatCard label="Verified Paths" value={m.verified_paths} icon={<ShieldCheck size={14} />} variant={m.verified_paths > 0 ? 'danger' : 'safe'} />
        <StatCard label="Precision" value={m.precision} icon={<Target size={14} />} />
        <StatCard label="Chokepoints" value={m.chokepoints_identified} icon={<TrendingDown size={14} />} variant="safe" />
        {m.eliminated_paths_count != null && m.eliminated_paths_count > 0 && (
          <StatCard label="Paths Eliminated" value={m.eliminated_paths_count} icon={<ShieldCheck size={14} />} variant="safe"
            sub={`${m.applied_fixes_count} fix${m.applied_fixes_count !== 1 ? 'es' : ''} applied`} />
        )}
      </div>

      {/* Scenario + Precision */}
      <div className="two-col">
        <div className="card">
          <div className="card-header">
            <Activity size={16} color="var(--accent-cyan)" />
            <h2>Active Scenario</h2>
          </div>
          <div className="card-body">
            <div style={{ fontSize: 22, fontWeight: 800, color: 'var(--accent-cyan)', marginBottom: 6 }}>
              {m.active_scenario === 'benign' ? '🟢 Benign' : '🔴 Default Adversary'}
            </div>
            {paths && (
              <div style={{ fontSize: 13, color: 'var(--text-1)', lineHeight: 1.6 }}>
                {paths.description || paths.name}
                {paths.description && (
                  <div style={{ marginTop: 8, fontSize: 11, color: 'var(--text-2)' }}>
                    Entry: <b style={{ color: 'var(--accent-cyan)' }}>{paths.entry_point}</b> →
                    Crown Jewel: <b style={{ color: 'var(--accent-red)' }}>{paths.crown_jewel}</b>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
        <div className="card">
          <div className="card-header">
            <ShieldCheck size={16} color="var(--accent-green)" />
            <h2>Verification Summary</h2>
          </div>
          <div className="card-body">
            {verifyData ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                <div style={{ display: 'flex', gap: 16 }}>
                  <div>
                    <div style={{ fontSize: 28, fontWeight: 800, color: 'var(--accent-red)', lineHeight: 1 }}>
                      {verifyData.summary.paths_verified}
                    </div>
                    <div style={{ fontSize: 10, color: 'var(--text-2)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                      Verified
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: 28, fontWeight: 800, color: 'var(--accent-amber)', lineHeight: 1 }}>
                      {verifyData.summary.paths_failed}
                    </div>
                    <div style={{ fontSize: 10, color: 'var(--text-2)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                      Failed
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: 28, fontWeight: 800, color: 'var(--accent-green)', lineHeight: 1 }}>
                      {(verifyData.summary.precision * 100).toFixed(0)}%
                    </div>
                    <div style={{ fontSize: 10, color: 'var(--text-2)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                      Precision
                    </div>
                  </div>
                </div>
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
  label, value, icon, variant = 'default', sub
}: {
  label: string; value: string | number; icon?: React.ReactNode;
  variant?: 'default' | 'danger' | 'warn' | 'safe'; sub?: string;
}) {
  return (
    <div className="stat-card">
      {icon && <div className="stat-icon">{icon}</div>}
      <div className="stat-label">{label}</div>
      <div className={`stat-value${variant !== 'default' ? ` ${variant}` : ''}`}>{value}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  );
}

// ─── Root App ─────────────────────────────────────────────────────────────────
export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>('overview');
  const [scenario, setScenario] = useState<Scenario>('default');

  // Data states
  const [network, setNetwork] = useState<NetworkData | null>(null);
  const [paths, setPaths] = useState<PathsResponse | null>(null);
  const [verifyData, setVerifyData] = useState<VerifyData | null>(null);
  const [remediation, setRemediation] = useState<RemediationData | null>(null);
  const [status, setStatus] = useState<StatusData | null>(null);

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
      const [net, pth, vfy, rem, st] = await Promise.all([
        api.get<NetworkData>('/api/network'),
        api.post<PathsResponse>('/api/enumerate', { scenario: sc }),
        api.post<VerifyData>('/api/verify'),
        api.get<RemediationData>('/api/remediation'),
        api.get<StatusData>('/api/status'),
      ]);
      setNetwork(net);
      setPaths(pth);
      setVerifyData(vfy);
      setRemediation(rem);
      setStatus(st);
      setAppliedFixes(st.summary_metrics.applied_fixes_count
        ? Array.from({ length: st.summary_metrics.applied_fixes_count! }, (_, i) => `fix-0${i + 1}`)
        : []
      );
      setBackendOnline(true);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(`Cannot reach backend: ${msg}. Make sure FastAPI is running on port 8000.`);
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

  return (
    <div className="shell">
      {/* ── Topbar ── */}
      <header className="topbar">
        <div className="topbar-logo">
          <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M12 2L2 7v10l10 5 10-5V7L12 2z" stroke="url(#logoGrad)" strokeWidth="1.5" strokeLinejoin="round" />
            <path d="M12 22V12M2 7l10 5 10-5" stroke="url(#logoGrad2)" strokeWidth="1.5" />
            <defs>
              <linearGradient id="logoGrad" x1="2" y1="2" x2="22" y2="22">
                <stop stopColor="#00d4ff" /><stop offset="1" stopColor="#8b5cf6" />
              </linearGradient>
              <linearGradient id="logoGrad2" x1="2" y1="7" x2="22" y2="17">
                <stop stopColor="#00d4ff" /><stop offset="1" stopColor="#3b82f6" />
              </linearGradient>
            </defs>
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
            <button
              key={sc}
              id={`scenario-${sc}`}
              className={`scenario-tab${scenario === sc ? ' active' : ''}`}
              onClick={() => handleScenarioChange(sc)}
            >
              {sc === 'default' ? '🔴 Adversary' : '🟢 Benign'}
            </button>
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
        activeTab={activeTab}
        onTabChange={t => setActiveTab(t as Tab)}
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
                ? <OverviewTab status={status} paths={paths} verifyData={verifyData} onSwitchTab={t => setActiveTab(t)} />
                : !error && <Loader text="Connecting…" />
          )}

          {/* ── Network ── */}
          {activeTab === 'network' && (
            <>
              <div className="page-header">
                <div className="section-heading">
                  <NetworkIcon size={20} color="var(--accent-cyan)" />
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
                            <td><span style={{ fontWeight: 700, color: h.asset_value >= 80 ? 'var(--accent-red)' : 'var(--text-1)' }}>{h.asset_value}</span></td>
                            <td>
                              <span className={`tag ${h.vectors.length > 0 ? 'tag-amber' : 'tag-green'}`}>
                                {h.vectors.length}
                              </span>
                            </td>
                            <td style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                              {h.is_entry_point && <span className="tag tag-cyan">Entry</span>}
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
                  <AlertTriangle size={20} color="var(--accent-red)" />
                  <div>
                    <h1>Attack Paths</h1>
                    <div className="subtitle">
                      {paths ? `${paths.total_paths} path${paths.total_paths !== 1 ? 's' : ''} enumerated · scenario: ${paths.name}` : ''}
                    </div>
                  </div>
                </div>
                <div className="page-header-actions">
                  {selectedPath && (
                    <span style={{ fontSize: 11, color: 'var(--accent-cyan)' }}>
                      Path highlighted in Network view
                    </span>
                  )}
                  <button
                    id="run-verify"
                    className="btn btn-primary"
                    onClick={() => api.post<VerifyData>('/api/verify').then(setVerifyData)}
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
                />
              ) : null}
            </>
          )}

          {/* ── Remediation ── */}
          {activeTab === 'remediation' && (
            <>
              <div className="page-header">
                <div className="section-heading">
                  <Shield size={20} color="var(--accent-green)" />
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
                />
              ) : null}
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

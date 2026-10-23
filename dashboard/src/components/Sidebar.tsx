import {
  Server, Shield, Activity, Wrench, RotateCcw,
  Network, AlertTriangle, ShieldCheck, BookOpen, Bug
} from 'lucide-react';
import type { StatusData, RemediationData } from '../types';

interface Props {
  status: StatusData | null;
  remediation: RemediationData | null;
  appliedFixes: string[];
  activeTab: string;
  onTabChange: (tab: string) => void;
  onReset: () => void;
  loading?: boolean;
}

/**
 * Remediation nav badge: how many chokepoint fixes (the minimum cover) are
 * still unapplied. Red until any fix is applied, amber after that while paths
 * remain. Hidden once the chokepoint set is applied or no path remains.
 */
function remediationBadge(
  rem: RemediationData | null, applied: string[], pathsRemaining: number | undefined,
): { text: string; tone: '' | ' amber'; title: string } | null {
  const pending = (rem?.minimum_cover?.fixes ?? []).filter(id => !applied.includes(id));
  if (pending.length === 0 || pathsRemaining === 0) return null;
  const parts = [
    `${pending.length} chokepoint fix${pending.length !== 1 ? 'es' : ''} left to break every path (${pending.join(', ')})`,
  ];
  if (pathsRemaining != null) parts.push(`${pathsRemaining} attack path${pathsRemaining !== 1 ? 's' : ''} remaining`);
  return {
    text: String(pending.length),
    tone: applied.length > 0 ? ' amber' : '',
    title: parts.join(' · '),
  };
}

const TABS = [
  { id: 'overview',    label: 'Overview',     icon: Activity },
  { id: 'network',     label: 'Network',      icon: Network },
  { id: 'paths',       label: 'Attack Paths', icon: AlertTriangle },
  { id: 'techniques',  label: 'Techniques',   icon: Bug },
  { id: 'remediation', label: 'Remediation',  icon: Wrench },
  { id: 'docs',        label: 'Methodology',  icon: BookOpen },
];

export default function Sidebar({
  status, remediation, appliedFixes, activeTab, onTabChange, onReset, loading,
}: Props) {
  const m = status?.summary_metrics;
  const remBadge = remediationBadge(remediation, appliedFixes, m?.enumerated_paths);
  return (
    <nav className="sidebar">
      {/* System info */}
      <div style={{ padding: '4px 10px 12px', borderBottom: '1px solid var(--border)', marginBottom: 8 }}>
        <div style={{ fontSize: 11, color: 'var(--text-2)', marginBottom: 2 }}>Analysis Core</div>
        <div style={{ fontSize: 12, color: 'var(--text-1)', fontWeight: 600 }}>
          {status?.version ?? '—'}
        </div>
        <div style={{ fontSize: 10, color: 'var(--text-2)', marginTop: 4 }}>
          {status?.lab_environment ?? '—'}
        </div>
      </div>

      <div className="sidebar-group-label">Navigation</div>
      {TABS.map(tab => {
        const Icon = tab.icon;
        let badge: { text: string; tone: string; title?: string } | null = null;
        if (tab.id === 'paths' && m)
          badge = { text: String(m.enumerated_paths), tone: m.enumerated_paths === 0 ? ' green' : '' };
        if (tab.id === 'remediation') badge = remBadge;
        return (
          <button
            key={tab.id}
            id={`nav-${tab.id}`}
            className={`nav-item${activeTab === tab.id ? ' active' : ''}`}
            onClick={() => onTabChange(tab.id)}
          >
            <Icon className="nav-icon" size={16} />
            {tab.label}
            {badge && (
              <span className={`nav-badge${badge.tone}`} title={badge.title}>
                {badge.text}
              </span>
            )}
          </button>
        );
      })}

      <div className="divider" style={{ margin: '12px 0' }} />
      <div className="sidebar-group-label">Demo Controls</div>

      <button
        id="nav-reset"
        className="nav-item"
        onClick={onReset}
        disabled={loading}
      >
        <RotateCcw className="nav-icon" size={16} />
        Reset State
      </button>

      {/* Metrics summary at bottom */}
      {m && (
        <div style={{ marginTop: 'auto', padding: '16px 10px 4px' }}>
          <div style={{ borderTop: '1px solid var(--border)', paddingTop: 12, display: 'flex', flexDirection: 'column', gap: 8 }}>
            <MetricRow icon={Server} label="Hosts" value={m.hosts_count} />
            <MetricRow icon={AlertTriangle} label="Vectors" value={m.vectors_count} color="var(--accent-amber)" />
            <MetricRow icon={Shield} label="Paths" value={m.enumerated_paths} color="var(--accent-red)" />
            <MetricRow icon={ShieldCheck} label="Verified" value={m.verified_paths} color="var(--accent-green)" />
            {(m.partial_paths ?? 0) > 0 && (
              <MetricRow icon={AlertTriangle} label="Partial" value={m.partial_paths!} color="var(--accent-amber)" tooltip="Paths where every executable step succeeded but at least one step could not be attempted" />
            )}
            {m.precision && (
              <MetricRow icon={ShieldCheck} label="Coverage" value={m.precision} tooltip="Config coverage: fraction of paths whose vectors have the required configuration present" />
            )}
          </div>
        </div>
      )}
    </nav>
  );
}

function MetricRow({ icon: Icon, label, value, color, tooltip }: {
  icon?: React.ComponentType<{ size?: number }>;
  label: string;
  value: string | number;
  color?: string;
  tooltip?: string;
}) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      {Icon && <Icon size={12} />}
      <span
        style={{ fontSize: 11, color: 'var(--text-2)', flex: 1, cursor: tooltip ? 'help' : 'default' }}
        title={tooltip}
      >{label}</span>
      <span style={{ fontSize: 12, fontWeight: 700, color: color ?? 'var(--text-1)' }}>
        {value}
      </span>
    </div>
  );
}

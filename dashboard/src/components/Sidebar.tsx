import {
  Server, Shield, Activity, Wrench, RotateCcw,
  Network, AlertTriangle, ShieldCheck
} from 'lucide-react';
import type { StatusData } from '../types';

interface Props {
  status: StatusData | null;
  activeTab: string;
  onTabChange: (tab: string) => void;
  onReset: () => void;
  loading?: boolean;
}

const TABS = [
  { id: 'overview',    label: 'Overview',     icon: Activity },
  { id: 'network',     label: 'Network',      icon: Network },
  { id: 'paths',       label: 'Attack Paths', icon: AlertTriangle },
  { id: 'remediation', label: 'Remediation',  icon: Wrench },
];

export default function Sidebar({ status, activeTab, onTabChange, onReset, loading }: Props) {
  const m = status?.summary_metrics;
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
        let badge: string | null = null;
        if (tab.id === 'paths' && m) badge = String(m.enumerated_paths);
        if (tab.id === 'remediation' && m?.eliminated_paths_count != null && m.eliminated_paths_count > 0)
          badge = `−${m.eliminated_paths_count}`;
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
              <span className={`nav-badge${tab.id === 'remediation' ? ' green' : ''}`}>
                {badge}
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
            <MetricRow label="Precision" value={m.precision} />
          </div>
        </div>
      )}
    </nav>
  );
}

function MetricRow({ icon: Icon, label, value, color }: {
  icon?: React.ComponentType<{ size?: number }>;
  label: string;
  value: string | number;
  color?: string;
}) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      {Icon && <Icon size={12} />}
      <span style={{ fontSize: 11, color: 'var(--text-2)', flex: 1 }}>{label}</span>
      <span style={{ fontSize: 12, fontWeight: 700, color: color ?? 'var(--text-1)' }}>
        {value}
      </span>
    </div>
  );
}

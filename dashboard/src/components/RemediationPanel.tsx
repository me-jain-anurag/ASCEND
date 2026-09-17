import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer
} from 'recharts';
import { CheckCircle, Star, Zap } from 'lucide-react';
import type { RemediationData, Fix } from '../types';

interface Props {
  data: RemediationData;
  appliedFixes: string[];
  onApply: (fixId: string) => void;
  applying?: string | null;
}

function CustomTooltip({ active, payload }: { active?: boolean; payload?: any[] }) {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  return (
    <div className="custom-tooltip">
      <div style={{ fontWeight: 700, color: 'var(--text-0)', marginBottom: 4 }}>
        {d.fixes_applied} fix{d.fixes_applied !== 1 ? 'es' : ''} applied
      </div>
      <div style={{ color: 'var(--accent-red)', fontSize: 12 }}>
        Paths remaining: {d.paths_remaining}
      </div>
      <div style={{ color: 'var(--accent-green)', fontSize: 12 }}>
        Reduction: {d.reduction_pct}%
      </div>
    </div>
  );
}

function costStars(cost: number) {
  const max = 5;
  return Array.from({ length: max }, (_, i) => (
    <Star key={i} size={10} fill={i < cost ? 'var(--accent-amber)' : 'none'}
      color={i < cost ? 'var(--accent-amber)' : 'var(--text-2)'} />
  ));
}

export default function RemediationPanel({ data, appliedFixes, onApply, applying }: Props) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

      {/* Efficacy curve */}
      <div className="card">
        <div className="card-header">
          <Zap size={16} color="var(--accent-amber)" />
          <h2>Fixes-vs-Paths Efficacy Curve</h2>
        </div>
        <div className="card-body">
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={data.efficacy_curve} margin={{ top: 10, right: 20, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="redGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#f43f5e" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="greenGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="fixes_applied" label={{ value: 'Fixes Applied', position: 'insideBottom', offset: -2, fontSize: 10 }} />
              <YAxis />
              <Tooltip content={<CustomTooltip />} />
              <Area type="monotone" dataKey="paths_remaining" stroke="#f43f5e" fill="url(#redGrad)" name="Paths remaining" strokeWidth={2} />
              <Area type="monotone" dataKey="paths_eliminated" stroke="#10b981" fill="url(#greenGrad)" name="Paths eliminated" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Fix list */}
      <div className="card">
        <div className="card-header">
          <CheckCircle size={16} color="var(--accent-cyan)" />
          <h2>Ranked Chokepoint Fixes</h2>
          <span style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--text-2)' }}>
            {appliedFixes.length} / {data.ranked_fixes.length} applied
          </span>
        </div>
        <div className="card-body">
          <div className="fix-list">
            {data.ranked_fixes.map((fix: Fix) => {
              const isApplied = appliedFixes.includes(fix.fix_id);
              const isApplying = applying === fix.fix_id;
              return (
                <div
                  key={fix.fix_id}
                  className={`fix-card${fix.is_recommended_chokepoint ? ' recommended' : ''}${isApplied ? ' applied' : ''}`}
                >
                  <div className={`fix-rank rank-${fix.rank}`}>#{fix.rank}</div>
                  <div className="fix-body">
                    <div className="fix-title">
                      {fix.title}
                      {fix.is_recommended_chokepoint && (
                        <span className="tag tag-cyan" style={{ marginLeft: 8 }}>⭐ Chokepoint</span>
                      )}
                    </div>
                    <div className="fix-description">{fix.description}</div>
                    <div className="fix-meta">
                      <span className="tag tag-purple">{fix.chokepoint_type}</span>
                      <span className="tag tag-blue">{fix.technique_broken}</span>
                      <span className="tag tag-gray">
                        Host: {fix.target_host}
                      </span>
                      <span title={`Implementation cost: ${fix.cost}/5`} style={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                        {costStars(fix.cost)}
                      </span>
                    </div>
                  </div>
                  <div className="fix-action">
                    <div className="fix-efficacy">{fix.efficacy_percentage.toFixed(0)}%</div>
                    <div style={{ fontSize: 10, color: 'var(--text-2)', textAlign: 'right' }}>
                      Eliminates {fix.paths_eliminated.length} path{fix.paths_eliminated.length !== 1 ? 's' : ''}
                    </div>
                    {isApplied ? (
                      <span className="tag tag-green" style={{ gap: 4 }}>
                        <CheckCircle size={10} /> Applied
                      </span>
                    ) : (
                      <button
                        id={`apply-fix-${fix.fix_id}`}
                        className={`btn ${fix.is_recommended_chokepoint ? 'btn-primary' : 'btn-ghost'}`}
                        onClick={() => onApply(fix.fix_id)}
                        disabled={!!applying || isApplied}
                        style={{ fontSize: 11, padding: '6px 12px' }}
                      >
                        {isApplying ? 'Applying…' : 'Apply Fix'}
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}

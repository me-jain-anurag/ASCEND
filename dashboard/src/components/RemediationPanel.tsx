import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer
} from 'recharts';
import { CheckCircle, AlertTriangle, Zap } from 'lucide-react';
import type { ReactNode } from 'react';
import type { RemediationData, Fix } from '../types';

interface Props {
  data: RemediationData;
  appliedFixes: string[];
  onApply: (fixId: string) => void;
  applying?: string | null;
  /** Path ids proven by execution in the last verify run. */
  verifiedPathIds?: string[];
  /** Whether a verify run has happened at all — an empty list is ambiguous. */
  hasVerifyRun?: boolean;
}

// Efficacy is measured by re-running the path-finder with the fix removed, but
// it is measured against ENUMERATED paths — no path has been execution-verified
// at this point. Say so rather than letting a bare number imply proof.
const NOT_YET_VERIFIED_NOTE =
  'Predicted eliminations. Each figure is measured by removing the fix and ' +
  're-running the path-finder, but against enumerated paths — nothing here has ' +
  'been execution-verified yet. Run Verify to see what actually executed.';

const verifiedNote = (verified: number, total: number) =>
  `Eliminations are measured by removing each fix and re-running the path-finder. ` +
  `${verified} of ${total} enumerated paths are execution-verified; each fix below ` +
  `shows how many of the paths it removes were proven by execution.`;

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
        Eliminated: {d.paths_eliminated}
      </div>
    </div>
  );
}

function WipNote({ children }: { children: ReactNode }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'flex-start', gap: 8,
      padding: '8px 10px', marginBottom: 12,
      border: '1px solid var(--border)', borderLeft: '3px solid var(--accent-amber)',
      borderRadius: 4, background: 'var(--bg-2)',
      fontSize: 11, lineHeight: 1.5, color: 'var(--text-2)',
    }}>
      <AlertTriangle size={13} color="var(--accent-amber)" style={{ flexShrink: 0, marginTop: 1 }} />
      <span>{children}</span>
    </div>
  );
}

export default function RemediationPanel({
  data, appliedFixes, onApply, applying,
  verifiedPathIds = [], hasVerifyRun = false,
}: Props) {
  // total_verified_paths is a legacy field name: the service returns the
  // ENUMERATED count in it. Prefer the correctly named field when present.
  const totalPaths = data.total_enumerated_paths ?? data.total_verified_paths;
  const verifiedSet = new Set(verifiedPathIds);
  const note = hasVerifyRun
    ? verifiedNote(verifiedSet.size, totalPaths)
    : (data._verification_note ?? NOT_YET_VERIFIED_NOTE);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

      {/* Efficacy curve */}
      <div className="card">
        <div className="card-header">
          <Zap size={16} color="var(--accent-amber)" />
          <h2>Fixes-vs-Paths Efficacy Curve</h2>
          <span className="tag tag-gray" style={{ marginLeft: 'auto', fontSize: 10 }}>
            {hasVerifyRun ? 'predicted · verify run complete' : 'predicted'}
          </span>
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
          <WipNote>{note}</WipNote>
          <div className="fix-list">
            {data.ranked_fixes.map((fix: Fix) => {
              const isApplied = appliedFixes.includes(fix.fix_id);
              const isApplying = applying === fix.fix_id;
              const verifiedHere = fix.paths_eliminated.filter(id => verifiedSet.has(id)).length;
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
                      {/* Implementation effort is a hand-written ordinal in
                          scope.yaml, not a measurement. It used to render as a
                          5-star rating, which read as data. Held back until
                          there is a real effort model. */}
                      <span
                        className="tag tag-gray"
                        title="Effort is a hand-written ordinal in scope.yaml, not measured. No effort model is built yet."
                        style={{ opacity: 0.75 }}
                      >
                        Effort: not modelled (WIP)
                      </span>
                    </div>
                  </div>
                  <div className="fix-action">
                    <div className="fix-efficacy">
                      {fix.paths_eliminated.length} / {totalPaths}
                    </div>
                    <div style={{ fontSize: 10, color: 'var(--text-2)', textAlign: 'right', lineHeight: 1.4 }}>
                      paths eliminated
                      <br />
                      {hasVerifyRun ? (
                        <span style={{ color: verifiedHere > 0 ? 'var(--accent-green)' : 'var(--accent-amber)' }}>
                          {verifiedHere} of {fix.paths_eliminated.length} execution-verified
                        </span>
                      ) : (
                        <span style={{ color: 'var(--accent-amber)' }}>predicted — not verified yet</span>
                      )}
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

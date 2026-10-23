import { useState } from 'react';
import { ChevronDown, Shield, CheckCircle, XCircle, AlertTriangle, KeyRound } from 'lucide-react';
import type { AttackPath, VerifyData } from '../types';

interface Props {
  paths: AttackPath[];
  verifyData?: VerifyData | null;
  onSelectPath: (path: AttackPath | null) => void;
  selectedPathId?: string | null;
  /** ATT&CK technique id -> tactic, from /api/knowledge. */
  tactics?: Record<string, string>;
}

function techniqueTag(t: string) {
  return <span className="tag tag-purple" key={t}>{t}</span>;
}

/** Tactic for a technique id. A combined id ("T1021.004+T1550") is looked up
 *  part by part; parts sharing a tactic show it once. Null when unknown. */
function tacticOf(technique: string, tactics: Record<string, string>): string | null {
  const found = technique.split('+').map(id => tactics[id.trim()]).filter(Boolean);
  return found.length ? [...new Set(found)].join(' / ') : null;
}

/**
 * Derive the three-valued path status from the verify result.
 *
 * The API returns a `status` field ("verified" | "partial" | "failed") on
 * each path result. We prefer that when present. Fallback: derive from
 * `overall_verified` boolean + the presence of not_executable steps.
 */
function pathStatus(verResult: { overall_verified: boolean; status?: string; not_executable?: unknown[] } | undefined):
  'unverified' | 'verified' | 'partial' | 'failed' {
  if (!verResult) return 'unverified';
  if (verResult.status) {
    return verResult.status as 'verified' | 'partial' | 'failed';
  }
  return verResult.overall_verified ? 'verified' : 'failed';
}

/**
 * Derive the three-valued step status from a verify step.
 *
 * "escalated"       — technique ran and privilege escalated (step.verified === true)
 * "not_escalated"   — technique ran and did NOT escalate (step.verified === false, but it was attempted)
 * "not_executable"  — technique was never attempted due to a precondition the lab cannot meet
 *
 * The API already returns `status` on each step; we use it when present.
 */
function stepStatus(stepVerify: { verified: boolean; status?: string; reason?: string } | undefined):
  'pending' | 'escalated' | 'not_escalated' | 'not_executable' {
  if (!stepVerify) return 'pending';
  if (stepVerify.status === 'not_executable') return 'not_executable';
  if (stepVerify.status === 'not_attempted') return 'not_executable';
  return stepVerify.verified ? 'escalated' : 'not_escalated';
}

export default function PathList({
  paths, verifyData, onSelectPath, selectedPathId, tactics = {},
}: Props) {
  const [expanded, setExpanded] = useState<string | null>(null);

  if (!paths.length) {
    return (
      <div className="empty-state">
        <Shield size={48} />
        <h3>No attack paths found</h3>
        <p>The current scenario has no enumerated escalation routes to the crown jewel.</p>
      </div>
    );
  }

  return (
    <div className="path-list">
      {paths.map(path => {
        const isExpanded = expanded === path.path_id;
        const isSelected = selectedPathId === path.path_id;
        const verResult = verifyData?.results[path.path_id];
        const pStatus = pathStatus(verResult);

        return (
          <div
            key={path.path_id}
            className={`path-item${isExpanded ? ' expanded' : ''}`}
            onClick={() => {
              const next = isExpanded ? null : path.path_id;
              setExpanded(next);
              onSelectPath(next ? path : null);
            }}
          >
            <div className="path-item-header">
              {/* Path-level badge — four states, three visually distinct */}
              <div style={{ flexShrink: 0 }}>
                {pStatus === 'unverified' ? (
                  <span className="tag tag-gray">Unverified</span>
                ) : pStatus === 'verified' ? (
                  <span className="tag tag-green" style={{ gap: 4 }}>
                    <CheckCircle size={10} /> Verified
                  </span>
                ) : pStatus === 'partial' ? (
                  <span className="tag tag-amber" style={{ gap: 4 }}>
                    <AlertTriangle size={10} /> Partial
                  </span>
                ) : (
                  <span className="tag tag-gray" style={{ gap: 4, borderColor: 'rgba(181,88,75,0.3)', color: '#B5584B', background: 'rgba(181,88,75,0.1)' }}>
                    <XCircle size={10} /> Failed
                  </span>
                )}
              </div>

              {/* Title */}
              <div className="path-item-title">
                <div className="path-name">{path.name}</div>
                <div className="path-sub">
                  {path.entry_host} → {path.crown_jewel_host} &nbsp;·&nbsp; {path.length} steps
                  {isSelected && <span style={{ color: 'var(--accent-partial)', marginLeft: 8 }}>● Graph highlighted</span>}
                  {verResult && pStatus === 'partial' && (
                    <span style={{ marginLeft: 8, color: 'var(--accent-amber)', fontSize: 10 }}>
                      {verResult.steps_verified ?? verResult.steps.filter(s => s.verified).length}/{verResult.steps_total ?? verResult.steps.length} steps proven
                    </span>
                  )}
                </div>
              </div>

              <ChevronDown
                className={`path-chevron${isExpanded ? ' open' : ''}`}
                size={16}
              />
            </div>

            {isExpanded && (
              <div className="path-item-body">
                {/* Partial-path explanation banner */}
                {verResult && pStatus === 'partial' && verResult.not_executable && verResult.not_executable.length > 0 && (
                  <div style={{
                    display: 'flex', alignItems: 'flex-start', gap: 8,
                    padding: '8px 10px', marginBottom: 12,
                    border: '1px solid var(--border)', borderLeft: '3px solid var(--accent-amber)',
                    borderRadius: 4, background: 'var(--bg-2)',
                    fontSize: 11, lineHeight: 1.5, color: 'var(--text-2)',
                  }}>
                    <AlertTriangle size={13} color="var(--accent-amber)" style={{ flexShrink: 0, marginTop: 1 }} />
                    <span>
                      Every step that could be executed succeeded, but {verResult.not_executable.length} step(s) could not
                      be attempted. This path is neither proven nor disproven.
                    </span>
                  </div>
                )}

                <div className="path-steps">
                  {path.steps.map(step => {
                    const stepVerify = verResult?.steps.find(s => s.step_number === step.step_number);
                    const sStatus = stepStatus(stepVerify);

                    // Node visual class
                    const nodeClass =
                      sStatus === 'escalated' ? 'verified' :
                      sStatus === 'not_escalated' ? 'failed' :
                      sStatus === 'not_executable' ? 'not-executable' :
                      '';

                    return (
                      <div key={step.step_number} className="path-step">
                        <div className={`step-node ${nodeClass}`}>
                          {sStatus === 'escalated' ? (
                            <CheckCircle size={14} />
                          ) : sStatus === 'not_escalated' ? (
                            <XCircle size={14} />
                          ) : sStatus === 'not_executable' ? (
                            <AlertTriangle size={14} />
                          ) : (
                            step.step_number
                          )}
                        </div>
                        <div className="step-body">
                          <div className="step-title">
                            {step.description}
                            {sStatus === 'escalated' && (
                              <span className="tag tag-green" style={{ marginLeft: 8, fontSize: 9 }}>escalated</span>
                            )}
                            {sStatus === 'not_escalated' && (
                              <span className="tag tag-red" style={{ marginLeft: 8, fontSize: 9 }}>not escalated</span>
                            )}
                            {sStatus === 'not_executable' && (
                              <span className="tag tag-amber" style={{ marginLeft: 8, fontSize: 9 }}>not executable</span>
                            )}
                          </div>
                          <div className="step-meta">
                            <span>{step.source_host} ({step.source_account.username})</span>
                            <span>→</span>
                            <span>{step.target_host} ({step.target_account.username})</span>
                            {techniqueTag(step.vector.technique)}
                            {tacticOf(step.vector.technique, tactics) && (
                              <span className="tag tag-blue">{tacticOf(step.vector.technique, tactics)}</span>
                            )}
                            {step.vector.cvss != null && (
                              <span className={`tag ${step.vector.cvss >= 7 ? 'tag-red' : step.vector.cvss >= 4 ? 'tag-amber' : 'tag-green'}`}>
                                CVSS {step.vector.cvss.toFixed(1)}
                              </span>
                            )}
                            {step.vector.cve && (
                              <span className="tag tag-gray">{step.vector.cve}</span>
                            )}
                          </div>

                          {/* Not-executable reason — inline, from the real API data */}
                          {sStatus === 'not_executable' && stepVerify?.reason && (
                            <div style={{
                              marginTop: 6, padding: '6px 10px',
                              background: 'rgba(245,158,11,0.08)',
                              border: '1px solid rgba(245,158,11,0.2)',
                              borderRadius: 4, fontSize: 11, lineHeight: 1.5,
                              color: 'var(--accent-amber)',
                              display: 'flex', alignItems: 'flex-start', gap: 6,
                            }}>
                              <AlertTriangle size={12} style={{ flexShrink: 0, marginTop: 1 }} />
                              {stepVerify.reason}
                            </div>
                          )}

                          {/* Verified evidence */}
                          {stepVerify && sStatus !== 'not_executable' && (
                            <div className="step-evidence">
                              <div>$ {stepVerify.evidence.stdout}</div>
                              <div className="telemetry">{stepVerify.evidence.telemetry}</div>
                            </div>
                          )}

                          {/* Credential info */}
                          {step.credential && (
                            <div style={{ marginTop: 6, fontSize: 11, color: 'var(--text-2)', display: 'flex', alignItems: 'center', gap: 6 }}>
                              <KeyRound size={12} color="var(--accent-partial)" />
                              Credential: <span style={{ color: 'var(--accent-partial)' }}>{step.credential.type}</span> — {step.credential.discoverable_at}
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

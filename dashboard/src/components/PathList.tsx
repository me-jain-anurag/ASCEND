import { useState } from 'react';
import { ChevronDown, Shield, CheckCircle, XCircle } from 'lucide-react';
import type { AttackPath, VerifyData } from '../types';

interface Props {
  paths: AttackPath[];
  verifyData?: VerifyData | null;
  onSelectPath: (path: AttackPath | null) => void;
  selectedPathId?: string | null;
}

function techniqueTag(t: string) {
  return <span className="tag tag-purple" key={t}>{t}</span>;
}

export default function PathList({ paths, verifyData, onSelectPath, selectedPathId }: Props) {
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
              {/* Verified badge */}
              <div style={{ flexShrink: 0 }}>
                {verResult === undefined ? (
                  <span className="tag tag-gray">Unverified</span>
                ) : verResult.overall_verified ? (
                  <span className="tag tag-red" style={{ gap: 4 }}>
                    <CheckCircle size={10} /> Verified
                  </span>
                ) : (
                  <span className="tag tag-amber" style={{ gap: 4 }}>
                    <XCircle size={10} /> Failed
                  </span>
                )}
              </div>

              {/* Title */}
              <div className="path-item-title">
                <div className="path-name">{path.name}</div>
                <div className="path-sub">
                  {path.entry_host} → {path.crown_jewel_host} &nbsp;·&nbsp; {path.length} steps
                  {isSelected && <span style={{ color: 'var(--accent-cyan)', marginLeft: 8 }}>● Graph highlighted</span>}
                </div>
              </div>

              <ChevronDown
                className={`path-chevron${isExpanded ? ' open' : ''}`}
                size={16}
              />
            </div>

            {isExpanded && (
              <div className="path-item-body">
                <div className="path-steps">
                  {path.steps.map(step => {
                    const stepVerify = verResult?.steps.find(s => s.step_number === step.step_number);
                    const nodeStatus = stepVerify === undefined
                      ? ''
                      : stepVerify.verified ? 'verified' : 'failed';

                    return (
                      <div key={step.step_number} className="path-step">
                        <div className={`step-node ${nodeStatus}`}>
                          {stepVerify?.verified === false ? (
                            <XCircle size={14} />
                          ) : stepVerify?.verified ? (
                            <CheckCircle size={14} />
                          ) : (
                            step.step_number
                          )}
                        </div>
                        <div className="step-body">
                          <div className="step-title">{step.description}</div>
                          <div className="step-meta">
                            <span>{step.source_host} ({step.source_account.username})</span>
                            <span>→</span>
                            <span>{step.target_host} ({step.target_account.username})</span>
                            {techniqueTag(step.vector.technique)}
                            {step.vector.cvss !== undefined && (
                              <span className={`tag ${step.vector.cvss >= 7 ? 'tag-red' : step.vector.cvss >= 4 ? 'tag-amber' : 'tag-green'}`}>
                                CVSS {step.vector.cvss.toFixed(1)}
                              </span>
                            )}
                            {step.vector.cve && (
                              <span className="tag tag-blue">{step.vector.cve}</span>
                            )}
                          </div>

                          {/* Verified evidence */}
                          {stepVerify && (
                            <div className="step-evidence">
                              <div>$ {stepVerify.evidence.stdout}</div>
                              <div className="telemetry">⚡ {stepVerify.evidence.telemetry}</div>
                            </div>
                          )}

                          {/* Credential info */}
                          {step.credential && (
                            <div style={{ marginTop: 6, fontSize: 11, color: 'var(--text-2)' }}>
                              🔑 Credential: <span style={{ color: 'var(--accent-amber)' }}>{step.credential.type}</span> — {step.credential.discoverable_at}
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

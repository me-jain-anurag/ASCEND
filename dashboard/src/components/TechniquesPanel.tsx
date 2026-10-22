import type { KnowledgeData } from '../types';

/**
 * Reference view: the ATT&CK techniques and CVEs this project demonstrates,
 * in plain language. Data comes from GET /api/knowledge (the restricted
 * knowledge pack), and each row says whether it is present in the currently
 * loaded lab or is in-scope reference material.
 */
function StatusTag({ inLab }: { inLab: boolean }) {
  return inLab
    ? <span className="tag tag-green">In lab</span>
    : <span className="tag tag-gray">Reference</span>;
}

export default function TechniquesPanel({ data }: { data: KnowledgeData }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="card">
        <div className="card-header">
          <h2>ATT&amp;CK techniques</h2>
          <span className="tag tag-gray" style={{ marginLeft: 'auto' }}>
            {data.demonstrated_count} demonstrated in the lab
          </span>
        </div>
        <div className="card-body" style={{ padding: 0 }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>ID</th><th>Technique</th><th>Tactic</th><th>Status</th><th>What it is</th>
              </tr>
            </thead>
            <tbody>
              {data.techniques.map(t => (
                <tr key={t.attack_id}>
                  <td><span className="mono">{t.attack_id}</span></td>
                  <td style={{ color: 'var(--text-0)', fontWeight: 500 }}>{t.name}</td>
                  <td><span className="tag tag-blue">{t.tactic}</span></td>
                  <td><StatusTag inLab={t.present_in_lab} /></td>
                  <td style={{ maxWidth: 440, lineHeight: 1.55 }}>{t.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h2>Demonstrated CVEs</h2>
          <span className="tag tag-gray" style={{ marginLeft: 'auto', fontSize: 10 }}>
            {data.source}
          </span>
        </div>
        <div className="card-body" style={{ padding: 0 }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>CVE</th><th>Name</th><th>CVSS</th><th>Maps to</th>
                <th>Status</th><th>Affected</th><th>Summary</th>
              </tr>
            </thead>
            <tbody>
              {data.cves.map(c => {
                const sev = c.base_cvss ?? 0;
                return (
                  <tr key={c.cve_id}>
                    <td><span className="mono">{c.cve_id}</span></td>
                    <td style={{ color: 'var(--text-0)', fontWeight: 500 }}>{c.name}</td>
                    <td>
                      <span className={`tag ${sev >= 7 ? 'tag-red' : sev >= 4 ? 'tag-amber' : 'tag-green'}`}>
                        {sev.toFixed(1)}
                      </span>
                    </td>
                    <td><span className="mono">{c.attack_id}</span></td>
                    <td><StatusTag inLab={c.present_in_lab} /></td>
                    <td style={{ fontSize: 11, color: 'var(--text-2)' }}>{c.affected}</td>
                    <td style={{ maxWidth: 360, lineHeight: 1.55 }}>{c.description}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

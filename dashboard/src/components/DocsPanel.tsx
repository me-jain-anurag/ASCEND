import type { ReactNode } from 'react';

/**
 * In-app methodology reference. Every number the dashboard shows is derived,
 * not asserted — this tab says exactly how, so a reader never has to trust a
 * figure on faith. Kept in sync with service/main.py and chokepoint/engine.py.
 */

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="doc-section">
      <h3 className="doc-h">{title}</h3>
      {children}
    </div>
  );
}

export default function DocsPanel() {
  return (
    <div className="doc-body">

      <Section title="What the numbers mean">
        <p>
          ASCEND finds privilege-escalation routes from the entry host to the
          crown jewel, then proves each by executing it in an isolated lab. Every
          figure below is computed from the collected facts or from a real
          execution run — none is hand-entered.
        </p>
      </Section>

      <Section title="Config coverage vs. execution precision">
        <p>
          Two different questions, deliberately kept apart:
        </p>
        <ul className="doc-list">
          <li>
            <b>Config coverage</b> — the fraction of enumerated paths whose
            vectors all have the required configuration present in the facts. It
            answers &ldquo;does the environment look exploitable?&rdquo; and is
            available without running anything.
          </li>
          <li>
            <b>Execution precision</b> — the fraction of enumerated paths proven
            end-to-end by actually running every step in the lab. A path with a
            step the lab cannot execute (e.g. a kernel exploit needing a
            vulnerable kernel) is <i>partial</i>, and counts against precision
            because it is not proven.
          </li>
        </ul>
        <p>
          Coverage can be 100% while precision is lower — that gap is the point:
          configuration present is not the same as attack proven.
        </p>
      </Section>

      <Section title="Path risk score — not yet scored">
        <p>
          Paths are not given a risk score yet. The score will come from the
          exploitability scorer planned for Semester 2, which predicts how likely
          each vector is to work. Until then the dashboard shows only what was
          derived from the facts or proven by execution.
        </p>
      </Section>

      <Section title="Remediation — ranked fixes">
        <p>
          Each fix&rsquo;s effect is <b>measured, not estimated</b>: the fix is
          removed from a copy of the facts and the path-finder is re-run, so the
          predicted elimination equals the effect of actually applying it.
        </p>
        <ul className="doc-list">
          <li><b>paths eliminated / efficacy %</b> — how many of the enumerated
            paths that fix removes.</li>
          <li><b>Chokepoint</b> — the first fix of the minimum set that covers
            every path, chosen by greedy weighted set-cover (paths eliminated per
            unit of cost). It is the &ldquo;fewest fixes, most paths&rdquo; answer.</li>
          <li><b>Ranking ties</b> — fixes that eliminate the same number of paths
            are ordered by cost, cheaper first.</li>
          <li><b>Effort</b> — a hand-written ordinal in <span className="doc-code">scope.yaml</span>,
            shown as &ldquo;not modelled&rdquo; because no real effort model exists yet.</li>
        </ul>
      </Section>

      <Section title="Path &amp; step status">
        <ul className="doc-list">
          <li><b>Verified</b> — every step ran and escalated privilege.</li>
          <li><b>Partial</b> — every step that could be attempted succeeded, but
            at least one could not be executed in this lab. Neither proven nor
            disproven.</li>
          <li><b>Failed</b> — a step ran and did not escalate: a real negative.</li>
          <li><b>Unverified</b> — no execution run has been performed yet.</li>
        </ul>
      </Section>

      <Section title="Observed vs. declared facts">
        <p>
          Most facts are measured on the live hosts (file modes, key
          fingerprints, <span className="doc-code">sudo -l</span>, open ports,
          reachability). Per-host kernel versions are <b>declared</b>, because
          containers share one kernel — any vector derived from a declared fact
          is marked as such.
        </p>
      </Section>

    </div>
  );
}

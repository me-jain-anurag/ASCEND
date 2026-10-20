# Dashboard UI direction and external-tool integration

Status: proposal / backlog. Nothing here is scheduled yet — this captures the
agreed direction so the detail work can happen later without re-deciding it.

## 1. Where the dashboard is now

The dashboard shows the real pipeline: network topology, enumerated attack
paths, execution-verified results, ranked chokepoint fixes, a techniques/CVE
reference, and a methodology page. A first pass has already moved it off the
"generic KPI dashboard" look — flat surfaces, status-only colour, no emoji, a
light and a dark theme, and per-metric explanations.

## 2. Target visual direction

Model the layout and workflow on real security tooling rather than a generic
admin template. Useful references:

- **Splunk Enterprise Security** — for layout and workflow: dedicated incident
  review, security posture, risk analysis and investigation screens, not a wall
  of KPI cards.
- **Wazuh** — for how practical security data is laid out (events, agents,
  rules, compliance).
- **Grafana** — for restrained, readable charts.

Design rules to hold to:

- Compact sidebar with clear sections (Overview, Attack Paths, Techniques,
  Remediation, Methodology — extendable to Alerts / Incidents / Assets / Audit
  as those exist).
- Rectangular panels with subtle borders and consistent spacing — not rounded
  cards everywhere.
- Tables are a major part of the screen: stable columns (identifier, source,
  target/asset, severity, status, timestamp), monospaced identifiers.
- Red = critical, amber = warning, green = healthy — semantic, never
  decorative.
- Simple line charts, timelines and horizontal bars with readable legends over
  elaborate visualizations.
- Realistic sample data with consistent, plausible timestamps and meaningful
  empty states.
- Functional filters, search, sorting, pagination and a detail view for a
  single path / finding.

### Redesign backlog (unscheduled)

1. Convert the remaining rounded "cards" to bordered rectangular panels with one
   consistent spacing scale.
2. Promote the path list to a sortable, filterable table (by risk, status,
   length, technique) with a dedicated path-detail view.
3. Add a findings/ run timeline (verification runs over time) once runs are
   persisted.
4. Search + pagination on the techniques and (future) events tables.
5. Consistent, realistic timestamps on everything that has a time.

## 3. External-tool integration (idea to evaluate later)

**The question:** should ASCEND let a team connect tools they already run
(SIEM, vulnerability scanners, monitoring) instead of being a closed dashboard?

**Assessment — worth doing, but as a later phase, not now.** It fits ASCEND's
position well: the product's value is the *execution-proven* attack path and the
measured chokepoint, and that becomes far more useful when it lands in the
tools a team already watches. Two complementary directions:

- **Outbound (push ASCEND findings out)** — highest value, lowest risk. Emit
  proven paths and chokepoint fixes as structured events: a webhook, a
  Splunk HEC / syslog forwarder, an Elastic/Wazuh index, or simply an
  export (JSON / CSV / STIX-ish). A team sees "path web01 → db01:root proven"
  as an alert in their existing console.
- **Inbound (pull context in)** — more work, more care. Import asset inventory
  / CMDB, existing vuln-scan results, or live monitoring state to enrich the
  environment graph (asset values, which hosts are already watched). This
  touches the collector and the facts schema, so it needs design.

**Recommendation.** Start with outbound export/webhook of findings — small,
decoupled, and it does not risk the integrity of the execution-truth core.
Treat inbound enrichment as a separate, later design once the facts schema is
stable. Keep any integration optional and clearly separated from the proven
core so an external feed can never be mistaken for execution ground truth.

**Risks to respect:** don't let imported (unverified) data blur the line
ASCEND is built on — observed/execution-proven vs. declared/asserted. Any
pulled-in data is "declared" until ASCEND proves it, and must be labelled that
way, exactly as the kernel-version provenance is today.

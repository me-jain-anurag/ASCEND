# 10 — System Flow and Live Demo (flow of record)

> **Status:** Authoritative for the system design going forward. Extends
> `ASCEND_Plan_of_Record.md` with (a) the two-mode model, (b) scanner
> integration, (c) the weakness catalogue + scenario generator, and (d) the
> multi-host / VM live demo. Where this doc and older docs differ on these four
> topics, this doc wins. Dated 2026-11-14.

This is the document to read before building anything new. It says what ASCEND
*is for whom*, how data flows for a developer and for a user, and how the live
demo is staged. The research/paper side is in `11_Research_Narrative_and_Paper_Plan.md`.

---

## 1. Two modes, one engine (the load-bearing decision)

ASCEND's headline claim is "we do not predict, we **execute** each path." That
claim is true only in a lab — you can never run exploits against a real
production network. Earlier drafts blurred this, which made the tool's selling
point the one thing a real user cannot do. We split it cleanly:

| | **Lab mode** (offline, R&D) | **Assessment mode** (production, real use) |
|---|---|---|
| Input | planted scenario | read-only facts from a real network, or imported scanner output |
| Reasoning | enumerate paths | enumerate paths (same engine) |
| Reality check | **execute every step**, canary-verified | **none** — execution is never run in production |
| Output | precision/recall of the engine + labelled dataset | ranked chokepoint fixes, each with a confidence |
| Purpose | **calibrate and prove the engine is correct** | **deploy the proven engine** |

**The one sentence for the panel:** *"We build an execution-grounded lab to
prove our reasoning engine is correct, then we deploy that same engine,
read-only, against real networks. Execution is how we earn the right to be
believed in production, not something we pretend to do there."*

Consequence: the enumerator and chokepoint engine are **mode-agnostic** and must
stay so. Only the fact source (planted lab vs real host vs scanner import) and
the presence/absence of the verifier differ between modes.

---

## 2. Developer flow (end to end)

```
weakness catalogue              scenario blueprint (YAML)
(reusable, verifiable plants) ──► hosts · roles · segments · chosen weaknesses
         │                                     │
         └───────────────────┬─────────────────┘
                             ▼
                 generator / orchestrator
       (emit VM/compose + seed, bring the lab up, reset)
                             ▼
   collect ─► enumerate ─► VERIFY (execute) ─► outcomes.jsonl (labels)
                             │                        │
                             └─► chokepoint rank ─► apply fix ─► re-run ─► proof loop
                             ▼
             metrics harness  (run across MANY generated variants)
                             ▼
             service (FastAPI) ─► dashboard + live log stream (SSE)
```

New vs today:
- **weakness catalogue** and **generator** do not exist yet — they are the
  unlock (see §4). Today a weakness is spread across a seed script, `scope.yaml`
  and a verify adapter.
- **metrics harness across variants** replaces hand-reading a single lab (§7 of
  doc 11).
- **live log stream** is new (SSE from each stage to the dashboard).

Everything up to the verifier is **reasoning** ("the door appears unlocked"); the
verifier is **reality** ("we walked through it"). Keep that split visible in the
code, as now.

---

## 3. User flow (two personas)

**Security engineer — assessment mode (the real product):**
1. Point ASCEND at a network *or* drop in a Trivy image scan + a Lynis host audit.
2. See the network graph and the enumerated routes to the crown jewel.
3. See the top fixes: "applying these 3 removes N of M routes," ranked by
   paths-removed-per-cost.
4. Export a remediation plan. **No exploit is ever run.** Confidence on each
   route comes from the lab-calibrated engine.

**Reviewer / presenter — lab mode (the demo and the proof):**
1. Pick or build a scenario.
2. Watch the lab come up; watch collect → enumerate → verify stream live.
3. See verified vs partial vs unverified routes on the graph.
4. **Add another host live** (e.g. a second database with a weak sudo rule);
   watch it get collected, the new route appear, the ranking update.
5. Apply the top fix; watch the route disappear on re-run.

The demo *is* the research method made visible. The whole build points at it.

---

## 4. Weakness catalogue + scenario generator (the main new component)

### 4.1 Weakness catalogue

One self-contained, parameterised unit per plantable weakness, replacing today's
spread across seed/`scope.yaml`/adapter. Each catalogue entry declares:

- `technique` — ATT&CK ID (reuses the seven in `scope.yaml`, extensible).
- `seed` — how to plant it on a host (idempotent script fragment, parameterised).
- `evidence` — the raw fact a collector probe must observe for it to be derived.
- `verify` — adapter + success check (canary-based).
- `remediation` — the fix and its ordinal cost.
- `executable_in` — `container` | `vm` | `either` (so T1068 is marked `vm` only).

### 4.2 Scenario blueprint

A blueprint is the whole lab as data:

```yaml
scenario: "two-db-fan-in"
hosts:
  - id: web01   {role: web,      segment: dmz,  asset: 10,  weaknesses: [readable_ssh_key]}
  - id: app01   {role: app,      segment: both, asset: 30,  weaknesses: [nopasswd_tar, reused_key]}
  - id: db01    {role: database, segment: core, asset: 100, weaknesses: [suid_find, dirtypipe_kernel]}
  - id: db02    {role: database, segment: core, asset: 100, weaknesses: [nopasswd_vim]}
entry:       {host: web01, account: www-data, privilege: low}
crown_jewel: {host: db01,  privilege: root}
```

### 4.3 Generator / orchestrator

Blueprint → materialised lab. Responsibilities:
- Emit per-host VM definitions (and/or compose services for the container
  fallback) and seed scripts from the catalogue.
- Bring the lab up on the chosen placement (one laptop or several); reset to an
  identical state on demand.
- **Hot-add a host** at runtime: materialise one new VM, join it to the network,
  trigger a re-collect — no full rebuild.
- Stream every step to the log pane.

Design rule: the generator writes the same `facts.json`/`scope.yaml`-shaped
inputs the engine already consumes, so the enumerator/verifier/chokepoint code
does not change. The generator is an input producer, nothing more.

---

## 5. Scanner integration (Trivy / Lynis / OpenVAS)

ASCEND is **not** a scanner and never competes with one. Scanners find CVEs and
misconfigurations on a single host; ASCEND chains findings across hosts into
paths. Scanners play three roles:

1. **Input adapter (assessment mode).** Ingest Trivy image scans and Lynis host
   audits as `declared` facts, so a real org needs to install nothing new. Each
   imported fact keeps provenance `declared` and its source tool.
2. **Baseline comparator (the paper).** A scanner hands you a CVSS-sorted list.
   ASCEND's job is to show path-aware ranking beats severity-only ranking. Trivy
   severity order is a named, reproducible baseline (fixes "compared to what?").
3. **Credibility.** "Works with the tools you already run" beats "install our
   stack."

Keep the execution-truth core intact: imported scanner facts are `declared`,
never counted as `observed` or `verified`. Labelling is non-negotiable.

---

## 6. The live demo (multi-host, VM, isolated)

### 6.1 Topology
- **Console** — one laptop runs ASCEND (service + dashboard + orchestrator) and
  drives the demo. Shows the graph and ranked fixes.
- **Targets** — each host is a **VM** (own kernel → T1068 is genuinely
  executable, resettable). VMs are placed across 2–4 laptops for impact, or all
  on the console laptop as the fallback. Placement is a deployment detail; the
  lab is "N VMs" regardless.

### 6.2 Network (no hardware purchased)
- **Primary:** all target VMs on a hypervisor **internal network**. The lab LAN
  lives inside the hypervisor, touches no wifi, and is air-gapped by
  construction. Nothing to configure at the venue.
- **If VMs span laptops:** one laptop or a phone runs a **hotspot**; the other
  laptops join it. We own that LAN; it is isolated from campus; venue
  laptop-to-laptop blocking ("AP isolation") does not apply.
- **Never** put the lab on venue wifi directly.

### 6.3 Safety story (say it before the panel asks)
The lab network has no route to campus or the internet (internal virtual net, or
our own hotspot with no uplink). Real exploits run only inside throwaway VMs on
that isolated net. No exploit code ships in the repo; it is brought separately
and mounted only into the lab. Tear-down discards the VMs.

### 6.4 "Add a system" live
Boot a prepared VM (on any laptop) from a catalogue blueprint → it joins the
internal net → `orchestrator add-host` → ASCEND re-collects, re-enumerates, and
the graph/paths/fixes update live, with the log pane narrating each step. This is
the moment that answers "can you handle another database?".

### 6.5 Backup
The single-laptop **container lab** (today's `lab/`) stays as the
guaranteed-to-work fallback — resets in seconds — if venue networking or VM
performance misbehaves. Multi-laptop VMs are the primary for impact; containers
are the net. The container lab cannot execute T1068; say so and show it as
`not_executable` rather than hiding it.

---

## 7. What exists vs what is left (build order)

**Exists (code, reconciled):** collectors (9 probes) → `facts.json`; enumerator
(stdlib state-space search, 2 routes); verifier (canary-based, 3 adapters);
chokepoint engine (greedy weighted set-cover + exact cross-check); service
(FastAPI) + dashboard (React, light/dark, techniques & methodology tabs);
4-container lab; 52 tests.

**Left, in order:**
1. **Weakness catalogue + scenario generator** (§4) — unlocks the demo *and* the
   metrics. Do first.
2. **Live log stream** (SSE) + dashboard log pane; hot-add-host action (§6.4).
3. **VM lab path** (per-host VMs, internal net) + real T1068 execution; keep the
   container lab as fallback.
4. **Assessment mode + scanner import** (§5): Trivy/Lynis adapters, `declared`
   labelling, baseline comparison.
5. **Metrics harness** across generated variants (doc 11 §5).
6. **Exploitability scorer** (ML) — last, secondary to execution, must beat the
   baselines or be dropped and reported.

Rationale: the generator is the keystone — the live demo, the real `n`, and the
held-out evaluation all depend on it, so it comes before the scorer and before
assessment mode.

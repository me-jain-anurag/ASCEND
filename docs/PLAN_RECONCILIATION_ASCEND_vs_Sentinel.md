# Plan reconciliation — ASCEND (attached PDF) vs Sentinel Implementation Plan v2 (in repo)

> Short answer: **they are not the same plan.** The attached **ASCEND** PDF is a
> newer, narrower re-centring that **supersedes** `Sentinel_Implementation_Plan_v2.pdf`.
> The repository's **code and primary docs already follow ASCEND** — the Sentinel v2
> PDF is the earlier plan, kept for history. `docs/00_START_HERE_Index.md` already
> records this pivot under "What changed from Sentinel".

## How they relate

Sentinel v2 and ASCEND share the same course context and a lot of DNA, but they make
a **different core research claim**:

- **Sentinel v2** — *predict* the attacker's likely **next step** from a live event
  stream and produce a risk score. The headline result is an ML model's accuracy on a
  dataset the team generated.
- **ASCEND** — *enumerate* privilege-escalation paths, **execute each one in the lab to
  prove it works**, then compute the **minimum-cost set of fixes (chokepoints)** and
  prove the paths disappear. The headline result is the observable before/after
  remediation experiment, not a number.

ASCEND deliberately keeps the good parts of Sentinel (scope-locking via `scope.yaml`,
the three-graph model, anti-data-leakage discipline, baselines-before-fancy-models) and
re-anchors on something that can be **proven by execution instead of asserted**.

## What they share

- DSCE / ISE final-year project, Aug 2026 – June 2027, build by ~Jan 2027 then a paper.
- Isolated Linux lab; MITRE ATT&CK-scoped; `scope.yaml` + `demo.md` as controlling artefacts.
- Knowledge graph CVE → CWE → CAPEC → ATT&CK (with description text), built **first**.
- Environment graph (hosts / services / vulns / reachability) linked into the knowledge graph.
- Anti-leakage: split by lab variant / experiment; keep benign look-alikes, failed attempts,
  background traffic; remove only malformed records and exact duplicates.
- Baselines must be beaten or the fancy model is dropped and that is reported honestly.
- React dashboard; ~90-second review demo; p95 < 5 s latency target.

## Concrete differences

| Dimension | Sentinel v2 (repo PDF) | ASCEND (attached PDF) |
|---|---|---|
| **Core thesis** | Predict next attack step + risk score | Enumerate → execute/verify paths → min-cost chokepoint fixes → proof loop |
| **Headline result** | ML model accuracy on self-generated data | Before/after remediation experiment (observable, not a number) |
| **Contribution framing** | Intersection of two base papers (text-KG for runtime prediction) | "Prior work predicts, ASCEND proves" (execution + optimised remediation) |
| **Techniques in scope** | 4: T1190 (Log4Shell), T1068, T1021.004, T1041 | 7: T1548.001, T1548.003, T1068, T1611, T1021.004, T1078.003, T1552.x |
| **Anchor CVE(s)** | Log4Shell CVE-2021-44228 (initial access) | PwnKit CVE-2021-4034 + DirtyPipe CVE-2022-0847 (priv-esc) |
| **Initial access / exfil** | In scope (T1190 / T1041) | Out of scope (single web foothold; no exfil technique) |
| **Lab** | 4 containers (attacker, web, db, collector); VM fallback | 10 hosts incl. 2 QEMU/KVM VMs — db01 (vuln kernel) + db02 (patched control) — plus web01, ci01, nfs01, admin01, app01, app02, collector01 |
| **VMs** | None by default | Required, because DirtyPipe is a kernel bug |
| **Role of ML** | Central (next-step prediction is the product) | Secondary — exploitability scorer; must beat simple rules or be cut; GNN is a stretch |
| **ML model** | Graph Attention Network (Gao et al.); baselines: majority, Markov | Logistic regression → gradient-boosted trees; baselines: majority, "CVSS ≥ 7", scanner-flag |
| **Execution verification** | Absent (emulation logs double as labels, no path is run to prove it) | **The core contribution** — every path executed, success proven by per-host tokens |
| **Remediation / optimisation** | None | Chokepoint engine: greedy weighted set-cover + exact min-cost cut (OR-Tools/PuLP) + proof loop |
| **Runtime / live pipeline** | Central (event → predict → dashboard, near real-time) | Not the focus; batch enumerate + verify; read-only "assessment mode" is a stretch |
| **Attack execution tool** | MITRE Caldera or Atomic Red Team | Team scripts per technique + Atomic Red Team where one exists; public PoC for PwnKit/DirtyPipe |
| **Base papers** | Gao et al. 2026; Ben Fredj & Cheikhrouhou 2026 | PIGNN; compared against BloodHound/GoLinHound and MulVAL |
| **Dataset** | Branching scenarios, experiment-level split | Lab generator → ≥ 30 seeded variants + decoys |
| **Dashboard detail** | Live path, predicted next step, risk | React + Cytoscape.js: network view, path list, verification state; scores/fixes added in Phase 2 |
| **Phase structure** | Phases 0–8 (linear) | Phase 1 (foundation) + Phase 2 (ML & remediation), milestones M0–M8, Phase-1 gate mid-Jan 2027 |

## Recommended source of truth

**Adopt ASCEND as the single source of truth**, because:

1. The repository code already implements it — `collectors/`, `enumerator/`, `verifier/`,
   `chokepoint/`, `environment_graph/`, `knowledge_graph/`, `scope.yaml`
   (seven techniques), and recent commits ("three verified paths and precision 0.5",
   "remediation panel", "db01 … route to root") are all ASCEND, not Sentinel.
2. `docs/00_START_HERE_Index.md` already states the pivot away from Sentinel.
3. ASCEND's headline (execution-verified paths + proved remediation) is more defensible
   at review than Sentinel's self-generated-accuracy number.

Fold in from Sentinel only what ASCEND does not already have and still wants:
- Keep the three-graph terminology and data-flow separation (ASCEND already uses it).
- Treat next-step **prediction + risk scoring** as an **optional runtime/assessment-mode
  extension**, clearly secondary to execution + remediation.

### Resolved
- The old Sentinel plan (`Sentinel_Implementation_Plan_v2.pdf`) and synopsis
  (`Sentinel_Synopsis.docx`) are archived in `docs/legacy/`. The `docs/00`–`docs/09`
  markdown set is the **current ASCEND documentation** (it is written as ASCEND and is
  referenced throughout the code) and stays in place, so there is one plan of record.

# 11 — Research Narrative and Paper Plan

> **Status:** Authoritative for how we write up ASCEND. Pairs with
> `10_System_Flow_and_Live_Demo.md` (the system side). Dated 2026-11-14.
> Citation policy for this project: **2024 or later** is acceptable; prefer 2025+.

---

## 1. Writing stance — observation → response

The paper is written as a **research journey**, not a brochure. The strongest
thing a student team can show a panel is that it *found its own problems and did
something about them*. So every limitation we hit is written as a pair:

> **We observed** that X did not hold / did not work. **We responded** by doing Y,
> and here is the evidence that Y is better.

This runs as a thread through the paper (a "Design Evolution / Lessons" section,
plus short limitation notes where relevant), and it is honest: we would rather
report a zero with a reason than a rounded-up number.

---

## 2. The documented shortfalls and our responses (the spine of the story)

These are real problems we identified in the Phase I design and the first paper
draft. Each becomes an observation → response pair in the write-up.

| # | We observed | We responded |
|---|---|---|
| 1 | A container shares the host kernel, so T1068 (DirtyPipe) can never be executed — the flashiest step was faked (`declared`, `not_executable`). | Moved to a **per-host VM testbed**; each host has its own kernel, so kernel-level privilege escalation is genuinely observed and executed. |
| 2 | A single planted lab makes evaluation **circular** (we wrote both the question and the answer key) and `n` is tiny (2 paths, 1 chokepoint). | Built a **scenario generator** producing many lab variants with decoys; metrics are reported across variants, split by variant to prevent leakage. |
| 3 | Execution — the headline — is **impossible in production**; no real user can run exploits against live systems. | Split into **two modes**: lab execution *calibrates and proves* the engine; a read-only **assessment mode** deploys the proven engine in production. |
| 4 | Chokepoint ranking had **no named baseline**; "better than CVSS" was unquantified. | Adopted **scanner severity order (Trivy/CVSS) and random order** as explicit baselines, and ingest scanner output as input too. |
| 5 | The first paper's "scoring" (edge-likelihood product + betweenness) was **neither learned nor novel**, and the code did set-cover — paper and code disagreed. | Reframed scoring as an optional, **secondary** learned exploitability scorer that must beat the baselines or be dropped; made the paper describe what the code does. |
| 6 | Internal inconsistencies in the first draft (T1550 vs T1078.003; Table II cites [25] with only 13 refs; Section VI promises results it does not show). | Reconciled taxonomy, fixed references, and aligned Phase I results to the actual run (doc `REPORT_REMAINING_FIXES.md`). |

This table is the backbone of both the paper's novelty argument and the viva
answers.

---

## 3. Phase I paper — finish and align to code (do now)

The attached Phase I draft is a solid *design* paper but incomplete and
code-divergent. Actions:
- Apply the pending corrections in `docs/REPORT_REMAINING_FIXES.md` (test counts,
  latency, precision wording, reference hygiene).
- Resolve the **T1550 vs T1078.003** taxonomy (recommendation: keep the code's
  T1550 and change the paper, since editing prose is cheaper than code).
- Fix **Section VI**: either present the honest small result (2 routes, 1
  verified, 1 `not_executable` with the kernel reason) *or* label the section
  clearly as design + evaluation-plan only. Do not promise results that are not
  shown.
- Fix the **reference numbering** (Table II cites [25]; the list must support
  every citation).
- Add a short **Limitations / Design Evolution** paragraph seeded from §2 — this
  is where the "we noticed problems" voice first appears.

Phase I stays a legitimate standalone paper: isolated lab + ground-truth design +
a working, if small, verified pipeline.

---

## 4. Phase II paper — the headline (write as the engine lands)

This is the paper the project is really for. Contributions:
1. **Execution-grounded benchmark** via the scenario generator — many lab
   variants with ground-truth paths established by execution, not labels.
2. **Two-mode architecture** — lab calibration + read-only production
   assessment, with scanner integration.
3. **Chokepoint remediation with a proof loop** — apply the fix, re-run, show the
   paths vanish — measured against scanner-severity and random baselines.
4. (If it earns its place) a **learned exploitability scorer** that beats the
   baselines on held-out variants.

Base paper remains the physics-informed GNN predictor [ref]; the framing stays
*prior work predicts; ASCEND proves, then predicts only as a labelled, secondary
layer*.

---

## 5. Metrics to capture from now (so the paper writes itself)

Run across generated variants, not the single lab:
- **Reasoning fidelity:** path precision (reasoned paths confirmed by execution)
  and recall (executable paths the engine found).
- **Chokepoint quality:** paths removed per fix (cost-weighted); greedy vs exact
  min-cut gap; **vs Trivy/CVSS-severity order; vs random order.**
- **Robustness:** decoys (look-vulnerable-but-aren't) → false-positive rate.
- **Scale:** enumeration latency p50/p95/p99 vs host count and vector density
  (target p95 < 5 s).
- **Generalisation:** calibrate on some variants, evaluate on held-out variants,
  **split by variant** to prevent leakage.
- **Verifier reliability:** flake rate (goal 0).

Every table/figure script-generated from versioned config with recorded seeds, so
"run it again" gives the same numbers.

---

## 6. Literature survey — structure and policy

**Policy:** 2024+ acceptable, prefer 2025+. Every entry recorded with full
citation, what it contributes to ASCEND, and — in the reflective voice — *what it
does not do that ASCEND needs to*.

**Lanes** (keep the four we have, add a fifth the reframe needs):
1. **Attack graphs & topology-aware prioritisation** — graph construction, IaC-derived graphs, centrality-based patching.
2. **Learned prediction** — GCN/GNN attack prediction (the base-paper lane).
3. **Execution / pentest verification** — RL pentest, execution-driven testing (the "prove it by running it" lane).
4. **Detection** — container-escape and lateral-movement detection (shows our planted techniques are realistic; the contrast is predict-and-prove vs detect-after).
5. **NEW — scanner / SCA integration & reachability / exploit-likelihood** — Trivy and SCA tooling, reachability-based prioritisation, EPSS-style exploit-probability work. This lane justifies the assessment-mode input adapters and the scanner baseline, and is currently missing from the draft.

**Reference hygiene:** replace or re-verify the 2024 entries only if a stronger
2025+ equivalent exists; otherwise 2024 stays. Fix the citation/numbering gap
from §3. Confirm every "code is public" claim or drop it (see
`REPORT_REMAINING_FIXES.md` item on Ben Fredj & Cheikhrouhou).

---

## 7. Immediate next actions

1. Run the literature survey for lane 5 (and refresh 1–4) under the 2024+ policy;
   record each entry in the reflective contribute/does-not-do format.
2. Apply `REPORT_REMAINING_FIXES.md` to the Phase I paper and resolve the
   taxonomy + reference gaps.
3. Begin the weakness catalogue + generator (doc 10 §4) — the keystone for the
   demo and for every metric in §5.

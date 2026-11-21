# 12 — Literature & ML Research Notes (working)

> **Status:** Working research notes for the Phase II paper and the ML scorer.
> Pairs with `11_Research_Narrative_and_Paper_Plan.md`. Dated 2026-11-14.
> **Citation policy:** 2024+ acceptable, prefer 2025+. Every entry here is a
> *candidate* — verify venue/DOI against the primary source before it enters the
> paper. Numbers quoted from vendor blogs are marked unverified and must not be
> cited. Entries marked **[verified 2026-11-14]** had their title/authors/venue
> checked against the primary source.

Each entry follows the project's reflective format: **contributes** (what we
take) / **does not do** (the gap ASCEND fills).

---

## Lane 1 — Attack graphs & topology-aware prioritisation
Already cited in the Phase I paper: Tiță et al. (IaC→attack graphs, *Future
Internet* 2026), Podder et al. (SPEAR, SACMAT 2025), Kuikka et al. (network-
science of cyber graphs, 2025), Plaka et al. (topology-aware EV patching, ICISSP
2025). Keep.
- **Contributes:** graph construction, centrality/position-aware ranking.
- **Does not do:** none execute to confirm a path or a fix's effect.

## Lane 2 — Learned prediction (the base-paper lane)
- **François, Arduin, Merad — Physics-Informed GNN for Attack Path Prediction**,
  *J. Cybersecur. Privacy* (ISSN 2624-800X) 5(2):15, Apr 2025
  (doi:10.3390/jcp5020015). **[verified 2026-11-14]** **This is the base paper.**
  Public replication repo `mbdlrocks/PhD_Replication_Package` **confirmed real**
  (GPL-3.0, PhD-thesis replication package) with a `Physics-Informed-GNN (PIGNN)`
  folder. Framework / dataset format not yet inspected — browse the folder before
  committing to it as a runnable comparator (follow-up 1).
  - **Contributes:** a GNN whose loss penalises predicted paths that violate
    graph-theoretic domain constraints. **Runnable comparator for Phase II.**
  - **Does not do:** predicts; never executes to verify. ASCEND's delta exactly.
- **Text-Enhanced Graph Attention for attack path prediction**, *Electronics*
  (MDPI) 15(3):552, 2025. Reframes prediction as link prediction. *(candidate)*
- **Ren et al. — GPCNKB (improved GCN)**, *Neural Process. Lett.* 2025. Already
  cited.

## Lane 3 — Execution / pentest verification (the "prove it" lane)
2025 RL-pentest work, mostly MulVAL attack graph + deep-RL agents:
- RL + attack-graph book chapter (Apr 2025); DDQN attack-path planning on MulVAL;
  Deep-Q sim (ANUJR 39(1) 2025); Rainbow-DQN MDP path discovery (Springer);
  QR-DQN DoS testing (IJACSA 16(3) 2025). *(all candidate — verify full cites)*
  - **Contributes:** learning an attack policy in an environment; "break it to
    know it" appears independently (also Re-Pen SoC pentest, already cited).
  - **Does not do:** RL learns a *policy* to verify, and runs in simulation/MulVAL
    rather than a deterministic, canary-checked real lab a reviewer can trust.
    ASCEND uses deterministic execution + per-host canary, no trained policy.

## Lane 4 — Detection (shows our planted techniques are realistic)
- **Zhou, Yao, Chen, Yu, Xuan, Yang — LMDetect: Lateral Movement Detection via
  Time-aware Subgraph Classification on Authentication Logs**, arXiv 2411.10279,
  Nov 2024. **[verified 2026-11-14]** Heterogeneous auth multigraph, time-aware
  subgraph generator, multi-scale attention; two real auth-log datasets (unnamed
  in the abstract). *(replaces an older lateral-movement detection cite)*
- Container-escape detection (dependency graph; CNI) — already cited.
  - **Contributes:** confirms our planted techniques (reused key, container
    escape) mirror real studied attacks.
  - **Does not do:** detects *after* the fact; ASCEND predicts-and-proves before.

## Lane 5 — Scanner/SCA integration, reachability & exploit-likelihood (NEW)
This lane justifies assessment mode's inputs and the scanner baseline. It is
missing from the current paper and must be added.
- **EPSS**, FIRST. ML forecast of the probability a CVE is exploited in the next
  30 days (score 0–1 + percentile), recalculated daily; inputs include ExploitDB/
  Metasploit, CISA KEV, scanner/threat telemetry. Cite the EPSS paper (Jacobs et
  al.) + first.org/epss. *(v4 is the current model; the exact "17 Mar 2025" date
  and the "1,600 variables" vendor figure are unverified — check first.org/epss.)*
  - **Take:** ingest EPSS as a per-vector **feature**, do not reinvent it.
- **NIST CSWP 41 — Likely Exploited Vulnerabilities (LEV)**, May 2025. Proposes a
  metric to augment EPSS. *(candidate)*
- **Shen et al. — AEAS: Actionable Exploit Assessment System**, arXiv 2509.17832,
  Sep 2025. **[verified 2026-11-14]** Static-analyses exploit code + docs to score
  how *actionable* an exploit is (does working code exist, does it function, how
  hard to set up); ranks exploits; built into PentestAgent's planner.
  - **Sharp contrast for the paper:** AEAS's own framing is that CVSS/EPSS give
    probabilities *without checking working exploit code exists*. AEAS checks the
    code exists; **ASCEND goes one step further and executes it** to a canary.
    Natural three-rung ladder to draw: severity (CVSS) → likelihood (EPSS) →
    code-exists (AEAS) → **executed (ASCEND)**.
- **Jiang, Oo, Meng, Lim, Sikdar — A Survey on Vulnerability Prioritization:
  Taxonomy, Metrics, and Research Challenges**, arXiv 2502.11070, Feb 2025.
  **[verified 2026-11-14]** 82 studies; taxonomy = Severity / Exploitability /
  Contextual factors / Predictive indicators / Aggregation. Good survey anchor for
  the lane, and its taxonomy maps onto our scorer's feature groups.
- **SCA reachability analysis** (Cycode, Sonar, Checkmarx, Arnica — vendor, 2025):
  flag a CVE only if the vulnerable code is actually callable from an entry
  point. Combined with CVSS/KEV/EPSS, not used as proof.
  - **Contributes:** reachability = "is it on a real path" is exactly ASCEND's
    network-level analogue at host/credential granularity.
  - **Does not do:** reachability is within one codebase; ASCEND does it across
    hosts, accounts and credentials to a crown jewel, and then *executes*.
- **Trivy / Grype / Snyk / Anchore** (tools). **No credible independent academic
  benchmark found** (only disagreeing vendor blogs). Cite as tools + baseline, run
  our own comparison; do not cite blog accuracy numbers.

## Lane 6 — Network hardening / minimum-cost remediation (for the chokepoint claim)
- Noel & Jajodia et al. — **minimum-cost network hardening using attack graphs**
  (foundational): the problem reduces to **set cover → NP-hard**; approximation
  algorithms give a worst-case ~2×-optimal bound; interdependent actions modelled.
  - **Contributes:** the formal basis for our greedy set-cover + exact-cut gap.
  - **Does not do:** these are old, graph-theoretic, and **never execute** to
    confirm the fix removed the path. Recent (2025) exact work is thin → ASCEND's
    apply-and-re-run proof loop is a genuine, underexplored contribution.

---

## ML part — the exploitability scorer (design)

**Role (set by the two-mode model):** in **assessment mode** we cannot execute,
so a learned scorer predicts, per vector/edge, the probability that the step
*would* succeed. In **lab mode** we have the true labels (execution outcomes), so
the lab is the training/calibration source. ML is **secondary to execution** and
must beat baselines or be dropped and reported.

**Labels:** `outcomes.jsonl` from the verifier — `verified` / `partial` /
`not_executable` / failure-reason per step. The generator (doc 10 §4) is what
produces enough variants for a real dataset; split **by variant** to avoid
leakage.

**Features (per vector/edge):**
- CVSS sub-scores (exploitability, required-privileges, attack-complexity).
- **EPSS score** for the anchor CVE (ingested, not recomputed).
- Technique ID / tactic (categorical).
- Topology position: betweenness, segment, distance-to-crown-jewel, asset_value.
- Provenance: observed vs declared; source tool (Trivy/Lynis) for imported facts.
- Decoy flag at training time (negatives from look-vulnerable-but-aren't plants).

**Models (in order, per the plan):**
1. Logistic regression — interpretable, the first baseline-beater.
2. Gradient-boosted trees — the likely workhorse on tabular features.
3. GNN (stretch) — compare directly against the **PIGNN base paper's public
   repo**; this is the headline ML comparison if we get there.

**Baselines it must beat (held-out variants):** majority class; CVSS ≥ 7;
**EPSS-only**; scanner-severity (Trivy) order; random. Report macro-F1 / precision
/ recall, and ranking quality (paths-removed-per-fix) vs each baseline. If it does
not beat them, we say so — that is the honest result.

**Why this is novel, not a reinvention:** EPSS predicts *per-CVE* exploitation in
the wild; ASCEND predicts *per-edge* success *in a specific network context* and
validates it against execution ground truth. We stand on EPSS/reachability as
features and add the thing they lack: a network-path, execution-verified label.

---

## Follow-ups (before anything is cited)
1. Pull and read the **PIGNN repo**; confirm its dataset format and whether its
   graphs can be mapped onto ASCEND's environment graph for a fair comparison.
2. Verify venue/DOI for every *(candidate)* above; drop any that don't hold up.
3. Read the Feb-2025 prioritisation survey (arXiv 2502.11070) to position lane 5
   and harvest its reference list for stronger primaries.
4. Decide the exact EPSS ingestion path (API vs daily CSV) for assessment mode.

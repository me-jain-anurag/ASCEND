# ASCEND — Plan of Record (single source of truth)

> **Status:** Authoritative. This document supersedes the earlier **Sentinel**
> plan, now archived in `docs/legacy/`. The full ASCEND document set lives in
> `docs/00`–`docs/09`; this file is the consolidated, code-reconciled overview of it.
> It is **ASCEND** — the project described in the attached ASCEND PDF — reconciled
> against what the repository code actually does today. Where the PDF and the code
> differ, the code wins and the gap is called out in §10.
>
> **ASCEND = A**ttack-path **S**coring and **C**hokepoint **E**valuation for **N**etwork **D**efence.
> DSCE / ISE final-year project · Aug 2026 – June 2027 · build by ~Jan 2027, then a paper.
> See `docs/PLAN_RECONCILIATION_ASCEND_vs_Sentinel.md` for the full ASCEND-vs-Sentinel diff.

## 1. What ASCEND is

ASCEND maps every privilege-escalation route from a low-privilege foothold to a
critical asset across a Linux network, **proves each route by executing it** in an
isolated lab, and computes the **smallest, cheapest set of fixes** that eliminates
the most routes — then proves the routes are gone.

> **Core principle:** ground truth comes from *execution*, not from scores or
> labels we invented. A path is "verified" only when every step was run and every
> step worked (checked by a per-host canary token, not by a script exit code).

Framing against prior work: **prior work predicts; ASCEND proves.**

## 2. Scope — in-scope ATT&CK techniques

Deliberately narrow so results are measurable. The authoritative list is
`scope.yaml` (read by `collectors/derive.py` and `chokepoint/engine.py`):

| ATT&CK ID | Technique | Evidence (probe) | Anchor |
|---|---|---|---|
| T1548.001 | Setuid/Setgid abuse | `suid_binaries` | shell-escapable SUID outside baseline |
| T1548.003 | Sudo misconfiguration | `sudo_rules` | NOPASSWD + GTFOBins shell escape |
| T1068 | Exploitation for priv-esc | `kernel_version` / pkexec pkg | **DirtyPipe** CVE-2022-0847, **PwnKit** CVE-2021-4034 |
| T1611 | Escape to host | `docker_socket` | exposed `/var/run/docker.sock` |
| T1021.004 | SSH lateral movement | `reachability` | SSH to a reachable host |
| T1550 | Use Alternate Auth Material | `credential_reuse` | reused SSH key (fingerprint match) |
| T1552.001 | Unsecured credentials in files | `readable_credential_file` | group/world-readable key or secret |

Out of scope: Windows/AD; web-app attacks (beyond one initial foothold); malware,
phishing, DoS; any production/third-party system; enterprise-scale deployment.

> **Conflict to resolve (see §10.1):** the PDF maps reused-key lateral movement to
> **T1078.003** and explicitly *excludes* T1550. The code uses **T1550** and omits
> T1078.003. Pick one taxonomy and make the PDF, `scope.yaml` and the paper agree.

## 3. Architecture — maps 1:1 to the repo

```
Isolated lab ──► collectors/ ──► environment_graph/facts.json
                                        │
          knowledge_graph/pack.json ────┤   (CVE→CWE→CAPEC→ATT&CK, in-scope only)
                                        ▼
                                  enumerator/pathfinder.py ──► attack paths
                                        │
                                  verifier/ ──► runs every step in the lab ──► outcomes.jsonl
                                        │                                         (labels)
                      ┌─────────────────┴─────────────────┐
             (Phase 2) exploitability scorer     chokepoint/engine.py ──► ranked, costed fixes
                                                          │
                                                   proof loop (apply → re-run → paths vanish)
                                        │
                         service/main.py (FastAPI) ──► dashboard/ (React + Vite + Cytoscape)
```

Module map: `collectors/` (read-only fact probes + `derive.py`), `knowledge_graph/`
(`pack.json`), `environment_graph/` (`facts.json`), `enumerator/` (stdlib-only
state-space search), `verifier/` (adapters: `config_abuse`, `lateral_ssh`,
`anchor_cve`; canary-based pass/fail), `chokepoint/` (`engine.py`), `eval/`
(`analysis.json`), `service/` (FastAPI), `dashboard/` (React), `lab/`, `tests/`.

## 4. The lab

**Currently implemented (code, `scope.yaml` inventory + `lab/docker-compose.yml`):**
a 3-host container lab — **web01** (entry, `www-data`, low priv, readable SSH key)
→ **app01** (NOPASSWD sudo + SUID escape, asset 30) → **db01** (crown jewel, root,
asset 100). Entry = `web01:www-data`; target = `root@db01`. The enumerator currently
finds **6 paths**; **3 verify** (precision ≈ 0.5 at last run).

**Reference lab (PDF target, roadmap):** 10 hosts incl. two QEMU/KVM VMs — db01
(vulnerable kernel) + db02 (patched control) — plus ci01 (Docker-socket escape),
nfs01 (`no_root_squash`), admin01, app02 (PwnKit), collector01, attacker01.

> **Conflict to resolve (see §10.2):** the current lab is 3 containers; the PDF
> describes 10 hosts incl. VMs. Decide how far the lab scales before review.

**DirtyPipe reality (see §10.3):** T1068 is a *kernel* bug. db01's kernel version in
the environment graph is `declared` (5.16.0), so it cannot be executed for real in a
shared-kernel container. The verifier correctly reports `not_executable` until (a) the
three-VM fallback gives db01 a real vulnerable kernel and (b) a real exploit binary is
placed at `exploit_ref`. ASCEND never ships exploit code in the repo.

## 5. Phase 1 — foundation (the core contribution)

1. **Isolated lab** — rebuilds from the repo; resets in seconds; internet-isolated
   except a one-time read-only pull of public vuln data.
2. **Fact collection** — read-only probes write one versioned `facts.json` per host,
   each fact keeping its raw evidence string. Read-only is what enables assessment mode.
3. **Knowledge graph** — public CVE→CWE→CAPEC→ATT&CK restricted to in-scope
   techniques; every edge records its source; a test asserts each in-scope CVE ends in
   a technique; missing hops curated by hand and flagged.
4. **Environment graph** — accounts-on-hosts as nodes; reach / log-in / escalate as
   edges; each weakness linked to its technique with preconditions checked against facts.
5. **Path enumeration** — state-space search (attacker holds a growing set of
   `(host, privilege)` + credentials) from foothold to crown jewel; depth cap, path cap,
   equivalent-path collapse; dropped-path count reported.
6. **Execution verification** — reset → place attacker → run each step with the
   technique adapter → confirm via the per-host **canary** → record pass/fail with a
   reason (not_applicable / exploit_failed / timeout / environment_error). Outputs:
   path-finder **precision** and per-vector **labels** (`outcomes.jsonl`).
7. **Labelled dataset** — a seeded **lab generator** produces many variants (target
   **≥30**) with decoys (things that look vulnerable but are not) for negatives.
   Split **by lab variant** to prevent leakage. *(Generator = roadmap; see §10.2.)*

## 6. Phase 2 — ML scoring & remediation

- **Exploitability scorer** — predicts whether a vector would work without running it
  (feeds assessment mode). Logistic regression first, then gradient-boosted trees; GNN
  is an optional stretch. Must beat baselines (majority class; "CVSS ≥ 7"; scanner-flag)
  or it is dropped and that is reported honestly. ML is **secondary** to execution.
- **Chokepoint engine** (`chokepoint/engine.py`) — smallest, cheapest fix set that
  breaks the most paths. Greedy weighted set-cover (Chvátal bound) **and** an exact
  min-cost cut (OR-Tools / PuLP) to measure the greedy gap. Costs from `scope.yaml`
  remediation templates (1 = minutes … 5 = change control, e.g. kernel patch).
- **Proof loop** — the single most important result: *before* (enumerate + verify),
  *compute* top fix, *apply* it in the real lab, *re-run*, *confirm* only the paths
  through the fixed weakness disappear, repeat until the crown jewel is unreachable.
  Negative control + CVSS-order / random-order comparison runs.
- **Assessment mode** (stretch) — read-only collectors on a real host → ranked fixes
  with no execution.

## 7. Evaluation

Path finder: precision + recall (recall vs planted paths + a manual red-team pass;
unplanted "surprise" paths counted separately); vs OpenVAS/Lynis, optionally GoLinHound.
Enumeration speed: p50/p95/p99, target p95 < 5 s (verification time reported separately).
Verifier: flake rate (goal 0). Scorer: accuracy/precision/recall/macro-F1 on held-out
variants vs the three baselines. Remediation: fixes-to-cut-crown-jewel, paths-removed-
per-fix, greedy-vs-optimal, vs CVSS and random ordering. All tables/figures are
script-generated from versioned config with recorded seeds.

## 8. Deliverables & timeline

Phase 1 (by mid-Jan 2027 gate): isolated lab, lab generator, fact pipeline, knowledge
graph, environment graph + enumerator, execution verifier + labelled dataset, basic
dashboard. Phase 2 (to June 2027): exploitability scorer, chokepoint engine +
before/after proof, assessment mode (stretch), scripted demo, research paper
(base paper: PIGNN; vs graph-only tools BloodHound/GoLinHound and MulVAL).
Milestones M0–M8; Phase-2 scorer begins on the first verified data in early Jan.

## 9. Safety

All attack simulation stays inside the isolated lab, on an internal-only network with
no route out. Exploit scripts run only from the attacker host and live only in the
lab directory; no exploit code is distributed. The only outside access is a one-time,
read-only pull of public vulnerability data.

## 10. Plan-vs-code deltas & open decisions (for the team to close)

1. **Credential-reuse technique — T1550 (code) vs T1078.003 (PDF).** The PDF excludes
   T1550 and uses T1078.003; the code uses T1550. **Decide one** and align `scope.yaml`,
   the PDF and the paper. *(Recommendation: keep the code's T1550 unless the paper
   argument needs T1078.003; changing code is more costly than editing the PDF.)*
2. **Lab size — 3 hosts (code) vs 10 hosts + VMs (PDF).** Decide the target for review:
   stay at the 3-host container lab, or build out ci01/nfs01/admin01/app02/db02 and the
   two VMs. This also gates the lab generator and the ≥30-variant dataset claim.
3. **DirtyPipe execution.** Real T1068 execution needs the three-VM fallback (a genuinely
   vulnerable kernel on db01) plus an exploit binary at `exploit_ref`. Until then T1068 is
   `not_executable` and must not be reported as a verified pass. PwnKit (pkexec package
   version) is the more lab-executable T1068 anchor in the current container setup.
4. **Sentinel archive — done.** The old `Sentinel_Implementation_Plan_v2.pdf` and
   `Sentinel_Synopsis.docx` are archived in `docs/legacy/`. `docs/00`–`docs/09` are the
   current ASCEND document set and stay in place — they are *not* Sentinel docs.

## 11. What was kept from Sentinel / what was dropped

**Kept:** scope-locking via a single config, the three-graph model (knowledge /
environment / attack-state), anti-data-leakage discipline (split by variant; keep
benign look-alikes, failed attempts, background), baselines-before-fancy-models.
**Dropped / demoted:** runtime next-step *prediction* and the live risk-score pipeline
(Sentinel's headline) — available only as an optional assessment-mode extension, since
ASCEND's headline is execution-verified paths + proved remediation, not a model's
accuracy on self-generated data.

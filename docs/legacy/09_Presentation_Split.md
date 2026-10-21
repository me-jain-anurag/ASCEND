# 09 — Presentation Split (4 speakers)

Each person presents the lane they own (doc 03 §6). Arc: **problem → design → proof → show it**.
Target: 20 minutes of talking, 5 minutes of questions. Five minutes each, hard stop — if a
section overruns, cut detail, never cut the handover line.

| # | Speaker | Lane | Presents | Source |
|---|---|---|---|---|
| 1 | **A** | Lab & Ground Truth | Problem, one-liner, locked scope, the lab | 01 §1–4, 02 §6 |
| 2 | **B** | Graphs & Enumeration | Architecture, three graphs, one worked attack path | 02 §1, §2, §5 |
| 3 | **D** | ML, Chokepoint & Evaluation | Ground truth by execution, baselines, chokepoints, the research gap | 06 §1–3, 08 §6 |
| 4 | **C** | App & Integration | Live thin slice on the dashboard, then plan and timeline | 05 §1, 03 §3–4 |

---

## 1. Person A — "what problem, and how big is it" (5 min)

1. The one-liner, verbatim from doc 01 §2. Lead with it; do not warm up to it.
2. The problem: scanners list vulnerabilities, they do not tell you which chain an attacker
   actually walks (01 §3).
3. Scope, stated in ATT&CK terms, and stated as **locked** (01 §4). Naming the boundary early
   stops the panel widening it for you.
4. The lab: the container hosts, the planted vectors, the fact collectors (02 §6).

**Hand over:** "So that is the environment and the facts we collect from it. B will show what we
build out of those facts."

---

## 2. Person B — "what we build out of it" (5 min)

1. The architecture diagram, one page (02 §1). Talk over it; do not read it.
2. The three graphs and how data flows between them (02 §2) — knowledge graph, environment
   graph, attack-state model.
3. **One** enumerated path, walked edge by edge (02 §5). This is the slide that convinces the
   panel the design is real. Spend half your time here.

**Hand over:** "That is a path we *propose*. D will explain why you should believe it."

---

## 3. Person D — "why you should believe it" (5 min)

1. The core claim: ground truth comes from **executing** the technique in the lab, not from
   invented labels (06 §1). This is the project's credibility; state it as the central idea.
2. The four things we measure and what each is compared against (06 §2).
3. Host-wise splits, so the scorer cannot memorise the lab (06 §3).
4. Where we sit against the base paper — PIGNN predicts, it does not verify or remediate
   (08 §6). One sentence on the chokepoint contribution.
5. Say the honest line out loud: **if the scorer does not beat the CVSS baseline, we report
   that.** Panels trust teams that pre-commit to reporting negative results.

**Hand over:** "C will now show the slice of this that already runs."

---

## 4. Person C — "here it is running, and here is the plan" (5 min)

1. The thin slice, live (05 §1): the network graph, the enumerated path, verified vs unverified.
   Keep it small and real — one verified path on screen beats a broken large demo.
2. Semester 1 milestones S1-M0 → M5, one line each (03 §3).
3. Semester 2 in a sentence: chokepoints, before/after remediation proof, the paper (03 §4).
4. The January 2027 build-complete target, with the remaining months for the paper.

**Close:** the Semester-1 deliverable sentence from doc 03 §3, said as the last thing before
questions.

---

## 5. Question routing (announce this once, at the handover to Q&A)

| Question | Answers | Source |
|---|---|---|
| "Isn't this just BloodHound / a scanner?" | **A** | 01 §6 |
| "How do you know the path actually works?" | **D** | 06 §1 |
| "What if the ML does not beat the baseline?" | **D** | 03 §3 (S1-M5) |
| "Is this enough work for 80 credits?" | **A** | 03 §5 |
| Dashboard, stack or integration | **C** | 05 §3–4 |

Rule: the named owner answers, nobody else adds to it. A second voice on the same answer reads
as uncertainty.

---

## 6. If a speaker is missing

Fold **D** into **B** (same doc 03 lane before the split) and cut the base-paper comparison to a
single sentence. Fold **C** into **A** and show the thin slice from a recording or static
screenshots. Never drop the execution-verification section — that is the whole argument.

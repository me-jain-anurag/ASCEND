# 03 — Team Plan, Workstreams and Timeline

This is the document the whole team follows. It assigns clear ownership, runs the workstreams **in parallel**,
defines "done" for each piece, explains how the **fourth member slots back in after Review 1**, and states how the
plan **degrades gracefully to three (or two) people** for Review 1 itself.

- **Team capacity — read carefully:** the full project is a **4-person** effort. The reduction to **3 active
  contributors (and a 2-person fallback) applies only to tomorrow's Review 1**; the fourth member rejoins
  immediately after Review 1. The workstream plan below is sized for the **4-person** project, and §6 explains both
  how the fourth member slots in and how the team shrinks for Review 1 if needed. Heavy use of AI coding assistants
  is expected and planned for — it changes *how fast* each task is done, not *what* the tasks are.
- **Credits:** this is a **20-credit-per-person** project — with **4 members, 80 credits in total** — split across
  the two semesters roughly **4 credits in one semester and 16 in the other**. That is a very large envelope, which
  is why the scope in §5 is broad and decomposed.
- **Calendar reality:** the project formally runs **Aug 2026 – Jun 2027**. Today is mid-September 2026, so we are
  early in **Semester 1**. **Target: complete the build by January 2027**, leaving the remaining months to write and
  submit a **research paper** (see doc 08 for the base paper and the paper narrative). The next review is
  **tomorrow** and is an early checkpoint, not the final defence.

---

## 1. Roles (three owners)

| Person | Role title | Owns | Skills leaned on |
|---|---|---|---|
| **A** | Lab & Ground-Truth Engineer | Docker lab, planted weaknesses, fact collectors, **execution verifier** | Linux, containers, shell, a little offensive tooling |
| **B** | Graphs & ML Engineer | Knowledge graph, environment-graph builder, path enumerator, exploitability scorer + baselines, chokepoint engine, evaluation | Python, graph algorithms, basic machine learning |
| **C** | App & Integration Engineer | Data pipeline (collector → queue → API), **dashboard**, demo orchestration, keeping docs current | Python (FastAPI), a modern web framework, systems glue |

**Person A is the "ground-truth owner."** Their execution verifier is what makes every number defensible, so this
role is not optional plumbing — it is the spine of the project's credibility. **With the full four members, the
heaviest workstream (B, Graphs & ML) is split into B1 and B2** so that the fourth member has a clear, substantial
lane — see §6.

> **The golden rule of the split:** *A produces truth, B turns truth into analysis, C makes it runnable and
> visible.* When in doubt about who owns a task, ask which of those three it is.

---

## 2. What to present at TOMORROW's review

Tomorrow you are defending a **plan and direction**, plus one concrete slice. You are *not* expected to have the full
system. Present, in this order:

1. **Name, one-liner, problem, scope** (doc 01) — 3 minutes. Lead with the one-liner. State scope in ATT&CK terms.
   Pre-empt "isn't this BloodHound?" with the §6 answer from doc 01.
2. **The diagrams** (doc 02) — architecture, the three-graph data flow, the example attack path, the schema. This is
   the bulk of what convinces a panel you have thought it through.
3. **Why it is defensible** (doc 06) — the one idea that ground truth comes from execution, not invented labels.
4. **The plan and timeline** (this doc) — show the workstreams and the semester milestones.
5. **A concrete "thin slice"** if you can build one overnight (doc 05, §1). If you cannot, the diagrams plus a
   walk-through of the example path in doc 02 §5 is an acceptable concrete artefact for an early review — narrate it
   as "here is exactly what the system will output, and here is how we prove each edge."

### Overnight division of labour (only if attempting the thin slice — see doc 05 §1)
- **A:** stand up a 3-container Compose lab (web → app → db) with two planted, real vectors, OR hand-write a
  `facts.json` describing such a network if Docker time runs short.
- **B:** write the path enumerator over that graph and print the enumerated path(s); wire a placeholder
  exploitability score.
- **C:** a single React page that draws the network graph and the one path, reading B's JSON output.

Keep it *small and real*. One verified path on screen beats a broken large demo.

---

## 3. Semester 1 (now → December 2026): "the path-finder that proves itself"

**Goal of Semester 1:** a working pipeline that builds the graphs, enumerates escalation paths, **verifies them by
execution**, and reports path-finder precision against baselines. Machine learning starts here (baselines + first
scorer) but the *headline* Semester-1 result is the verified path-finder.

### Milestone S1-M0 — Foundations (≈ 1 week)
- Repository, `scope.yaml` (the techniques from doc 01 §4), `demo.md` (the target demo from doc 05), coding
  conventions, task board.
- **Definition of done:** every member can run the empty pipeline end-to-end (even if each stage is a stub).

### Milestone S1-M1 — Lab + collectors (Person A) (≈ 2–3 weeks)
- Docker Compose lab with the hosts from doc 02 §6, each with deliberately planted vectors from the scope.
- Fact collectors producing normalised `facts.json` per host (users, sudo rules, SUID binaries, kernel version,
  docker-group membership, SSH keys, readable credential files, listening ports, NFS mounts, reachability).
- **Definition of done:** `docker compose up` builds the lab; running the collectors produces a facts file for every
  host; the lab resets cleanly.

### Milestone S1-M2 — Knowledge graph (Person B, parallel with S1-M1) (≈ 2 weeks)
- Pull and parse NVD/CVE, CWE, CAPEC, ATT&CK **restricted to our techniques**; attach description text.
- **Definition of done:** given a CVE id (e.g., CVE-2021-4034) the graph returns its CWE, CAPEC and ATT&CK technique
  with text. (Because the knowledge graph depends only on public data, it can be built before the lab is finished —
  exploit this parallelism.)

### Milestone S1-M3 — Environment graph + path enumerator (Person B) (≈ 3 weeks)
- Build the environment graph from A's facts; link each vector to the knowledge graph.
- Implement path enumeration (entry foothold → crown-jewel asset) over the attack-state model in doc 02 §5.
- **Definition of done:** given a facts set, the enumerator lists concrete paths with the techniques on each edge.

### Milestone S1-M4 — Execution verifier + ground-truth dataset (Person A, with B) (≈ 3 weeks)
- For each vector/path, actually run the technique in the lab (Atomic Red Team where possible, custom scripts for
  the two anchor CVEs) and record success/failure.
- Assemble the labelled feature dataset; **split by host** (doc 06).
- **Definition of done:** a dataset file where every vector has features + a verified label; and path-finder
  **precision** (verified ÷ proposed) is computed.

### Milestone S1-M5 — Baselines + first scorer + Semester-1 evaluation (Person B) (≈ 2 weeks)
- Baselines: majority-class and CVSS-threshold. Then the first exploitability scorer (start with logistic regression
  / gradient-boosted trees; a graph neural network is a Semester-2 stretch).
- **Definition of done:** a metrics table (accuracy, precision, recall, F1) on held-out hosts, scorer vs both
  baselines; path-finder precision/recall reported. **If the scorer does not beat the baselines, we report that** —
  discovering it in December is a success of the process, not a failure.

### Person C across Semester 1
- S1-M1→M3: build the **collector → queue → FastAPI** pipeline so facts flow automatically; scaffold the **React
  dashboard** (network graph + path list) reading B's output.
- S1-M4→M5: wire the dashboard to show verified vs unverified paths and the metrics.
- **Definition of done for the semester:** an analyst can open the dashboard and see the lab's network, the
  enumerated paths, and which ones are verified.

**Semester-1 review deliverable:** *"We build the graph, enumerate escalation paths, and prove which ones work by
executing them. Path-finder precision is X. Our exploitability scorer beats the CVSS baseline by Y."*

---

## 4. Semester 2 (January → June 2027): "from finding paths to removing them"

**Goal of Semester 2:** the **chokepoint remediation** contribution, a stronger scorer, a polished dashboard, full
evaluation with **before/after remediation proof**, and the report/paper.

### Milestone S2-M1 — Chokepoint / remediation engine (Person B) (≈ 3 weeks)
- Compute the minimum set of fixes that eliminates the most verified paths (minimum-cut / weighted set-cover), and
  the "fixes-vs-paths-eliminated" efficacy curve.
- **Definition of done:** given the verified paths, the engine outputs a ranked fix list and the efficacy curve.

### Milestone S2-M2 — Remediation proof loop (Person A + B) (≈ 2 weeks)
- Apply a recommended fix in the lab, re-run enumeration + verification, and show the targeted paths are gone.
- **Definition of done:** a before/after report proving paths disappear after the recommended fix — empirically.

### Milestone S2-M3 — Stronger scorer + text features (Person B) (≈ 3–4 weeks)
- Add vulnerability-description **text features** (the Gao et al. idea) and, as a stretch, a **graph neural network**
  for path-likelihood. Always still reported against the Semester-1 baselines.
- **Definition of done:** updated evaluation table; a clear statement of whether the added complexity earns its keep.

### Milestone S2-M4 — Dashboard, risk scoring, demo polish (Person C) (≈ 4 weeks)
- Risk score = a simple, explainable combination of exploitability likelihood and asset criticality (write the
  formula down; keep it explainable in one sentence).
- Polish the network/path visualisation, remediation panel, and before/after view; script the final demo.
- **Definition of done:** the full demo from doc 05 §2 runs end to end.

### Milestone S2-M5 — Full evaluation, report, paper (all) (≈ 3–4 weeks)
- Complete metrics (doc 06), threats-to-validity section, and the write-up.
- **Definition of done:** final report + demo ready for the final defence.

---

## 5. How this maps to 80 credits (20 per person × 4) — the "is the scope big enough?" answer

**20 credits per person, 80 in total across the four members** (weighted roughly 4 credits in one semester and 16 in
the other) is a very large envelope, and ASCEND fills it with **distinct, substantial workstreams** rather than one
idea stretched thin:

- **Systems / infrastructure:** a reproducible multi-host container lab with realistic, planted weaknesses, plus a
  fact-collection pipeline (a real distributed-collection problem). *(Workstream A + C)*
- **Knowledge engineering:** ingesting and linking four public security standards (CVE/CWE/CAPEC/ATT&CK) into a
  queryable graph. *(Workstream B)*
- **Algorithms:** attack-path enumeration over an identity-and-reachability graph, and remediation as a
  minimum-cut / set-cover optimisation — both are genuine graph-theory problems with a literature. *(Workstream B)*
- **Machine learning:** an exploitability scorer trained on execution-verified labels, evaluated with proper
  host-wise splits and baselines, with an optional graph-neural-network extension. *(Workstream B)*
- **Security research / evaluation:** the execution-verification methodology itself, and the before/after
  remediation study, are the research contribution. *(Workstream A + B)*
- **Software engineering:** a service (FastAPI) and a modern web dashboard integrating all of the above. *(C)*

Each member carries a full, credit-worthy workstream, and the shared evaluation/paper work is genuine research
effort. Because the work is decomposed, it also **shrinks cleanly** for Review 1 if fewer people are available
(next section).

---

## 6. Team size: the fourth member, and the Review-1 fallback

### Normal case (after Review 1): four members, four lanes
The fourth member rejoins immediately after Review 1 and reinforces the **heaviest** workstream, **B (Graphs & ML)**,
which alone carries the knowledge graph, environment graph, path enumerator, exploitability scorer, chokepoint
engine and evaluation. Split B in two for a clean four-way division of labour:

| Lane | Owner | Scope |
|---|---|---|
| **A — Lab & Ground Truth** | Person A | Docker lab, planted vectors, collectors, **execution verifier** |
| **B1 — Graphs & Enumeration** | Person B | Knowledge graph, environment graph, path enumerator |
| **B2 — ML, Chokepoint & Evaluation** | Person D (the returning member) | Exploitability scorer + baselines, chokepoint/remediation engine, evaluation harness, **research-paper results** |
| **C — App & Integration** | Person C | Collector → queue → FastAPI pipeline, React dashboard, demo, docs |

This split also matches the paper: **B2 owns the numbers that go in the paper**, which pairs naturally with the
January "finish the build, then write the paper" target.

### Review-1-only fallback (3, or even 2, people)
For **tomorrow's Review 1 only**, the fourth member is unavailable and the team may be as small as two. Keep
Workstreams A and B; fold C (and, at two people, B2) into them and **cut polish, not substance:**

- **Person A** takes Lab + Ground-Truth **and** the data pipeline (collector → API). Use the simplest possible
  transport (write facts to files / a small queue); skip the fancy streaming.
- **Person B** takes all Graphs + ML + chokepoint + evaluation **and** a *minimal* dashboard (a single web page or
  even a set of generated static views) instead of a full app.
- **Cuts (in priority order):** graph-neural-network stretch → live-streaming pipeline → dashboard polish →
  number of planted scenario variants. **Never cut:** the execution verifier or the host-wise evaluation — those are
  the credibility of the whole project.

Either way the project still stands as: *build the graph, enumerate paths, verify by execution, recommend and prove
remediation.* That is a complete, defensible final-year project on its own.

---

## 7. Working agreement (keeps three parallel streams from colliding)

- **One shared repository**, one `scope.yaml` as the single source of truth for what is in scope. A change to scope
  is a change to that file, reviewed by the team.
- **Interfaces first.** A and B agree the `facts.json` schema in week 1; B and C agree the analysis-output JSON
  schema in week 1. Then all three can build against stubs without waiting on each other.
- **Integration cadence:** merge to a working `main` at least weekly; run the whole pipeline end-to-end every week
  even while stages are stubs, so integration problems surface early.
- **Decisions are asynchronous** (see doc 07). Do not block on getting all members on a call; put the decision in a
  shared doc with a deadline and a named owner, and reserve live calls for genuine disagreement.
- **All Git/GitHub write actions are drafted, reviewed, then pasted by a human** — see the `git-drafter` skill in
  `.claude/skills/git-drafter/`.

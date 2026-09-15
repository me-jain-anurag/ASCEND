# 07 — Open Decisions and Risk Register

## 1. Open decisions (each has a default and an owner)

These are genuinely undecided. Each should be **closed by its named owner with a comment deadline**, not left to the
next time all members happen to be on a call. The scope decision is already settled (doc 01) and only needs
confirmation.

| Decision | Options | Default (use unless someone objects) | Blocks | Owner |
|---|---|---|---|---|
| Containers or virtual machines | Docker + Falco / three VMs + auditd | **Docker + Falco** | Lab (S1-M1) | Person A |
| Attack execution tool | Atomic Red Team / Caldera | **Atomic Red Team** (add Caldera only if multi-step orchestration is needed) | Verifier (S1-M4) | Person A |
| Graph storage | NetworkX / Neo4j | **NetworkX** (move to Neo4j only on a *measured* performance problem) | Graphs (S1-M2/M3) | Person B |
| First model family | Logistic regression / gradient-boosted trees | **Logistic regression first**, then gradient-boosted trees | Scorer (S1-M5) | Person B |
| Graph neural network | Include / defer | **Defer to Semester 2 stretch** | Scorer (S2-M3) | Person B |
| Risk-score formula | Weighted product / learned weighting | **Weighted product** of likelihood × asset criticality (explainable in one sentence) | Risk (S2-M4) | Person C |
| Dashboard component library | shadcn/ui / Mantine | **shadcn/ui** | Dashboard | Person C |
| Runs per scenario class | driven by the size of the rarest test class | **Plan the count backwards** from "the rarest class still has a usable test set" | Dataset (S1-M4) | Person A + B |

> Process note: put each decision in a shared document with a deadline. Reserve live calls for genuine disagreement.
> Waiting for everyone to be simultaneously free is the most expensive habit a small team can have.

---

## 2. Risk register

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | The machine-learning scorer does not beat the CVSS baseline | Medium | Medium | This is an acceptable, reportable outcome; the verified path-finder and remediation engine still deliver the project. Discover it early (S1-M5), not in May. |
| R2 | The two kernel exploits are hard to reproduce reliably in containers | Medium | High | Start with the easiest vectors (sudo, SUID, credential reuse) so ground truth exists even before the kernel exploits work; fall back to VMs for the kernel CVEs if containers resist. |
| R3 | Container telemetry (Falco) is insufficient | Low–Med | Medium | Documented fallback to three VMs with auditd; decide by end of S1-M1. |
| R4 | Path enumeration explodes combinatorially on the full lab | Medium | Medium | Depth bound, path cap, equivalence-collapsing; remediation needs chokepoints, not every path. |
| R5 | Data leakage silently inflates results | Medium | High | Enforce host-wise and scenario-wise splits from the start; code-review the split; report the split method in the paper. |
| R6 | Fewer than 3 people **for Review 1** (the 3/2 reduction is Review-1-only; the team is back to 4 afterwards) | Possible | Medium | The Review-1 fallback in doc 03 §6; never cut the verifier or the host-wise evaluation. |
| R11 | Compressed schedule — the build must finish by **January 2027** to leave time to write the research paper | Medium | High | Front-load Semester 1 (doc 03 §3); keep the base paper and paper narrative ready from day one (doc 08); the paper's numbers come straight from the evaluation harness (owned by lane B2). |
| R12 | Base-paper details cited without confirmation | Low | Medium | Only cite numbers/claims a team member has personally confirmed in the source PDF and replication package (doc 08 §10). |
| R7 | Scope creep back toward "detect everything" | Medium | High | `scope.yaml` is the single source of truth; any addition is a reviewed change; the demo defines what is in scope. |
| R8 | Integration left to the end | Medium | High | Weekly end-to-end runs against stubs; interface schemas agreed in week 1. |
| R9 | Review deadlines arrive with nothing concrete | Low | High | The thin slice (doc 05 §1) is always demonstrable; diagrams + example path are an acceptable early-review artefact. |
| R10 | Over-cleaning the dataset removes realism | Low | Medium | Remove only malformed records and exact duplicates; keep noise, failures and benign look-alikes. |

---

## 3. What "done" looks like for the whole project

- A reproducible, isolated Linux lab with planted, real privilege-escalation vectors.
- Automatic collection of host facts and construction of the knowledge and environment graphs.
- Enumeration of privilege-escalation paths from a foothold to the crown jewel, **with a measured precision from
  execution verification.**
- An exploitability scorer evaluated on held-out hosts against baselines, reported honestly.
- A chokepoint remediation engine that outputs the fewest fixes for the most paths, **with a before/after proof that
  the recommended fix removes the paths.**
- A React dashboard presenting all of the above, and a scripted demo.
- A final report and paper with metrics, a related-work delta, and a threats-to-validity section.

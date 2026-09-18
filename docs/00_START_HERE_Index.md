# ASCEND — Project Document Set (Start Here)

> **ASCEND** = **A**ttack-path **S**coring and **C**hokepoint **E**valuation for **N**etwork **D**efence
> Final Year Project · Dept. of Information Science and Engineering (ISE), Dayananda Sagar College of Engineering (DSCE)
> Guide: Dr. Santosh Anand · Team: Adithya Pradeep, Adithya R, Anurag Jain, Dhyani Kinjal Shah
> Timeline: August 2026 – June 2027 (two semesters; **20 credits per person, 80 total** across 4 members) · build targeted for completion by **January 2027**, then a research paper

---

## What changed from "Sentinel"

The earlier synopsis ("Sentinel: Cyber Attack Path Prediction and Risk Assessment Framework") and its
Implementation Plan Revision 2 were **too broad and hard to prove**. Their headline result was a machine-learning
model's *accuracy on a dataset the team generated itself* — the weakest kind of number to defend, because a panel
will ask "how do you know the model didn't just memorise your own script?"

**ASCEND keeps everything good about that work** (scope-locking, the three-graph model, anti-data-leakage
discipline, baselines-before-fancy-models) but **re-centres the project on one thing that can be proven by
execution instead of asserted**: privilege-escalation attack paths through a network.

The single most important idea:

> **Ground truth comes from execution, not from labels we invented.**
> We claim a path exists → we *run it* in the isolated lab → it works or it doesn't.
> That fact is not arguable, and it is what makes every downstream number credible.

---

## The documents (read in this order)

| # | File | What it is | Primary reader |
|---|------|-----------|----------------|
| 01 | `01_Overview_Pitch_Scope.md` | The one-liner, problem, locked scope, what we contribute over existing work | Everyone; the panel |
| 02 | `02_Architecture_and_Diagrams.md` | All diagrams: architecture, data-flow, sequence, schema, example attack path, deployment | Everyone; the panel |
| 03 | `03_Team_Plan_Workstreams_Timeline.md` | Who builds what, in parallel, week by week; how it maps to 20 credits over two semesters | The three builders |
| 04 | `04_Defense_Document.md` | Every term explained in full, and every question a panel could ask with a prepared answer | The whole team, to rehearse |
| 05 | `05_Demo_and_MVP_Spec.md` | Exactly what to build for a demo — the overnight "thin slice" and the full version; tools, datasets, libraries | The three builders |
| 06 | `06_Evaluation_and_Verifiability.md` | How every result is measured, and why the numbers are real and not hallucinated | The team; the panel's toughest questions |
| 07 | `07_Open_Decisions_and_Risks.md` | Decisions still open (with an owner each) and the honest risk register | Team leads |
| 08 | `08_Base_Paper_and_Research_Narrative.md` | The base paper (PIGNN, 2025) explained in full for ML/security newcomers, and the narrative to the paper we will publish | The whole team; the paper authors |

### Runbooks (in the repository root, not in `docs/`)

| File | What it is | Primary reader |
|------|-----------|----------------|
| `README.md` | **Start here.** What the project is, why it is built this way, and how the pieces fit — with a diagram | Anyone new to the project |
| `demo.md` | Step-by-step: how to test the pipeline and how to run the demo, in plain terms, with the prepared answers to the questions you will be asked | Whoever is presenting |
| `QUICKSTART.md` | The shortest path to a working pipeline, with and without Docker | A teammate on a fresh clone |
| `lab/README.md` | The Docker lab: what is planted, what is deliberately *not* reported, and the container-kernel caveat | Whoever touches the lab |
| `collectors/README.md` | How facts are collected and how to add a probe or a detection rule | Whoever adds a technique |
| `enumerator/README.md` | How attack paths are actually found: the attacker state model, the three moves, and the two metrics | Whoever touches the analysis |
| `verifier/README.md` | How a path is *proven* by executing it: the canary test, the three outcomes, and why one step reports not-executable | Whoever is asked "how do you know?" |

---

## The one sentence to say to the panel

> **"ASCEND maps every privilege-escalation route an attacker could take from a low-privilege foothold to a
> critical asset across a Linux network, proves each route by actually executing it in an isolated lab, scores how
> exploitable each step really is, and computes the smallest set of fixes that eliminates the most routes."**

Shorter, for a title slide:

> **Find every privilege-escalation path through a network, prove it by execution, and compute the fewest fixes
> that break the most paths.**

---

## Where this lives

- **Notion (shareable):** this document set has been published to Notion under the page **"ASCEND — Attack-path
  Scoring and Chokepoint Evaluation for Network Defence"** (in *Anurag Jain's Space*). The eight documents are
  sub-pages of it, and the Mermaid diagrams in document 02 render automatically there. Share that Notion page with
  the team and the guide.
- **Repository:** the same content lives as plain Markdown in the `docs/` folder, which stays the source of truth.
  If you edit the Markdown later, re-publish to Notion to keep them in sync.

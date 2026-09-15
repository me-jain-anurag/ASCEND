# 08 — Base Paper and Research Narrative

This document is written for a team that is **new to both machine learning and security**. It:

1. Names the **base paper** our project builds on, and why it is a sensible choice.
2. Explains that paper **in full, plain-English detail** — every idea and term.
3. Lays out the **narrative** from the base paper to **the paper we will write and publish** — i.e., exactly what
   we add that they did not do.

> A "base paper" is the single existing publication your project most directly extends. Reviewers and paper
> referees expect you to (a) understand it deeply, (b) state precisely what it did, and (c) show a clear, honest gap
> that your work fills. This document is built to let any team member do all three.

---

## 1. The base paper we chose

> **Physics-Informed Graph Neural Networks for Attack Path Prediction.**
> François, M., Arduin, P.-E., & Merad, M. (2025). *Journal of Cybersecurity and Privacy*, 5(2), Article 15.
> DOI: 10.3390/jcp5020015. Open access. Public code + dataset: replication package on GitHub
> (`mbdlrocks/PhD_Replication_Package`, folder "Physics-Informed-GNN (PIGNN)").

We refer to it throughout as **PIGNN** (its own short name for its method — "Physics-Informed Graph Neural
Network").

### Why this paper is the right base for ASCEND
- **Same core problem family.** It is about **attack-path prediction** — using a model to work out the routes an
  attacker could take through a network. That is exactly the family ASCEND lives in.
- **Same core technique we use for scoring.** It uses a **graph neural network** (defined in §3) to score parts of
  an attack graph. ASCEND's exploitability scorer is the same kind of idea, applied to a different question.
- **It hands us concrete assets.** It **publishes its code and a dataset of 1,033 attack/environment graphs**, so
  our lineage is verifiable and we can benchmark against something real rather than asserting a comparison.
- **Its limitations are precisely our contribution.** As §6 shows, the three things PIGNN does *not* do —
  verify paths by execution, target Linux host-and-network privilege escalation, and prove remediation by
  re-running — are the three things ASCEND *does*. That is the cleanest possible base-to-contribution story.
- **Continuity.** It was already listed in our original synopsis, so choosing it is consistent with the project's
  stated foundations.

> **Honesty note on the date.** PIGNN is a **2025** paper (mid-2025). It is recent and directly relevant, and the
> team has accepted 2025 as acceptable. Where we want to point at the very latest 2026 work, we cite it as
> *related work* (see §7), not as the base.

---

## 2. The problem PIGNN addresses (plain English)

Large organisations, especially those running Microsoft Windows, use a system called **Active Directory (AD)** to
manage who is allowed to do what: users, computers, groups, and the permissions connecting them. Attackers who get
a foothold in such a network try to **chain permissions together** to climb from an ordinary account to a
highly privileged one (a "Domain Admin," who effectively controls everything).

You can draw all of those users, computers, groups and permissions as a **graph** — dots (called **nodes**)
connected by lines (called **edges**), where an edge means "this thing can act on that thing." An **attack path** is
a route through that graph from where the attacker starts to a high-value target. The famous open-source tool
**BloodHound** draws these AD graphs and finds such paths.

The problem: on a real network these graphs are **enormous**, and the number of possible paths explodes. Working out
**which edges actually matter** — which ones lie on real, usable attack paths — by brute force does not scale.

**PIGNN's goal:** train a model to **predict, for each edge in the graph, how likely that edge is to be part of a
real attack path**, so that the important routes surface automatically instead of being searched for by hand.

---

## 3. The concepts you need (each explained once)

- **Node / vertex.** A "dot" in a graph — here, a user, computer, or group.
- **Edge.** A "line" connecting two nodes — here, a permission or relationship ("member of", "can reset password
  of", "admin on").
- **Attack graph / environment graph.** The whole picture: all the nodes and edges of an environment. (PIGNN uses
  Active Directory environments.)
- **Attack path.** An ordered sequence of edges from the attacker's starting node to a target node.
- **Machine learning model.** A program that is *trained on examples* to make predictions, instead of being
  hand-coded with rules. You show it many graphs where the true attack paths are known, and it learns to recognise
  the pattern.
- **Graph Neural Network (GNN).** A machine-learning model **designed to work on graphs**. Ordinary models expect a
  flat table of numbers; a GNN instead lets each node "look at" its neighbours and pass messages along edges, so it
  can learn from the *structure* of the graph — who is connected to whom. This is why it suits attack graphs, where
  the structure is the whole point.
- **Edge scoring.** Instead of labelling whole paths, PIGNN scores **each edge**: a number for "how likely is this
  edge to be on a real attack path?" High-scoring edges are the dangerous ones.
- **"Physics-informed."** This is the paper's twist and the source of its name. A purely learned model can be a
  black box and can predict things that break the rules of the graph. "Physics-informed" here means they **combine
  the learned edge scores with classical, exact graph algorithms** — long-established procedures with guaranteed
  behaviour — so the final answer respects the real structure of the graph rather than trusting the neural network
  blindly. The classical algorithms they use are:
  - **Dijkstra's algorithm** — finds the shortest (here, most-likely / least-resistance) path between two nodes.
  - **Kruskal's and Prim's algorithms** — find a "minimum spanning tree," the cheapest set of edges that connects a
    set of nodes. (These are standard, decades-old graph algorithms taught in most computer-science courses.)
  In short: **the GNN decides how "heavy" each edge is; the classical algorithms then compute the actual paths using
  those weights.** Learning supplies the intuition; the algorithm supplies the rigour.
- **Self-supervised learning.** A way of training where the model creates its own labelled examples from unlabelled
  data (rather than needing a human to label everything). PIGNN uses this for two sub-tasks: predicting the
  attacker's **initial access** (where they get in) and their **impact** (what they can ultimately reach).
- **Sparsest cut / graph cut (their mitigation idea).** A "cut" is a set of edges whose removal splits the graph so
  the attacker can no longer reach the target. The "sparsest cut" is, roughly, a cheap such set. PIGNN includes a
  script (`SparsestCutMitigation.py`) that uses this idea to suggest **which edges to remove to break the predicted
  attack paths.** Keep this in mind — it is closely related to ASCEND's "chokepoint" idea, and §6 is careful about
  how we differ from it.
- **F1 score.** A single number between 0 and 1 that measures how good a yes/no prediction is, balancing two things:
  **precision** (of the things it flagged, how many were right) and **recall** (of the things it should have found,
  how many it caught). 1.0 is perfect. (Full definitions are in doc 04's glossary.)

---

## 4. What PIGNN actually does, step by step

1. **Take an Active Directory environment graph** (nodes = users/computers/groups, edges = permissions).
2. **Feed it to the graph neural network.** Each edge gets a learned **score** = the model's estimate of how likely
   that edge lies on a real attack path.
3. **Feed those scores as edge weights into the classical algorithms** (Dijkstra / Kruskal / Prim). This produces
   the predicted attack paths — the "physics-informed" combination of learning and exact computation.
4. **Two extra self-supervised predictors** estimate the attacker's likely **initial access** point and eventual
   **impact**.
5. **A mitigation step** (sparsest cut) suggests edges to remove to disrupt the predicted paths.
6. **Evaluate** by comparing predictions against the known attack paths in their dataset, reporting F1 scores.

---

## 5. Their data and their results

- **Dataset:** **1,033 environment graphs** with their associated attack paths, released publicly so others can
  reproduce and extend the work. The graphs represent Active Directory environments. (The exact way the graphs were
  generated is documented in their replication package's preprocessing folder; a team member reproducing the study
  should read that folder's notes.)
- **Results (their headline numbers):**
  - **Full attack-path prediction: F1 = 0.9308.**
  - **Initial-access prediction: F1 = 0.9780.**
  - **Impact prediction: F1 = 0.8214.**
  These are strong scores, and the authors argue the method generalises well and points toward "fully automated
  assessments."

> **What these numbers mean and don't mean.** They say the model reproduces the attack paths **in their dataset of
> graphs** well. They do **not** say the predicted paths were **tried against real machines** — the evaluation is
> graph-against-graph, not prediction-against-reality. That distinction is the heart of ASCEND's contribution (§6).

---

## 6. The gap — what PIGNN does NOT do (and ASCEND does)

This is the section to know cold; it is the justification for our entire project.

| Dimension | PIGNN (the base paper) | ASCEND (our project) |
|---|---|---|
| **Where paths are validated** | Against **other graphs** in a dataset — the model's prediction is compared to a "known" attack path that was itself computed, not executed | Against **reality**: every path is **executed in an isolated lab** and either works or does not (**ground truth by execution**) |
| **Environment** | **Active Directory (Windows)** identity/permission graphs | **Linux host-and-network** privilege escalation (SUID, sudo, kernel exploits, credential reuse, SSH, containers, NFS) |
| **Nature of the graphs** | **Generated** environment graphs (synthetic) | Graphs built from **facts collected from a running lab**, linked to real CVEs |
| **Remediation** | A **graph-theoretic** suggestion (sparsest cut) on the **predicted** graph | **Chokepoint** fixes whose effect is **proven by re-running** the attacks and showing the paths are gone (before/after) |
| **What the ML predicts** | Which **edges** lie on an attack path | Which **weaknesses are actually exploitable**, trained on **execution outcomes** |

**The one-sentence gap:** *PIGNN predicts attack paths on synthetic Windows/Active-Directory graphs and validates
them graph-against-graph; ASCEND finds privilege-escalation paths on a real Linux network, proves each one by
executing it, and proves its recommended fixes by re-running — turning prediction into demonstrated fact, and adding
a remediation result you can trust.*

> **Be fair about their mitigation.** PIGNN *does* include a graph-cut mitigation idea, so we must **not** claim
> "they do no remediation." Our honest differentiator on remediation is **proof by execution** — we apply the fix in
> the lab and show the attack no longer works — not the mere idea of cutting edges.

---

## 7. Related 2026 work (the current frontier we sit alongside)

To show the work is current, cite these alongside PIGNN (as *related work*, not the base):

- **Ben Fredj & Cheikhrouhou (2026), "Graph-based attack prediction with probabilistic correlation for real-time
  threat analysis," *The Journal of Supercomputing*.** Real-time correlation of alerts over attack graphs. ASCEND
  shares its interest in connecting observed evidence to a graph, but adds execution-verified ground truth. (This
  paper was also in our synopsis.)
- **"Predictive Analytics in Cloud-Native Privilege-Escalation Detection" (Computers, 2026, 15(8):501).** Detects
  privilege escalation in **cloud identity** graphs using temporal graph attention and reinforcement learning.
  ASCEND targets **Linux host-and-network** privilege escalation and verifies by execution. Useful to show
  privilege-escalation-via-graphs is an active 2026 topic.
- **Industry context:** automated-pentest vendors in 2026 describe "**choke points**" — edges whose removal breaks
  the most attack paths to high-value assets — which is exactly ASCEND's remediation output, and good evidence the
  problem matters in practice. (Cite as industry background, not academic base.)

---

## 8. The paper we will write (the narrative, stated as a story)

**Working title (adjust later):** *"ASCEND: Execution-Verified Privilege-Escalation Attack-Path Analysis and
Chokepoint Remediation for Linux Networks."*

**The story, in five beats — this is the spine of both the project and the paper:**

1. **The setting.** Attack-path prediction with graph machine learning is a hot area; PIGNN (2025) is a strong
   recent example, scoring attack-path edges on Active Directory graphs with a physics-informed GNN and even
   suggesting graph-cut mitigations.
2. **The unmet need.** But these methods validate **predictions against other predictions** on **synthetic**
   graphs, and they live in the **Windows/Active-Directory** world. Nobody has shown, on a **real Linux network**,
   that the predicted privilege-escalation paths **actually work**, nor **proven** that the suggested fixes remove
   them.
3. **Our idea.** Build the attack-path analysis on **ground truth from execution**: model a real Linux lab as a
   graph, enumerate privilege-escalation paths, and **run each one** to see if it works. Train an exploitability
   scorer on those **real outcomes**. Then compute the **chokepoints** — the fewest fixes that break the most
   verified paths — and **prove** them by re-running.
4. **What we show.** Measured path-finder precision (predicted vs. executed), an exploitability scorer that beats
   simple baselines on **held-out machines**, and a **before/after remediation** result where the paths genuinely
   disappear after the fix.
5. **Why it matters.** It converts attack-path analysis from *plausible predictions* into *demonstrated facts*, and
   it gives defenders a **prioritised, proven** fix list instead of a long severity-ranked backlog.

**Our stated contribution, narrowly and honestly (say exactly this):** *"Building on physics-informed graph-based
attack-path prediction (PIGNN, 2025), we contribute (1) an execution-verified methodology that grounds
privilege-escalation paths in real outcomes on a Linux network, (2) an exploitability scorer trained on those
outcomes and evaluated against baselines on held-out hosts, and (3) a chokepoint remediation whose effectiveness is
demonstrated by re-execution. We do not claim novelty in graph-based path prediction itself; our novelty is the
execution grounding and the demonstrated remediation."*

---

## 9. How we will actually use the base paper in the project

- **Benchmark / sanity check.** Their public 1,033-graph dataset lets us (optionally) reproduce a baseline
  graph-ML path predictor, so we can say "we reproduced the prior approach, then went beyond it."
- **Method reuse.** Their "learn edge weights, then run a classical algorithm" pattern is a clean design we can
  echo in our enumerator + scorer (learned exploitability feeding graph search).
- **Positioning.** Every claim we make is phrased as "PIGNN predicts; ASCEND proves." Keep that verb contrast — it
  is the whole pitch.

---

## 10. What is verified vs. what the team must confirm from the full PDF

Being explicit so nobody overstates in the paper or the viva:

- **Verified from public sources** (search results, the journal listing, the public replication package): the
  title/authors/journal/year/DOI; that it targets Active Directory attack graphs; that it uses a GNN whose edge
  scores feed classical algorithms (Dijkstra/Kruskal/Prim); that it adds self-supervised initial-access and impact
  predictors; that it includes a sparsest-cut mitigation script; the 1,033-graph public dataset; and the F1 scores
  0.9308 / 0.9780 / 0.8214.
- **Confirm by reading the full paper + replication package before submitting our own paper:** the exact GNN layer
  type and hyper-parameters; precisely how the 1,033 graphs were generated; the exact evaluation protocol (their
  train/test split); and the precise scope of their sparsest-cut mitigation. Read the preprocessing folder's notes
  in the replication package for the dataset details.

> Do not cite a number or a claim in our paper that a team member has not personally confirmed in the source. This
> is the same discipline that makes ASCEND's own results defensible.

# 05 — Demo and MVP Build Specification

This document tells the builders **exactly what to build** to have something concrete to show, at two levels:

- **§1 — The "thin slice"**: the smallest real thing that can be built quickly (overnight, with AI-assistant help)
  and shown at an early review.
- **§2 — The full demo**: what the finished project demonstrates.

It also fixes the **tools, libraries and datasets** (§3–§5) so nobody wastes time re-deciding.

> Guiding principle: **one small thing that genuinely works beats a large thing that half-works on stage.** Build the
> thin slice end-to-end before adding breadth.

---

## 1. The thin slice (buildable quickly; safe to show at an early review)

**What it demonstrates:** *"Here is a network, here is a real privilege-escalation path through it that we found
automatically, and here is the chokepoint that breaks it."*

### Minimum components
1. **A tiny network description.** Either:
   - a **3-container Docker Compose lab** (`web01` → `app01` → `db01`) with two *real* planted vectors (e.g., a
     `sudo` misconfiguration on `app01` and a readable SSH key on `web01`); **or**
   - if Docker time is short, a hand-written **`facts.json`** describing that same 3-host network. (This is
     legitimate for an early review as long as you are clear it is illustrative and the real system reads collected
     facts.)
2. **The path enumerator** (Person B) reading that network and printing the concrete path(s) from `web01`
   (low privilege) to `db01` (root), with the ATT&CK technique on each edge.
3. **A minimal chokepoint step:** identify which single vector, if removed, kills the path — even a two-line
   "which edge appears in the most paths" is enough for the thin slice.
4. **A single web page** (Person C) that draws the network graph and highlights the path, reading B's JSON output.

### What makes it honest
- Label it clearly as an early prototype on an illustrative network.
- The enumeration and chokepoint logic are the *real* algorithms that scale to the full lab — only the input is
  small. Say this explicitly; it is the same code path.

### What NOT to do for the thin slice
- Do not try to run the two kernel exploits, wire live telemetry, or train a model overnight. Those belong in the
  full build. The thin slice is about proving the *analysis* is real and produces a concrete path.

---

## 2. The full demo (the finished project's demonstration)

Roughly a 90-second scripted walk-through (this becomes `demo.md`):

| Time | On screen | What you say |
|---|---|---|
| 0:00 | Dashboard: the lab network graph, quiet | "An isolated lab: a web server, an app tier, and a database holding our target data." |
| 0:10 | ASCEND highlights enumerated paths foothold → database | "Starting from a low-privilege foothold on the web server, ASCEND has enumerated every escalation route to the database." |
| 0:25 | One path expands; each edge shows its technique | "Each step is a named ATT&CK technique — a reused key here, a sudo misconfiguration there, a kernel exploit at the end." |
| 0:40 | "Verify" runs; verified paths turn solid, unverified fade | "We don't just claim these — we execute each one in the lab. These solid paths actually work. Path-finder precision is X." |
| 1:00 | Remediation panel: ranked fixes + efficacy curve | "These three fixes are chokepoints: they eliminate most of the paths. Here's the fixes-versus-paths curve." |
| 1:20 | Apply top fix; re-run; those paths vanish | "We apply the top fix, re-run, and the paths that depended on it are gone — demonstrated, not asserted." |
| 1:35 | Benign look-alike scenario: no false alarm | "And when an admin legitimately uses SSH, ASCEND does not raise a path — it distinguishes real escalation from normal activity." |

The benign look-alike at the end pre-empts the obvious "what about false positives?" question.

---

## 3. Tool and library choices (decided, so nobody re-litigates)

| Concern | Choice | Why |
|---|---|---|
| Lab | **Docker + Docker Compose**, Linux only | Resets in seconds; one telemetry schema; fallback = 3 VMs |
| Host telemetry | **Falco** (eBPF) in containers; **auditd** if VMs | Works inside containers; standard |
| Attack execution | **Atomic Red Team** for scripted techniques; small custom scripts for the two anchor CVEs; **Caldera** only if multi-step orchestration is needed | Their operation logs double as ground-truth labels |
| Graph storage | **NetworkX** (in-memory Python) for the prototype; move to **Neo4j** only if traversal performance becomes a *measured* problem | Don't add a database prematurely |
| Analysis service | **FastAPI** (Python) | Lightweight; matches the ML stack |
| Machine learning | **scikit-learn** (logistic regression, then gradient-boosted trees); **PyTorch Geometric** only for the optional GNN stretch | Explainable first; heavy tooling only if it earns its place |
| Dashboard framework | **React** (with **Vite**), component library **shadcn/ui** or **Mantine**; graph view via **Cytoscape.js** or **vis-network**; charts via **Recharts** | Good-looking and flexible; see §4 |
| Language | **Python** for everything server-side; **TypeScript** for the dashboard | One backend language keeps the small team efficient |

---

## 4. On the dashboard: React, not Streamlit

The team has decided **not** to use Streamlit. This is a sound choice and here is the reasoning to give if asked:

- **Streamlit** is quick for simple data apps but re-runs the whole script on every interaction, which makes a live,
  interactive **network-graph** view (pan, zoom, click a node, expand a path) awkward and slow.
- A **React** app gives full control over an interactive graph (via Cytoscape.js or vis-network), looks
  presentation-grade, and cleanly separates the user interface from the analysis service (which stays in FastAPI).
- Recommended concrete stack: **Vite + React + TypeScript**, **shadcn/ui** (or **Mantine**) for polished components,
  **Cytoscape.js** for the network/path graph, **Recharts** for the remediation efficacy curve. The dashboard talks
  to FastAPI over a small JSON application programming interface (API).

Keep the dashboard **thin**: it renders what the analysis service computes. No analysis logic lives in the browser.

---

## 5. Datasets and data sources

ASCEND uses **two kinds of data**, and it is important to state which is which at review:

1. **Public reference data** (for the knowledge graph), pulled once from official sources:
   - **NVD / CVE** feeds (National Vulnerability Database) — vulnerability records and CVSS scores.
   - **CWE** list (Common Weakness Enumeration) — weakness categories.
   - **CAPEC** catalogue (Common Attack Pattern Enumeration and Classification) — attack patterns.
   - **MITRE ATT&CK** (via its public STIX/JSON data) — techniques and their relationships.
   - **Restrict the import to the neighbourhood of our seven techniques.** Importing all of NVD produces a graph too
     large to inspect or debug.

2. **Our own generated data** (for training and evaluation), produced by the lab:
   - The **facts** collected from each host.
   - The **execution outcomes** from the verifier (our labels).
   - These are generated by us **on purpose**, and their credibility comes from being *observed by execution* and
     *split by host*, not from any external dataset. (See doc 06 for why this is defensible.)

There is **no suitable off-the-shelf labelled dataset** for "did this specific privilege-escalation technique work on
this specific host configuration" — which is precisely why we generate ground truth by execution. Say this if asked
"why not use an existing dataset?": the label we need (real exploitability on a known configuration) does not exist
in public datasets; we produce it, verifiably.

---

## 6. Repository layout (suggested)

```
ascend/
  scope.yaml                # the seven techniques + evidence types + hosts (single source of truth)
  demo.md                   # the scripted demo from section 2
  lab/                      # Docker Compose, host images, planted vectors, exploit scripts (isolated)
  collectors/               # fact collectors (one per fact type) -> facts.json
  verifier/                 # execution verifier (Atomic Red Team wrappers, anchor-CVE scripts)
  knowledge_graph/          # pull + parse CVE/CWE/CAPEC/ATT&CK, restricted import
  environment_graph/        # build the lab graph from facts, link to knowledge graph
  enumerator/               # attack-path enumeration
  scorer/                   # features, baselines, exploitability model, evaluation
  chokepoint/               # min-cut / set-cover remediation engine
  service/                  # FastAPI app tying it together
  dashboard/                # React (Vite + TypeScript) front end
  eval/                     # metrics scripts, result tables, figures
  docs/                     # these documents
```

Agree the **`facts.json` schema** (A ↔ B) and the **analysis-output JSON schema** (B ↔ C) in week 1 so the three
workstreams build against stable interfaces without waiting on each other.

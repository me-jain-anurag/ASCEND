# 04 — Defense Document (Glossary + Anticipated Questions)

This document has two parts:

- **Part A — Glossary.** Every term and abbreviation used anywhere in the project, written out in full with a
  plain-English meaning. If a panel member asks "what does X mean?", the answer is here.
- **Part B — Anticipated questions.** The questions a review panel is likely to ask, grouped by theme, each with a
  prepared answer. Rehearse these.

> Rule for the whole team: **never say an abbreviation without knowing its full form and one-sentence meaning.** They
> are all in Part A.

---

# PART A — GLOSSARY

### Core project terms

- **ASCEND** — the project name. Stands for **A**ttack-path **S**coring and **C**hokepoint **E**valuation for
  **N**etwork **D**efence. It is a defensive tool that finds, proves, scores and helps remove privilege-escalation
  routes through a network.
- **Privilege escalation** — an attacker increasing the level of control they have on a system, for example going
  from an ordinary user account to the all-powerful administrator account.
- **Root** — on Linux, the all-powerful administrator account (equivalent to "Administrator" on Windows). "Getting
  root" means total control of that machine.
- **Foothold** — the attacker's starting position: a single, usually low-privilege, point of access they have
  already obtained (in our lab, a low-privilege account on the public web server).
- **Lateral movement** — an attacker moving sideways from one machine to another inside a network, as opposed to
  escalating privilege on a single machine.
- **Crown jewel** — the most valuable asset we are protecting; in our lab, the database host holding the target data.
- **Attack path** — a concrete, ordered sequence of steps (escalations and movements) leading from the foothold to
  the crown jewel.
- **Vector** (attack vector) — one specific weakness or misconfiguration that enables one step of an attack. In our
  data model a "vector" is a single finding on a host, such as a vulnerable kernel or an over-permissive `sudo` rule.
- **Chokepoint** — a weakness that many different attack paths pass through. Fixing a chokepoint breaks many paths at
  once, so chokepoints are the highest-value things to fix.
- **Remediation** — the fix that removes a weakness (patch the kernel, tighten the `sudo` rule, remove the reused
  key, etc.).
- **Ground truth** — a fact known to be true because it was directly observed. In ASCEND, ground truth is obtained
  by **actually executing** an attack technique in the lab and seeing whether it works, rather than guessing.
- **Exploitable** — a weakness is "exploitable" if an attacker can actually use it to succeed. A weakness can be
  *present* but not *exploitable* (for example, a bug that a specific patch has already neutralised).

### Security standards and catalogues (the "four public sources")

- **CVE — Common Vulnerabilities and Exposures.** A public dictionary that gives every known software vulnerability
  a unique identifier, such as **CVE-2021-4034**. Maintained by the MITRE Corporation.
- **CWE — Common Weakness Enumeration.** A catalogue of the *types* of software weakness (for example "improper
  input validation"). A CVE is a specific instance; a CWE is its category.
- **CAPEC — Common Attack Pattern Enumeration and Classification.** A catalogue of the *patterns* attackers use to
  abuse those weaknesses.
- **MITRE ATT&CK — Adversarial Tactics, Techniques, and Common Knowledge.** A widely used knowledge base of
  real-world attacker behaviours. Each behaviour has a **technique ID** such as **T1068**. "Tactics" are the
  attacker's goals (e.g., Privilege Escalation); "techniques" are how they achieve them.
- **NVD — National Vulnerability Database.** The U.S. government database that publishes CVE records with extra
  detail such as severity scores; our main source for CVE data.
- **CVSS — Common Vulnerability Scoring System.** A standard 0–10 severity score attached to each CVE. **A central
  point of our project is that CVSS alone does not tell you real risk**, because it ignores whether the weakness is
  reachable or actually exploitable in your specific network.

### The chain that links them
> **CVE → CWE → CAPEC → ATT&CK.** A specific vulnerability (CVE) is an instance of a weakness type (CWE), which is
> abused by an attack pattern (CAPEC), which corresponds to an attacker technique (ATT&CK). This chain is what our
> **knowledge graph** stores, and it is why our knowledge graph is genuinely useful rather than decorative.

### The techniques in our scope (full forms)

- **T1548.001 — Setuid/Setgid.** Abusing a program marked to run with its owner's (often root's) privileges. See
  "SUID" below.
- **T1548.003 — Sudo and Sudo Caching.** Abusing the `sudo` mechanism (see below) when it is configured too loosely.
- **T1068 — Exploitation for Privilege Escalation.** Using a software bug (in our case a Linux kernel bug) to gain
  higher privileges. Our two anchor bugs are PwnKit and DirtyPipe (below).
- **T1611 — Escape to Host.** Breaking out of a container to control the machine that runs it.
- **T1021.004 — Remote Services: SSH.** Logging into another machine using SSH (below).
- **T1550 — Use Alternate Authentication Material.** Reusing stolen credentials or keys instead of a password prompt.
- **T1552.001 — Unsecured Credentials: Credentials In Files.** Finding secrets (passwords, keys) left in readable
  files.

### Linux / systems terms

- **SUID binary — "Set User ID" binary.** A program flagged so that it runs with the privileges of its *owner*
  (often root) rather than the user who launched it. If such a program can be tricked into running arbitrary
  commands, an ordinary user gains root. A common privilege-escalation route.
- **sudo — "superuser do".** A Linux command that lets specified users run specified commands as root. A
  misconfigured `sudo` rule (allowing too much, or without a password) is a classic escalation vector.
- **Capabilities (Linux capabilities)** — a way of granting a program *some* root-like powers without full root; if
  granted carelessly, they enable escalation.
- **Kernel** — the core of the operating system. A bug in the kernel is especially dangerous because the kernel runs
  with the highest privilege.
- **PwnKit (CVE-2021-4034)** — a well-known vulnerability in `pkexec` (part of Linux "Polkit") that let any local
  user become root. One of our two anchor vulnerabilities.
- **DirtyPipe (CVE-2022-0847)** — a well-known Linux kernel vulnerability that let a local user overwrite files they
  should not, leading to root. Our second anchor vulnerability.
- **SSH — Secure Shell.** The standard way to log into a Linux machine over the network.
- **SSH key** — a file-based credential used instead of a password for SSH. If a private key is left readable and is
  accepted on another host, it enables lateral movement.
- **Credential reuse** — the same password or key working on more than one machine or account. A very common reason
  a single compromise spreads.
- **NFS — Network File System.** A way to share files between Linux machines over the network. The
  **`no_root_squash`** option is a misconfiguration that lets a remote user create files owned by root on the share,
  which can be turned into escalation.
- **Docker socket / docker group** — access to Docker's control channel; anyone with it can effectively become root
  on the host, so it is an "escape to host" vector.
- **Container** — a lightweight, isolated package that runs an application. We use containers to build the lab
  because they start and reset in seconds.
- **Docker / Docker Compose** — the tools we use to define and run the lab's containers. "Compose" describes a
  multi-container setup in one file.
- **Virtual machine (VM)** — a fully emulated computer; heavier than a container. Our fallback if containers cannot
  produce enough telemetry.

### Data-collection and telemetry terms

- **Telemetry** — the stream of events and facts we collect from the hosts (process launches, logins, file access,
  network connections).
- **Falco** — an open-source tool that watches Linux system activity (using a kernel technology called **eBPF —
  extended Berkeley Packet Filter**) and reports security-relevant events; works inside containers.
- **auditd — the Linux Audit Daemon.** The built-in Linux auditing service; our telemetry fallback if we use virtual
  machines instead of containers.
- **Collector** — our component that gathers facts and events from every host into one place.
- **Fact** — a single piece of collected configuration state, e.g., "host db01 runs kernel 5.15" or "user appuser
  may run /bin/tar via sudo without a password."

### Graph, algorithm and machine-learning terms

- **Graph** — a set of **nodes** (things) connected by **edges** (relationships). ASCEND models the network as a
  graph.
- **Knowledge graph** — our graph of *public* security concepts (CVE/CWE/CAPEC/ATT&CK plus description text).
- **Environment graph** — our graph of *the lab itself* (hosts, accounts, credentials, reachability, vectors).
- **Attack state** — during analysis, the set of (host, privilege) pairs the attacker currently controls; a path is
  a sequence of moves that grows this state until it includes the crown jewel.
- **Reachability** — whether one host can make a network connection to another (and on what service). An attack step
  is only possible if the target is reachable.
- **Path enumeration** — the algorithm that lists all the attack paths from the foothold to the crown jewel by
  searching the environment graph.
- **Minimum cut / vertex cut** — a graph-theory result: the smallest set of edges (or nodes) whose removal
  disconnects a start point from a target. We use it to find the fewest fixes that break the paths.
- **Set cover (weighted set cover)** — a classic optimisation problem: choose the fewest sets (here, fixes) that
  together cover all items (here, attack paths). We solve it greedily to rank remediations.
- **Feature** — a single measurable property fed to the machine-learning model (e.g., "is the kernel a vulnerable
  version?", "is the weakness patched?", "CVSS score", "is it reachable?").
- **Label** — the correct answer the model is trained to predict. Our labels are **execution outcomes**: did the
  technique actually work (1) or not (0)?
- **Machine learning (ML)** — training a program to predict an answer from examples rather than hand-coding rules.
- **Logistic regression** — a simple, transparent machine-learning model that outputs a probability; a good first
  choice because it is easy to explain and inspect.
- **Gradient-boosted trees** — a stronger but still explainable model made of many small decision trees; a likely
  upgrade from logistic regression.
- **Graph neural network (GNN)** — a machine-learning model that operates directly on graph structure; our optional
  Semester-2 stretch, not a load-bearing dependency.
- **Graph Attention Network (GAT)** — a specific kind of graph neural network (the type used by one of our base
  papers).
- **Baseline** — a deliberately simple method we compare the machine-learning model against, so we can prove the
  model actually adds value. Our baselines: "always predict the most common outcome" (majority class) and "predict
  exploitable if CVSS ≥ 7."
- **Training / validation / test split** — dividing data so the model learns on one part (training), is tuned on
  another (validation), and is judged on a third part it never saw (test).
- **Data leakage** — the mistake of letting information from the test set influence training, which produces
  impressive but meaningless scores. We avoid it by splitting **by host** (see Part B).
- **Precision** — of the things the system flagged as positive, what fraction really were positive. (For our
  path-finder: of the paths we proposed, what fraction actually execute.)
- **Recall** — of the things that really were positive, what fraction the system found.
- **F1 score** — a single number balancing precision and recall (their harmonic mean); useful when the classes are
  imbalanced.
- **Macro-F1** — the F1 score averaged evenly across classes, so a rare class counts as much as a common one.
- **Latency** — the time delay between an event happening and the system reacting.
- **p95 latency** — the 95th-percentile latency: the value below which 95% of measurements fall (a standard way to
  state "worst realistic case" performance).
- **SLO — Service Level Objective.** A stated performance target we hold ourselves to (e.g., "p95 under 5 seconds").

### Software / architecture terms

- **FastAPI** — a Python framework for building web services (our analysis core exposes its results through it).
- **React** — a modern web framework for building user interfaces; our dashboard is built in it (we are deliberately
  **not** using Streamlit — see doc 05 for the reasoning).
- **Cytoscape.js / vis-network** — JavaScript libraries for drawing interactive network graphs in the browser
  (candidates for the dashboard's graph view).
- **Neo4j** — a database specialised for storing and querying graphs; an option if our graphs get large.
- **NetworkX** — a Python library for building and analysing graphs in memory; our default for the prototype.
- **Atomic Red Team** — an open-source library of small, scripted attack techniques mapped to ATT&CK, used to
  *execute* techniques for our ground truth.
- **MITRE Caldera** — an open-source platform for automated, multi-step attack emulation; an alternative/complement
  to Atomic Red Team.

---

# PART B — ANTICIPATED QUESTIONS AND PREPARED ANSWERS

### Scope and motivation

**Q. In one sentence, what is this project?**
A. ASCEND finds every privilege-escalation route through a Linux network, proves each one by executing it in an
isolated lab, and computes the fewest fixes that break the most routes.

**Q. Why not just use a vulnerability scanner?**
A. A scanner lists weaknesses one machine at a time and ranks them by a generic severity score. It cannot tell you
that three individually minor weaknesses, plus a reused password, *chain* into a path from the web server to the
database. ASCEND reasons about the chains and about reachability, which is exactly what scanners omit.

**Q. Why is scoping to privilege escalation a strength, not a limitation?**
A. Because a narrow scope is *provable*. "We detect all attacks" is impossible to evaluate and easy for a panel to
poke holes in. "We find and verify privilege-escalation paths, on Linux, for these seven named techniques" is a
claim we can demonstrate and measure. Narrow-and-proven beats broad-and-hand-waved at any review.

**Q. Is privilege escalation really a networking project?**
A. Yes — the escalation paths cross hosts. Credential reuse, SSH trust, NFS shares, and network reachability between
machines are the edges that turn single-host escalation into a network-wide compromise. The core object is a
*network* graph.

### Novelty and related work

**Q. Isn't this just BloodHound?**
A. BloodHound maps attack paths in **Windows Active Directory** from collected permission data. ASCEND differs on
three axes: (1) it targets **Linux host-and-network** escalation, a far less tooled area; (2) it **verifies paths by
executing them**, where BloodHound only infers them; (3) it **computes an optimal remediation set** and proves the
fix works, which BloodHound does not do. We also add a learned exploitability score.

**Q. What is genuinely new here?**
A. The combination of **execution-verified ground truth** for Linux privilege-escalation paths with a
**remediation-as-optimisation** output (fewest fixes, most paths removed), proven by a before/after re-scan. We are
careful *not* to claim novelty over the whole field — just this specific, defensible combination.

**Q. How does it relate to the two papers in your synopsis?**
A. Gao et al. attach vulnerability *text* to a knowledge graph for better attack-path reasoning — we reuse that idea
for our exploitability features. Ben Fredj & Cheikhrouhou do real-time correlation over attack graphs — we share the
spirit of matching observed evidence to a graph. ASCEND's addition is the execution grounding and the remediation
optimisation.

### Technical design

**Q. Why three separate graphs?**
A. They are built at different times from different sources and answer different questions. The **knowledge graph**
is public and static. The **environment graph** is our specific lab. The **attack state** is what an attacker
controls right now. Merging them (as our earlier draft did) made the design impossible to reason about; separating
them makes each one simple.

**Q. How does path enumeration actually work?**
A. We model the attacker's position as a set of (host, privilege) pairs — the "attack state" — starting from the
foothold. From any controlled host we can (a) apply a local escalation vector to gain root on that host, or (b) use a
movement vector (reused credential, SSH key, reachable service) to gain a foothold on another host. We search these
transitions (depth-first, with pruning and a depth limit) and record every sequence that ends with control of the
crown jewel. It is a standard graph search over a state space we define precisely.

**Q. Won't the number of paths explode?**
A. It can, which is why we (1) restrict to the in-scope techniques, (2) bound the search depth, (3) cap the number of
paths, and (4) collapse equivalent paths. For remediation we do not need every path individually — we need the
*chokepoints*, which the set-cover step finds efficiently.

**Q. Why machine learning at all — why not just rules?**
A. Whether a weakness is truly exploitable depends on a combination of conditions (patch state, kernel version,
configuration, reachability), not on severity alone. A single rule like "CVSS ≥ 7" misclassifies many cases. A
learned model can capture the combination — and we *prove* it does by beating that rule on held-out machines. If it
did not beat the rule, we would say so and use the rule.

**Q. Is the machine-learning part essential, or bolted on?**
A. It is one measured component, not the whole project. The graph enumeration and remediation stand on their own and
give exact, reproducible results. The ML adds a prioritisation signal (which weaknesses to trust), and we hold it to
account against baselines. This is deliberate: the project's credibility does not *depend* on the model winning.

### Dataset and verifiability (the toughest area — see doc 06)

**Q. How do we know your results are real and not made up by the model?**
A. Because our labels are not opinions — they are **execution outcomes**. For every weakness and every path, the
attacker container actually runs the technique in the lab and we record whether it worked. The model is then judged
on whether it predicts those real outcomes on machines it never trained on. We can re-run the whole thing from a
fixed configuration and get the same numbers.

**Q. Isn't the data synthetic / self-generated? Doesn't that make it circular?**
A. The *lab* is synthetic, but the *outcomes are not scripted* — they are observed by execution. Crucially, our
scenarios **branch**: some attacks succeed, some fail, some stop early, and some are benign look-alikes (a
legitimate admin using SSH). Because the outcome is genuinely uncertain given the starting point, there is a real
prediction problem, not a replay of our own script. And we **split by host**, so the test is always on machines the
model has not seen.

**Q. What exactly is "splitting by host" and why does it matter?**
A. If we split individual findings randomly, findings from the same machine could land in both training and test,
and the model would effectively see the answer in advance — giving impressive but meaningless scores (this is "data
leakage"). By putting *entire hosts* on only one side of the split, the test genuinely measures whether the model
generalises to new machines.

**Q. How do you avoid over-cleaning the data?**
A. We remove only malformed records and exact duplicates. We keep the noise, the background activity, and the failed
attempts, because a model trained only on clean, unambiguous cases will not survive a real event stream.

### Evaluation and results

**Q. What are your success metrics?**
A. Four, each against a baseline (full table in doc 06): path-finder **precision/recall** (versus a
timing-window-only heuristic), next-step / exploitability **accuracy, precision, recall, macro-F1** (versus majority
class and CVSS threshold), remediation **efficacy** (does the recommended fix rank truly critical paths first, versus
raw CVSS ordering), and **latency** (versus our stated 5-second target). Every reported number comes from the
held-out test set, evaluated once.

**Q. What if the machine-learning model does not beat the baseline?**
A. Then we report exactly that. It is a legitimate scientific result — it tells the field that for this problem the
simple rule is enough — and the project still delivers the verified path-finder and the remediation engine. We would
rather find that out and report it honestly than hide it.

**Q. What is the single most important result you will show?**
A. The **before/after remediation proof**: we recommend a small set of fixes, apply them in the lab, re-run, and show
the attack paths are actually gone. That is a demonstrated result, not a claimed one.

### Safety and ethics

**Q. Isn't building attack tooling dangerous?**
A. Everything runs inside an **isolated lab** we built ourselves, on a private network with **no route** to the
internet or the campus network (except a one-time pull of public vulnerability data). Nothing is ever run against
college, personal, or third-party systems. The exploit code stays in the lab directory of our repository and is not
distributed. The purpose is defensive: controlled data generation to help defenders prioritise fixes.

**Q. Could this be misused?**
A. The techniques we use are already public and documented; we add no new offensive capability. What we add is on
the *defensive* side: verification and remediation prioritisation. This is the same posture as established tools like
BloodHound, which are used by defenders.

### Practicality

**Q. Would this work on a real, large network?**
A. Our prototype is centralised (a single collector and analysis service) and evaluated on lab-scale hardware. We
will report the event rate and latency we actually achieve and state honestly that horizontal scaling is future
work. The *methodology* — verify by execution, find chokepoints — applies at any scale; the engineering to scale it
is beyond a final-year prototype and we say so rather than pretending otherwise.

**Q. Executing every attack is expensive — is that realistic in production?**
A. In production you would not execute continuously; verification is a periodic, authorised assessment (like a
scheduled penetration test), while the graph reasoning and scoring run continuously. In our project, execution is
how we obtain trustworthy labels and prove remediation — which is exactly the point a panel should credit.

### Individual contribution (viva often asks each member)

Each member should be able to answer: *"What did you personally build, what was the hardest problem in it, and how
did you verify it works?"* Map yourself to your workstream in doc 03:
- **Person A:** the lab, collectors and execution verifier — hardest problem: reliably reproducing the two kernel
  exploits in containers and capturing clean success/failure labels.
- **Person B:** the graphs, path enumeration, scorer and chokepoint engine — hardest problem: preventing data
  leakage in the split and proving the model beats the baseline.
- **Person C:** the pipeline and dashboard — hardest problem: turning a stream of raw facts into a live, correct
  graph view without the interface lying about the underlying state.

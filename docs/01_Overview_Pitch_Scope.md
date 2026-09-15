# 01 — Overview, Pitch and Scope

## 1. The name

**ASCEND** — **A**ttack-path **S**coring and **C**hokepoint **E**valuation for **N**etwork **D**efence.

Why this name works, if the panel asks:

- **"Ascend" literally means to climb.** Privilege escalation *is* climbing — from a low-privilege foothold up to
  root (full administrative control) and across to critical machines. The name states the subject.
- Every letter carries a real part of the project:
  - **A — Attack-path**: the concrete routes an attacker can take through the network.
  - **S — Scoring**: the machine-learning component that scores how exploitable each step really is.
  - **C — Chokepoint**: the point where many attack paths pass through one weakness — our remediation target.
  - **E — Evaluation**: the project is measured rigorously, not asserted.
  - **N / D — Network Defence**: this is a defensive (blue-team) tool, not an attack tool.
- It names our actual contribution — **"Reduction"/"Chokepoint"** — not just detection. Anyone can *find* problems;
  ASCEND tells you the *fewest fixes that remove the most risk*.

> If the team later shifts emphasis, the expansion still holds: the four nouns (Attack-path, Scoring, Chokepoint,
> Evaluation) are the four things the project does regardless of the exact algorithms chosen.

---

## 2. The one-liner (for the panel)

> **ASCEND maps every privilege-escalation route an attacker could take from a low-privilege foothold to a critical
> asset across a Linux network, proves each route by executing it in an isolated lab, scores how exploitable each
> step really is, and computes the smallest set of fixes that eliminates the most routes.**

---

## 3. The problem we solve

Organisations defend their networks with three kinds of tools:

1. **Vulnerability scanners** (for example Nessus, OpenVAS) — list weaknesses on each machine, each with a severity
   number called a **CVSS score** (Common Vulnerability Scoring System, 0–10).
2. **Firewalls** — block or allow network connections.
3. **SIEM systems** (Security Information and Event Management — tools that collect and search security logs).

All three share the same blind spot: **they look at each weakness or alert on its own.** They will tell you that
machine A has a medium-severity issue and machine B has a low-severity issue, but not that *those two issues, plus a
reused password, chain together into a path from a public web server all the way to the customer database.*

Two concrete consequences:

- **Severity ≠ real risk.** A weakness rated "critical" on a machine that no attacker can reach is less urgent than
  three "low" weaknesses that together form a working path to your most important data. Ranking purely by CVSS
  therefore sends teams to fix the wrong things first.
- **Chaining is invisible and does not scale by hand.** A human analyst *could* in principle trace how weaknesses
  combine, but for anything larger than a handful of machines the number of possible routes explodes. Nobody maps
  them manually.

**ASCEND fills exactly this gap for privilege escalation and lateral movement on Linux networks:** it models the
network as a graph, enumerates the concrete escalation routes through it, proves which ones actually work, and then
tells the defender the smallest set of changes that breaks the most routes.

---

## 4. The scope — locked, and stated in standard terms

Scope creep is the classic way a final-year project becomes indefensible. ASCEND is deliberately narrow and
**does not claim to detect all attacks.** It is scoped to **privilege escalation and the lateral movement that
supports it, on Linux, inside an isolated container lab.**

We express the scope in **MITRE ATT&CK** terms. *MITRE ATT&CK* is a free, globally used knowledge base that gives
every real-world attacker behaviour a standard identifier (a "technique ID" such as `T1068`). Using it means our
scope is stated in a vocabulary the panel and any security professional already recognises, rather than in words we
made up.

### The techniques in scope

| Category (ATT&CK "Tactic") | Technique ID | Plain-English meaning | How it appears in our lab |
|---|---|---|---|
| Privilege Escalation | **T1548.001** — Setuid/Setgid | Abusing a program that runs as root to run our own commands as root | A misconfigured **SUID binary** (see glossary in doc 04) |
| Privilege Escalation | **T1548.003** — Sudo/Sudo Caching | Abusing an over-permissive `sudo` rule | A `sudo` rule that lets a service account run a dangerous command without a password |
| Privilege Escalation | **T1068** — Exploitation for Privilege Escalation | Using a kernel bug to jump to root | **PwnKit (CVE-2021-4034)** and **DirtyPipe (CVE-2022-0847)** |
| Privilege Escalation | **T1611** — Escape to Host | Breaking out of a container to control the underlying machine | A container with the Docker socket mounted, or a member of the `docker` group |
| Lateral Movement | **T1021.004** — Remote Services: SSH | Logging into another machine over SSH | Using a harvested key/password to reach the next host |
| Lateral Movement | **T1550** — Use Alternate Authentication Material | Reusing a stolen credential or key elsewhere | The same password/key works on a second machine (**credential reuse**) |
| Credential Access | **T1552.001** — Unsecured Credentials in Files | Finding a password or key left in a readable file | A `.env` file, a config, or shell history containing a secret |

*(Supporting cross-host misconfiguration: NFS `no_root_squash` — a network file share that lets a remote user write
files owned by root — is included as a movement/escalation vector because it is common, realistic, and easy to plant.)*

### The two anchor vulnerabilities

We anchor the kernel-exploitation technique on **two named, real Common Vulnerabilities and Exposures (CVEs)**:

- **PwnKit — CVE-2021-4034** (a flaw in `pkexec`, part of the Linux Polkit toolkit).
- **DirtyPipe — CVE-2022-0847** (a flaw in the Linux kernel's pipe handling).

Why these specifically:

- Both are **trivially reproducible inside a container**, and both are **exhaustively documented** publicly.
- Both map cleanly to technique **T1068**, so the ATT&CK linkage is *real*, not asserted.
- Each gives a genuine, end-to-end **CVE → CWE → CAPEC → ATT&CK** chain (see doc 04 for what those four are). That
  chain is what makes the *knowledge graph* in our design load-bearing rather than decorative.

### What is explicitly OUT of scope (say this proactively)

- Windows and Active Directory (that is BloodHound's territory — see §6).
- Detecting malware, phishing, denial-of-service, or web-application exploitation *as goals in themselves*. (We use
  one web exploit only as the attacker's initial foothold; it is not what we study.)
- Running anything against real, production, or third-party systems. **Everything happens in an isolated lab we
  build ourselves** (see doc 04, Safety).

> **The sentence to say at review:** *"ASCEND does not detect all attacks. It answers one question well: given a
> foothold, what are all the ways an attacker escalates to our critical assets, which of them actually work, and
> what is the cheapest way to break them? We evaluate on paths and hosts the system has not been trained on."*

---

## 5. What ASCEND produces (the concrete outputs)

1. **A map of attack paths** from a chosen entry point to the crown-jewel asset, each path a concrete sequence of
   escalation and movement steps.
2. **A verification verdict per path**: does it actually execute in the lab? This yields a measured
   **precision** for the path-finder (of the paths we proposed, what fraction really work).
3. **An exploitability score per weakness**, from a machine-learning model, reported against simple baselines so
   the model has to *earn* its place.
4. **A remediation recommendation**: the smallest set of fixes (the **chokepoints**) that eliminates the most
   attack paths, with a "fixes-vs-paths-eliminated" efficacy curve — and a **re-scan that proves the paths are
   gone after the fix is applied.**

---

## 6. What we contribute over existing work (the "isn't this just X?" defence)

A panel *will* ask how this differs from existing tools and papers. Prepared answers:

### vs. BloodHound (the obvious comparison)
**BloodHound** is a well-known open-source tool that graphs attack paths in **Windows Active Directory**.
- It is **Active-Directory-specific** (Windows identity/permission relationships). ASCEND targets **Linux host and
  network privilege escalation** — a different and less-tooled domain.
- BloodHound **shows** paths from collected facts but **does not verify** that a path actually works, and **does not
  compute an optimal remediation set**. ASCEND adds **execution verification** (ground truth) and **chokepoint
  optimisation** (fewest fixes, most paths removed), plus a **learned exploitability score**.

### vs. logical attack-graph research (for example MulVAL)
Classic academic attack-graph tools reason *logically* from scanner output to produce a graph of possible attacks.
They generally **do not execute** the attacks to confirm them, and **do not learn** which weaknesses are truly
exploitable versus merely present. ASCEND's execution-grounded verification and learned scoring are the delta.

### vs. the two base papers from the original synopsis
- **Gao et al. (2026)** — *text-enhanced graph attention over a cybersecurity knowledge graph.* We reuse the idea of
  attaching **vulnerability description text** to graph nodes to enrich features for scoring.
- **Ben Fredj & Cheikhrouhou (2026)** — *real-time probabilistic correlation over attack graphs.* We reuse the
  spirit of correlating observed evidence against a graph.
- **Our narrow, honest claim:** ASCEND sits between them and adds what neither has — **execution-verified ground
  truth** for privilege-escalation paths and a **remediation-optimisation** output. We do **not** claim novelty over
  the entire field; we claim a specific, defensible combination.

> A modest, precise claim is exactly what a zeroth/early review wants to hear. Do **not** inflate it.

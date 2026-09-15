# 02 — Architecture and Diagrams

All diagrams below are written in **Mermaid**. Notion, GitHub, Obsidian and most Markdown tools render these
automatically from the `mermaid` fenced code blocks. Each diagram is followed by a plain-English explanation you
can read aloud at the review.

> **Presentation tip:** for the review slide deck, screenshot each rendered diagram. Keep the explanation paragraph
> as your speaker notes.

---

## 1. System architecture (the whole system on one page)

```mermaid
flowchart TB
    subgraph LAB["Isolated Lab (Docker network, Linux only)"]
        H1["web host<br/>entry foothold"]
        H2["app / ci / nfs hosts"]
        H3["db host<br/>CROWN JEWEL"]
        AT["attacker container<br/>(emulation tooling)"]
    end

    subgraph COLLECT["Collection layer"]
        AG["Fact collectors<br/>(one per host)"]
        VER["Execution verifier<br/>(Atomic Red Team / scripts)"]
    end

    subgraph BUILDTIME["Build-time knowledge (static)"]
        KG["Knowledge graph<br/>CVE / CWE / CAPEC / ATT&CK + text"]
    end

    subgraph CORE["ASCEND analysis core (FastAPI service)"]
        EG["Environment graph builder"]
        PE["Path enumerator"]
        ML["Exploitability scorer (ML)"]
        CH["Chokepoint / remediation engine"]
        EVAL["Evaluation harness"]
    end

    UI["Dashboard (React web app)"]

    AT -->|runs techniques| LAB
    LAB --> AG
    LAB --> VER
    AG -->|normalised facts JSON| EG
    KG --> EG
    EG --> PE
    VER -->|ground-truth labels| ML
    VER -->|which paths really work| PE
    PE --> ML
    ML --> CH
    PE --> CH
    CH --> EVAL
    PE --> EVAL
    ML --> EVAL
    CORE --> UI
    KG -. enriches .-> ML
```

**Explanation.** On the left is the **isolated lab** — a set of Linux containers on a private Docker network, with
one deliberately vulnerable **web host** (the attacker's entry point) and a **database host** holding the data we
are protecting (the "crown jewel"). An **attacker container** runs the actual attack techniques. Two things watch the
lab: **fact collectors** (which read each host's configuration — users, `sudo` rules, SUID programs, kernel version,
open ports, stored credentials) and the **execution verifier** (which actually *runs* each escalation technique and
records whether it succeeded — this is our ground truth). The collectors' facts, combined with the **knowledge
graph** of public vulnerability data, are assembled into the **environment graph**. The **analysis core** then
enumerates attack paths, scores how exploitable each step is, computes the cheapest remediation, and evaluates
everything. The **dashboard** presents it to an analyst.

---

## 2. The three graphs and three data flows

This is the most important conceptual diagram. ASCEND uses **three distinct graphs**, built at three different
times. Confusing them is what made the earlier "Sentinel" plan hard to follow.

```mermaid
flowchart LR
    subgraph BT["A. BUILD-TIME (runs occasionally)"]
        direction TB
        PUB["Public feeds:<br/>NVD/CVE, CWE, CAPEC, ATT&CK"] --> KG["KNOWLEDGE GRAPH<br/>concepts + description text"]
        CFG["Lab config + collector facts"] --> ENVG["ENVIRONMENT GRAPH<br/>hosts, accounts, creds,<br/>reachability, vectors"]
        KG -. each vector links to .-> ENVG
    end

    subgraph OFF["B. OFFLINE TRAINING (during development)"]
        direction TB
        RUNS["Execution verifier outcomes<br/>(did each technique work?)"] --> DS["Labelled feature dataset"]
        DS --> SPLIT["Split by HOST<br/>(no leakage)"]
        SPLIT --> TRAIN["Train exploitability scorer<br/>+ baselines"]
        TRAIN --> MODEL["Saved model"]
    end

    subgraph AN["C. ANALYSIS / RUNTIME (what the demo shows)"]
        direction TB
        ENUM["Enumerate attack paths<br/>on the environment graph"] --> SCORE["Score each step<br/>(saved model)"]
        SCORE --> CHOKE["Chokepoint remediation"]
        CHOKE --> DASH["Dashboard"]
    end

    ENVG --> ENUM
    KG --> SCORE
    MODEL --> SCORE
```

**Explanation.**
- **Flow A — build-time.** The **knowledge graph** captures *public* facts about vulnerabilities and attack
  techniques (it is the same for everyone; refreshed occasionally). The **environment graph** captures *our lab*
  (hosts, accounts, credentials, what can reach what, which weaknesses are present). Each weakness in the
  environment graph is *linked* to the matching concept in the knowledge graph — that link is what turns "the web
  host has CVE-2021-4034" into "the web host is exploitable via technique T1068."
- **Flow B — offline training.** During development we run attacks in the lab, record whether each worked, turn that
  into a labelled dataset, split it **by host** so the model is tested on machines it never trained on, and train the
  exploitability scorer. This produces one file: a saved model. **It never runs during the live demo.**
- **Flow C — analysis / runtime.** This is what the reviewer watches: enumerate the paths, score them with the saved
  model, compute remediation, show it on the dashboard.

---

## 3. End-to-end sequence (what happens, in order)

```mermaid
sequenceDiagram
    autonumber
    participant Attacker as Attacker container
    participant Lab as Lab hosts
    participant Coll as Collectors + verifier
    participant Core as ASCEND core
    participant KG as Knowledge graph
    participant UI as Dashboard

    Note over Core,KG: BUILD-TIME (done ahead of demo)
    Core->>KG: Pull CVE/CWE/CAPEC/ATT&CK for our techniques
    Coll->>Lab: Read host facts (users, sudo, SUID, kernel, ports, creds)
    Coll->>Core: Send normalised facts
    Core->>Core: Build environment graph, link vectors to KG

    Note over Attacker,UI: ANALYSIS
    Core->>Core: Enumerate all escalation paths entry -> crown jewel
    Attacker->>Lab: Execute each candidate technique
    Lab-->>Coll: Success / failure per technique
    Coll->>Core: Ground-truth outcomes
    Core->>Core: Mark which paths VERIFY (really work)
    Core->>Core: Score exploitability of each step (ML model)
    Core->>Core: Chokepoint analysis -> fewest fixes, most paths killed
    Core->>UI: Push paths, scores, remediation
    Note over Core,Lab: PROOF
    Core->>Lab: Apply a recommended fix
    Core->>Core: Re-enumerate + re-verify
    Core->>UI: Show the eliminated paths are gone
```

**Explanation.** Read top to bottom. The build-time steps (pulling public data, reading host facts, assembling the
graph) happen before the review. During analysis, ASCEND enumerates the possible paths, the attacker container
actually runs the techniques, and the outcomes tell us which paths are real. We then score and prioritise, recommend
the cheapest fix, and — the clinching step — *apply the fix and re-run* to prove the paths really disappear. That
last block is the strongest thing to show a panel: the result is demonstrated, not claimed.

---

## 4. Data schema (what the graph actually stores)

```mermaid
erDiagram
    HOST ||--o{ ACCOUNT : "has"
    HOST ||--o{ VECTOR : "exposes"
    HOST ||--o{ ASSET : "holds"
    HOST ||--o{ REACHABILITY : "can_reach"
    ACCOUNT ||--o{ CREDENTIAL : "authenticates_with"
    CREDENTIAL ||--o{ ACCOUNT : "reused_as"
    VECTOR ||--|| KG_TECHNIQUE : "maps_to"
    KG_TECHNIQUE ||--o{ KG_CVE : "realised_by"

    HOST {
        string hostname
        string role
        string os
        string kernel_version
        int asset_value
    }
    ACCOUNT {
        string username
        string type "root|service|human"
        int privilege_level
    }
    CREDENTIAL {
        string cred_id
        string type "password|ssh_key|token"
        string discoverable_at "privilege needed to read it"
    }
    VECTOR {
        string vector_id
        string technique "e.g. T1548.001"
        string cve
        float cvss
        json features "kernel, patch state, config, reachability"
        bool verified_exploitable
    }
    ASSET {
        string asset_id
        string kind "data|service"
        int criticality
    }
    REACHABILITY {
        string from_host
        string to_host
        int port
        string service
    }
    KG_TECHNIQUE {
        string attack_id
        string capec
        string cwe
        string description_text
    }
    KG_CVE {
        string cve_id
        float base_cvss
        string description
    }
```

**Explanation.** A **HOST** has **ACCOUNTs**, exposes **VECTORs** (privilege-escalation opportunities), may hold
**ASSETs** (valuable data), and has **REACHABILITY** to other hosts. **ACCOUNTs** authenticate with **CREDENTIALs**;
a credential **reused** on another host is the edge that lets an attacker move sideways. Every **VECTOR** maps to a
**KG_TECHNIQUE** (an ATT&CK technique) in the knowledge graph, which is in turn realised by one or more **KG_CVE**
records. The `verified_exploitable` flag on a VECTOR is the ground truth from execution — the field that makes our
numbers trustworthy.

---

## 5. Example: one enumerated attack path

```mermaid
flowchart LR
    E["web01<br/>account: www-data<br/>(low privilege)"]
    E -->|"T1552.001<br/>read SSH key from readable file"| S1["credential:<br/>app deploy key"]
    S1 -->|"T1021.004 + T1550<br/>SSH using reused key"| A["app01<br/>account: appuser"]
    A -->|"T1548.003<br/>sudo misconfig -> root"| AR["app01<br/>account: root"]
    AR -->|"T1021.004<br/>reachable over SSH"| D["db01<br/>account: dbuser"]
    D -->|"T1068<br/>DirtyPipe kernel exploit -> root"| DR["db01 = ROOT<br/>CROWN JEWEL COMPROMISED"]

    style E fill:#e05a5a,color:#fff
    style DR fill:#e0b341,color:#000
```

**Explanation.** This is a single concrete path the enumerator would output. The attacker starts as the
low-privilege `www-data` account on the web host, finds a reusable SSH key in a readable file (**T1552.001**), uses
it to move to the app host (**T1021.004 / T1550**), abuses a `sudo` misconfiguration to become root there
(**T1548.003**), reaches the database host over SSH, and finally uses the DirtyPipe kernel exploit (**T1068**) to
become root on the crown jewel. Each edge is a technique ASCEND can *execute* to confirm the path is real. A
**chokepoint** here might be the reused SSH key: remove it, and every path that relied on it dies at once.

---

## 6. Deployment view (the lab)

```mermaid
flowchart TB
    subgraph DOCKER["Docker Compose - private bridge network (no internet route)"]
        WEB["web01<br/>vulnerable app, entry"]
        APP["app01 / app02"]
        CI["ci01<br/>docker socket exposed"]
        NFS["nfs01<br/>no_root_squash export"]
        DB["db01 / db02<br/>data assets"]
        ADM["admin01<br/>jump host"]
        ATT["attacker01<br/>emulation tooling"]
        COL["collector01<br/>collectors + queue + FastAPI + dashboard"]
    end
    PUBLIC["Public vulnerability feeds<br/>(pulled once, from collector only)"]

    ATT -. attacks .-> WEB
    ATT -. attacks .-> APP
    WEB --- APP
    APP --- DB
    CI --- APP
    NFS --- APP
    ADM --- DB
    WEB --> COL
    APP --> COL
    DB --> COL
    CI --> COL
    NFS --> COL
    COL -->|one-time fetch| PUBLIC
```

**Explanation.** Everything runs as **Docker containers on one private network** with **no route to the internet or
the campus network**, except a single, one-time pull of public vulnerability data from the collector host. Containers
reset in seconds (versus minutes for virtual machines), which matters because building the training dataset requires
hundreds of reset-and-run cycles. If container telemetry ever proves insufficient, the fallback is **three virtual
machines** (attacker, web+app, database) — but containers are the default.

---

## 7. Component / workstream map (who owns what — see doc 03)

```mermaid
flowchart TB
    subgraph A["Workstream A - Lab & Ground Truth (Person A)"]
        A1["Docker lab + planted vectors"]
        A2["Fact collectors"]
        A3["Execution verifier"]
    end
    subgraph B["Workstream B - Graphs & ML (Person B)"]
        B1["Knowledge graph"]
        B2["Environment graph builder"]
        B3["Path enumerator"]
        B4["Exploitability scorer + baselines"]
        B5["Chokepoint engine + evaluation"]
    end
    subgraph C["Workstream C - App & Integration (Person C)"]
        C1["Collector -> queue -> FastAPI pipeline"]
        C2["React dashboard"]
        C3["Demo orchestration + docs"]
    end

    A2 --> B2
    A3 --> B4
    A3 --> B3
    B1 --> B2
    B3 --> B5
    B4 --> B5
    B5 --> C2
    C1 --> B2
```

**Explanation.** Three parallel workstreams. **A** owns everything that produces ground truth (the lab, the
collectors, the execution verifier). **B** owns the analysis brain (both graphs, path enumeration, the ML scorer,
chokepoint analysis, evaluation). **C** owns the plumbing and the face (the data pipeline, the dashboard, the demo).
The arrows show the hand-off points; §03 turns these into a week-by-week schedule and explains how it degrades to two
people if needed.

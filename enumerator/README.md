# `enumerator/` — from facts to attack paths

```
environment_graph/facts.json ──► pathfinder.py ──► eval/analysis.json
                                              └─► dashboard/data.js
```

Answers one question: **given what is actually on these machines, what sequences
of steps take an attacker from the entry foothold to root on the crown jewel?**

```bash
python3 enumerator/pathfinder.py
```

**No dependencies.** Standard library only, deliberately — see below.

---

## The idea in one paragraph

Think of the attacker as holding a **set of keys**, not standing in one place.

At any moment the attacker controls some set of `(host, privilege)` pairs and
holds some set of credentials. That pair of sets *is* the attacker's state. The
run starts with one thing controlled — `web01:low` — and nothing held. Each
legal move grows the state. A path is any sequence of moves that ends with the
crown jewel in the controlled set.

This is why it is a **state-space search and not a shortest-path algorithm**.
An attacker never gives up what they already control, so the state only ever
grows, and "where am I now?" is the wrong question — "what do I hold?" is the
right one. Two paths can visit the same hosts in the same order and still be
different paths, because the order in which privilege was gained differs.

## The three moves

Every edge in every reported path is one of these. Nothing else is possible.

| # | Move | What it means | Technique |
|---|---|---|---|
| 1 | **Harvest** | read a credential out of a file you can already reach | `T1552.001` |
| 2 | **Move** | log in somewhere else using a credential you hold | `T1021.004 + T1550` |
| 3 | **Escalate** | become root on a host you already have a foothold on | `T1548.003`, `T1548.001`, `T1068`, `T1611` |

Move 2 is the one that matters. It requires **both** a held credential that the
target accepts **and** network reachability from something you already control.
Either alone is not enough, which is why credential reuse and network
segmentation interact the way they do — and why fixing either one can break a
path.

## Worked example

From the current lab:

```
web01:low  --[T1552.001]-->        cred:app_deploy_key    harvest the readable key
web01:low  --[T1021.004+T1550]-->  app01:low              the key opens app01
app01:low  --[T1021.004+T1550]-->  db01:low               the SAME key opens db01
app01:low  --[T1548.003]-->        app01:root             sudo tar spawns a root shell
db01:low   --[T1068]-->            db01:root              DirtyPipe
```

Note steps 3 and 4: the attacker reaches `db01` *before* taking root on `app01`.
That ordering is a genuinely distinct path, and it is why the lab yields three
paths rather than one. It also explains why removing the sudo rule kills two of
the three and not all of them — one route never needed `app01:root` at all.

---

## Why depth-first, and why it terminates

`enumerate_paths()` is a recursive DFS with two guards:

- **Visited-state pruning.** A state already seen on the current trail is not
  re-entered. Since states only grow, this rules out cycles outright.
- **`max_depth=12`.** A backstop for pathological inputs, not a design limit.

Enumerating *every* path is exponential in the worst case; that is inherent to
the question, not a flaw in the implementation. It is tractable here because the
state space is bounded by the number of `(host, privilege)` pairs and
credentials, both small. **If a larger fact set makes this slow, that is the
measured signal to move to a smarter search** — not something to pre-optimise
for now (docs/05 §3 makes the same argument about Neo4j).

## The two metrics

`path_precision()` returns both, and they must never be collapsed into one
number:

| Metric | Meaning | Current |
|---|---|---|
| `config_coverage` | every vector on the path has the configuration its technique needs | **3/3** |
| `precision` | the path was confirmed **by executing it** | **0/3** |

Config coverage is what reading a machine can establish: *the door is unlocked*.
Precision requires *we walked through it*, which only `verifier/` can determine —
and it does not exist yet, so `0` is the honest value rather than a gap to be
papered over. Vectors carry `verified_exploitable: null` and
`config_exploitable: true` to keep the two claims apart.

---

## Input and output

**Input** — `environment_graph/facts.json`, the schema in docs/02 §4. Generated
by `collectors/collect.py`; a hand-written fallback ships in the repo.

Only these keys are read, and everything else is ignored — so extra fields like
`features`, `_meta` and per-host provenance pass through harmlessly:

| Function | Reads |
|---|---|
| `enumerate_paths()` | `entry`, `crown_jewel`, `reachability`, `credentials`, `vectors` |
| `build_graph()` | `entry`, `crown_jewel`, `reachability`, `hosts` |

Note what the search itself does **not** read: `hosts` and `accounts`. Roles and
asset values play no part in finding a path — they are presentation and, later,
scoring. A path is found from reachability, credentials and vectors alone.

**Output** — `eval/analysis.json`:

| Key | Contents |
|---|---|
| `entry`, `crown_jewel` | echoed from the facts |
| `graph` | nodes and edges for the dashboard network view |
| `paths` | list of paths; each a list of steps `{from, to, technique, technique_name, vector_id}` |
| `chokepoints` | vectors ranked by how many paths they lie on |
| `path_finder` | the two metrics above |

`dashboard/data.js` is the same object assigned to `window.ASCEND_DATA`, so the
standalone HTML viewer works over `file://` without a server.

## Used as a library

```python
from enumerate import enumerate_paths, path_precision
paths = enumerate_paths(facts)
```

Imported in-process by `service/main.py`, `chokepoint/engine.py` and
`tests/test_pipeline.py` — no subprocess, no temporary files. Each inserts
`enumerator/` on `sys.path` first, since the directory is not a package.

## No third-party dependencies, on purpose

This module must run on a bare clone with no `pip install`, no virtualenv and no
Docker, because it is the fallback when everything else is unavailable — and
because a reviewer should be able to read the algorithm without first
understanding a framework. `scope.yaml` is therefore **not** read here, even
though the collector and chokepoint engine both use it; that would drag in
PyYAML.

---

## Known limits

Worth knowing before you extend it, and worth stating plainly if asked:

- **Privilege is a two-level ladder** — `low` and `root`. Real systems have
  group membership, capabilities and sudo-to-another-user. `PRIV` at the top of
  the file is the single place that changes.
- **Reachability is host-to-host, not port-aware.** An edge means "can open a
  connection", not "can reach the service this technique needs".
- **Every enumerated path is treated as equally likely.** Ranking by
  exploitability is `scorer/`'s job (Semester-1 M5) and it does not exist yet.
- **`chokepoint()` in this file is a counter, not the engine.** It ranks vectors
  by how many paths mention them — an inference from the graph. The real
  remediation engine is `chokepoint/engine.py`, which *measures* each fix by
  removing it from a copy of the facts and re-running this enumerator. The
  service and dashboard use the engine; the counter stays so that running this
  module alone still gives a useful answer with no dependencies.

## Changing the lab and re-running

```bash
python3 collectors/collect.py      # re-probe the lab
python3 enumerator/pathfinder.py    # re-analyse
```

To explore without touching the lab, edit `environment_graph/facts.json` by hand
— add a host, a vector, a credential, a reachability edge — and re-run just the
enumerator. It will believe whatever the file says, which makes it a good way to
ask "what if this machine were also vulnerable?"

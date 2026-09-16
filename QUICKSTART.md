# ASCEND — Thin Slice Quickstart

The smallest real thing: a network, the privilege-escalation paths through it that ASCEND finds
**automatically**, and the chokepoint that breaks them. Runs offline, no install, ~30 seconds.

---

## Run it (2 commands)

```bash
# 1. Enumerate paths + chokepoints from the lab facts (regenerates the dashboard data)
python3 enumerator/enumerate.py

# 2. Open the dashboard — just double-click it, or:
open dashboard/index.html        # macOS
```

No `pip install`, no server, no internet. Python 3 standard library only. The dashboard is one
self-contained HTML file (inline SVG) that reads `dashboard/data.js`.

---

## What you'll see

| Piece | File | What it shows |
|---|---|---|
| **The lab** | `environment_graph/facts.json` | 3 hosts: `web01` (entry) → `app01` → `db01` (crown jewel), with real planted vectors |
| **The paths** | `eval/analysis.json` | 3 privilege-escalation paths, each edge tagged with its MITRE ATT&CK technique |
| **The chokepoints** | (same file) | Fixes ranked by how many paths each one eliminates |
| **The dashboard** | `dashboard/index.html` | Network graph, click a path to highlight it, precision metric, chokepoint panel |

**Headline result:** removing the reused SSH key (`v_web01_readable_key`) kills **3 of 3** paths.
DirtyPipe also kills 3/3; the sudo misconfig only 2/3. That is the "fewest fixes, most paths" idea,
demonstrated.

---

## What to say at the review (the honesty line)

> "The network here is illustrative and small. But the **enumeration and chokepoint code are the real
> algorithms** — a depth-first search over the attacker's `(host, privilege)` state space and a
> paths-per-vector ranking. The same code path runs unchanged on the facts collected from the full
> Docker lab; only the input grows."

Precision reads **1.00** because every planted vector is marked `verified_exploitable`. In the full
build that number comes from **actually executing** each path in the isolated lab — that is the
Semester-1 deliverable, not the thin slice (see `docs/05` §1: do **not** run the kernel exploits for
the thin slice).

---

## How the enumerator works (30-second explanation)

The attacker's state is the set of `(host, privilege)` pairs they control, starting at
`web01:low`. Three kinds of move grow that state:

1. **Harvest** a credential from a readable file — `T1552.001`
2. **Move** laterally with a reused credential over SSH — `T1021.004 + T1550`
3. **Escalate** locally (sudo / SUID / kernel exploit) — `T1548.003`, `T1068`

A depth-first search records every sequence of moves that ends with `db01:root`. Then the chokepoint
step counts how many paths each vector lies on and ranks the fixes. This mirrors
`docs/04` ("How does path enumeration actually work?") and `docs/02` §5 (the example path).

---

## To change the lab

Edit `environment_graph/facts.json` (add a host, a vector, a credential, a reachability edge), then
re-run `python3 enumerator/enumerate.py`. The dashboard picks up the new `data.js` on refresh. The
schema matches `docs/02` §4.

---

## Files

```
environment_graph/facts.json   # the illustrative lab (hand-written to the collector schema)
enumerator/enumerate.py        # DFS path enumeration + chokepoint ranking (the real algorithms)
eval/analysis.json             # generated: paths, chokepoints, precision
dashboard/data.js              # generated: same data as a JS global (avoids file:// fetch issues)
dashboard/index.html           # generated-data viewer: network graph + paths + chokepoints
```

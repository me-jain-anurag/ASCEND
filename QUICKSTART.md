# ASCEND — Thin Slice Quickstart

A network, the privilege-escalation paths through it that ASCEND finds
**automatically**, and the chokepoint that breaks them.

Two ways to run it. The Docker path collects facts from a real lab; the offline
path replays a recorded capture and needs nothing but Python 3.

---

## A. With the lab (what the demo runs on)

Needs Docker Engine and Compose v2 — **install commands are in
[`lab/README.md`](lab/README.md#prerequisites--installing-docker)**.
No Docker? Skip to B.

```bash
bash lab/up.sh                     # 3 containers on two isolated networks
python3 collectors/collect.py      # probe them -> environment_graph/facts.json
python3 enumerator/pathfinder.py    # paths + chokepoints
```

Then the dashboard:

```bash
pip install -r service/requirements.txt
python3 service/main.py            # FastAPI on 127.0.0.1:8000
cd dashboard && npm install && npm run dev
```

`bash lab/down.sh` tears it down. The lab holds no state, so that is also the
reset.

## B. Without Docker

```bash
pip install pyyaml
python3 collectors/collect.py --from-raw collectors/fixtures/lab_capture.json
python3 enumerator/pathfinder.py
```

`lab_capture.json` is a recorded capture of the real lab: the same probe output,
replayed through the same rules. Nothing is faked downstream of it.

The enumerator alone needs **no dependencies at all** — it reads whatever
`environment_graph/facts.json` holds, and the repository ships a hand-written
fallback there so `python3 enumerator/pathfinder.py` works on a fresh clone.

```bash
python3 tests/test_pipeline.py     # 15 checks over the whole pipeline
```

---

## Presenting this?

[`demo.md`](demo.md) is the runbook: the testing pass to run beforehand, the
demo beat by beat with what to say, the prepared answers to the questions you
will be asked, and a troubleshooting table.

## What you'll see

| Piece | File | What it shows |
|---|---|---|
| The lab | `lab/` | `web01` (entry) → `app01` → `db01` (crown jewel), two isolated networks |
| The facts | `environment_graph/facts.json` | **generated** by the collector from the live lab |
| What was declined | `environment_graph/collection_report.json` | conditions examined and deliberately not reported |
| The paths | `eval/analysis.json` | 3 escalation paths, each edge tagged with its ATT&CK technique |
| The fixes | `GET /api/remediation` | greedy weighted set-cover ranking + efficacy curve |
| The dashboard | `dashboard/` | network graph, paths, remediation panel |

**Headline result:** the reused deploy key is on **3 of 3** paths, and fixing it
alone covers every path at cost 1 — cheaper than patching DirtyPipe (cost 5),
which also covers 3 of 3. The sudo misconfiguration only covers 2 of 3. That is
"fewest fixes, most paths", computed rather than asserted.

---

## The two numbers, and why they differ

```
Config coverage   3/3 = 1.00   the configuration each technique needs is present
Precision         0/3 = 0.00   paths confirmed by EXECUTING them
```

Precision is **0 because no verifier has been built yet**, and that is the
correct thing to display. Every vector carries `verified_exploitable: null`;
`/api/verify` returns `not_implemented`; the dashboard shows every path
`Unverified`. Nothing on screen claims an execution that did not happen.

Raising precision above zero is Semester-1 milestone S1-M4 (`verifier/`).

## What is real, and what is declared

Almost everything is measured on the live containers: file modes, key
fingerprints, `sudo -l` output, listening ports, and reachability (opened as
**actual TCP connections**, which is how ASCEND discovers that `web01` cannot
reach `db01`).

Two things are declared, and say so on every item that uses them:

- **Roles and asset values** — business inputs. No scan produces them.
- **Per-host kernel versions** — containers share the host kernel, so the lab
  declares them in `/etc/ascend/declared_kernel`. Every vector derived from one
  carries `features.provenance: "declared"`, and the collector prints it with a
  `!`. See `lab/README.md`.

## The honesty line for the review

> "The network is small, but nothing downstream of it is simulated. The
> collector finds the reused key by fingerprinting it and matching every
> `authorized_keys` on every host; it finds the network segmentation by opening
> real TCP connections; and it *declines* to flag app01's patched 5.10 kernel
> that a naive version check would call vulnerable. The enumeration is a
> depth-first search over the attacker's `(host, privilege)` state space, and
> the remediation ranking is greedy weighted set-cover where each fix's effect
> is measured by re-running the enumerator on the patched graph. Precision is
> zero because we have not built the execution verifier yet — that is the next
> milestone, and we would rather show you a zero than a placeholder."

---

## How the enumerator works (30 seconds)

The attacker's state is the set of `(host, privilege)` pairs they control,
starting at `web01:low`. Three kinds of move grow it:

1. **Harvest** a credential from a readable file — `T1552.001`
2. **Move** laterally with a reused credential over SSH — `T1021.004 + T1550`
3. **Escalate** locally (sudo / SUID / kernel) — `T1548.003`, `T1548.001`, `T1068`

A depth-first search records every sequence ending at `db01:root`. The
chokepoint engine then removes each candidate fix from a copy of the facts,
**re-runs the enumerator**, and compares the survivors — so the panel's
predicted effect and the live "apply the fix" effect are produced by the same
operation and cannot disagree.

---

## Layout

```
scope.yaml                     techniques, detection rules, inventory, fix templates
lab/                           Docker Compose lab with the planted vectors
collectors/                    probes -> derivation rules -> facts.json
knowledge_graph/pack.json      ATT&CK / CWE / CAPEC / CVE, restricted to our 7 techniques
environment_graph/facts.json   GENERATED by the collector (hand-written fallback shipped)
environment_graph/facts.sample.json   pristine hand-written reference
enumerator/pathfinder.py        DFS path enumeration (stdlib only)
chokepoint/engine.py           greedy weighted set-cover remediation
service/main.py                FastAPI
dashboard/                     React + Vite
tests/test_pipeline.py         end-to-end regression suite
```

## Changing the lab

Edit `lab/seed/*.sh` and `scope.yaml`, then `bash lab/up.sh && python3
collectors/collect.py`. To change only the *rules*, edit `scope.yaml` and replay
a capture with `--from-raw` — no rebuild needed.

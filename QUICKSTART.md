# ASCEND — Thin Slice Quickstart

A network, the privilege-escalation paths through it that ASCEND finds
**automatically**, and the chokepoint that breaks them.

Two ways to run it. The Docker path collects facts from a real lab; the offline
path replays a recorded capture and needs only Python 3 and a venv.

Everything except the path-finder needs packages, so create the venv first, from
the repo root. Don't `pip install` into the system Python — Arch and current
Ubuntu refuse (`externally-managed-environment`).

```bash
python3 -m venv .venv
.venv/bin/pip install -r service/requirements.txt -r verifier/requirements.txt
```

---

## A. With the lab (what the demo runs on)

Needs Docker Engine and Compose v2 — **install commands are in
[`lab/README.md`](lab/README.md#prerequisites--installing-docker)**.
No Docker? Skip to B.

```bash
bash lab/up.sh                            # 3 containers on two isolated networks
.venv/bin/python collectors/collect.py    # probe them -> environment_graph/facts.json
python3 enumerator/pathfinder.py          # paths + chokepoints
```

Then the dashboard, each in its own terminal:

```bash
.venv/bin/python service/main.py          # FastAPI on 127.0.0.1:8000
cd dashboard && npm install && npm run dev
```

The terminal that starts the API must be able to run `docker ps` without
`sudo`, or **Verify** returns 503 — see `demo.md` §3 and §7.

Then prove the paths are real by actually running them in the lab:

```bash
.venv/bin/python -m verifier check        # canary present on all three hosts?
```

Clicking **Verify** on the dashboard executes each step of each path in the
containers and reports what genuinely worked. See [`verifier/README.md`](verifier/README.md).

`bash lab/down.sh` tears it down. The lab holds no state, so that is also the
reset.

## B. Without Docker

```bash
.venv/bin/python collectors/collect.py --from-raw collectors/fixtures/lab_capture.json
python3 enumerator/pathfinder.py
```

`lab_capture.json` is a recorded capture of the real lab: the same probe output,
replayed through the same rules. Nothing is faked downstream of it.

The enumerator alone needs **no dependencies at all** — it reads whatever
`environment_graph/facts.json` holds, and the repository ships a hand-written
fallback there so `python3 enumerator/pathfinder.py` works on a fresh clone.

```bash
.venv/bin/python tests/test_pipeline.py   # 23 passed with the lab up
```

Without the lab, expect `19 passed, 1 failed, 3 skipped`: three tests need the
containers, and the API-contract test fails because `/api/verify` cannot run.

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
| The paths | `eval/analysis.json` | 6 escalation paths, each edge tagged with its ATT&CK technique |
| The fixes | `GET /api/remediation` | greedy weighted set-cover ranking + efficacy curve; the panel shows paths eliminated and how many of them were execution-verified |
| The dashboard | `dashboard/` | network graph, paths, remediation panel |

**Headline result:** the exposed deploy key is on **6 of 6** paths, so removing
it alone breaks every route. Patching DirtyPipe breaks only 3 of 6, because
`db01` has a second way to root; the sudo misconfiguration breaks 4 of 6. That
is "fewest fixes, most paths", computed rather than asserted.

Fix *effort* is not modelled yet. `scope.yaml` holds a hand-written cost per fix
(1 = minutes, 5 = change control), which the ranking uses, but the dashboard
shows *Effort: not modelled (WIP)* instead of presenting that estimate as data.

---

## The two numbers, and why they differ

```
Config coverage   6/6 = 1.00   the configuration each technique needs is present
Precision         3/6 = 0.50   routes confirmed end-to-end by EXECUTING them
```

The verifier exists and runs, so precision is a measured number rather than a
placeholder. (`GET /api/status` also has a `precision` field reading 100% — that
one is **config coverage**, kept under its old name. Quote the Verify result.)

**19 of the 22 individual steps across the six routes execute and succeed for
real**: reading the exposed key, both SSH hops with it, the `sudo tar` escape,
and the setuid `find` escape that reaches root on the crown jewel.

Three routes are proven end to end. The other three each finish with the
DirtyPipe kernel exploit, which cannot run in a container lab because containers
share the host machine's kernel. A route is only `verified` if *every* step
verified, so those come back **partial**: not proven, and not disproven either.
Reporting them as failed would claim the attack does not work, which is a
different and false statement. Verifying them needs a genuinely vulnerable
kernel — the three-VM fallback in docs/02 §6.

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
> is measured by re-running the enumerator on the patched graph. Then we run the
> routes: three of six are proven end to end by execution, and the other three
> stop at a kernel exploit a container cannot run — so we report them as
> partial, not as proven."

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
enumerator/pathfinder.py       DFS path enumeration (stdlib only)
verifier/                      runs each step in the lab to prove the paths
chokepoint/engine.py           greedy weighted set-cover remediation
service/main.py                FastAPI
dashboard/                     React + Vite
tests/test_pipeline.py         end-to-end regression suite
```

## Changing the lab

Edit `lab/seed/*.sh` and `scope.yaml`, then `bash lab/up.sh &&
.venv/bin/python collectors/collect.py`. To change only the *rules*, edit `scope.yaml` and replay
a capture with `--from-raw` — no rebuild needed.

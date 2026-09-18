# `verifier/` — proving the attack paths are real

```
environment_graph/facts.json ──► pathfinder ──► 3 attack paths
                                                     │
                                    "are these real?" │
                                                     ▼
                                   verifier ──► actually runs each step
                                                     │
                                                     ├─► outcomes.jsonl  (labels for the scorer)
                                                     └─► /api/verify     (badges on the dashboard)
```

```bash
python -m verifier check     # is the lab healthy?
python -m verifier batch     # build the labelled dataset
python -m verifier verify    # verify one path (JSON on stdin)
```

Needs `pip install -r verifier/requirements.txt` and a running lab (`bash lab/up.sh`).

---

## Why this module exists

Everything before this point in ASCEND is *reasoning*. The collector reads
configuration, and the path-finder works out what an attacker could do with it.
Neither has tried anything. So a path is, at that stage, an educated guess.

The verifier's job is to stop guessing. It goes into the lab, **actually runs
each step of each path**, and reports what really happened. That turns
"we think this attack works" into "we ran it, here is the output".

This is the whole credibility argument of the project. Without it, ASCEND is a
tool that produces confident claims nobody has checked.

## How it decides whether a step worked — the canary

The hard part isn't running the attack. It's knowing whether it *worked*.

You can't trust a command's exit code. Lots of programs exit 0 while achieving
nothing, and an attack can half-succeed in ways an exit code won't show.

So the lab plants a **canary**: a file at `/root/.ascend_canary` containing a
random secret, readable by root and nobody else. Each build generates a fresh
secret.

Every escalation technique ends the same way — by trying to read that file:

> **If the secret comes back in the output, you were root. If it doesn't, you weren't.**

That's the entire test. One rule, applied identically to every technique, so
results are comparable. A technique can't "pass" by returning a friendly exit
code, because nothing but real root access produces that secret.

Lateral movement uses the same idea, adjusted: success means an SSH session
actually opened on the target host as the expected user.

## The three outcomes — the important part

Most verifiers have two outcomes: it worked, or it didn't. This one has three.

| Outcome | Means | Counts as a label? |
|---|---|---|
| `escalated` | ran, and privilege genuinely increased | yes — a positive |
| `not_escalated` | ran, and it did not work | yes — a negative |
| `not_executable` | **never ran**, because this lab cannot meet a precondition | **no** |

The third one matters more than it looks. Consider the DirtyPipe step on `db01`.
The environment graph says db01 runs kernel 5.16.0, which is vulnerable. But
containers all share the *host machine's* kernel — db01 doesn't really run
5.16.0, that number is planted so the graph has something to reason about
(tagged `provenance: declared`).

So the kernel exploit cannot possibly work there. The question is what to
report:

- Report it as **failed**, and you're telling everyone the attack doesn't work —
  which is a claim about the world, and it's false. It failed because of *our
  lab*, not because of the technique.
- Report it as **passed**, and you're lying outright.
- Report it as **not executable, and say why** — which is what this module does.

A path containing a not-executable step is reported as **partial**: not proven,
and equally not disproven. That distinction keeps the lab's own limits from
masquerading as findings.

> **Why this is a sore point.** An earlier version of the lab shipped a
> "DirtyPipe exploit" that was a setuid-root program calling `setuid(0)`. It had
> no DirtyPipe logic in it at all. It returned root because of its file
> permissions, on any kernel, and the verifier dutifully recorded
> `T1068 verified`. Removing the setuid bit made it fail on an unchanged kernel
> — proof that the "verification" was measuring a file mode. Both files were
> deleted, and `anchor_cve` now checks the running kernel **before** it will run
> anything. See `lab/exploits/README.md`.

## What it does today

Run against the current lab, this is the real output:

| Path | Result | Steps |
|---|---|---|
| path-01 | partial | 3 of 4 verified |
| path-02 | partial | 2 of 3 verified |
| path-03 | partial | 3 of 4 verified |

**8 of 11 steps genuinely executed and confirmed.** The 3 that didn't are all
the same DirtyPipe step, each carrying its reason.

What actually gets executed, for real, every time:

- reading the exposed private key on `web01` as `www-data`
- SSH `web01 → app01` with that key, landing as `appuser`
- SSH `app01 → db01` with the same key, landing as `dbuser`
- the `sudo tar` shell escape on `app01`, landing as `uid=0`

## How it fits the rest of ASCEND

```
collectors/  ──► facts.json ──► pathfinder ──► chokepoint ──► service ──► dashboard
                                    │                            ▲
                                    └──────► verifier ───────────┘
                                                │
                                                └──► outcomes.jsonl ──► scorer (not built)
```

| Module | Relationship |
|---|---|
| `collectors/` | tells the verifier *where things are* — the key's path on each host comes from the collector's own evidence, not from a path written into the service |
| `pathfinder` | produces the paths the verifier tries to walk |
| `service/` | `/api/verify` calls this module in-process against the live lab |
| dashboard | shows per-step verified / failed badges and the evidence |
| `chokepoint/` | today ranks fixes by enumerated paths; once enough paths verify, it should rank by *verified* paths |
| `scorer/` | not built. `outcomes.jsonl` is its training data — this module exists to produce it |

**Two output streams, kept apart on purpose:**

- `outcomes.jsonl` — the labelled dataset, from `verifier batch` with a fixed
  seed, meant to be reproducible.
- `verifier/runs/live.jsonl` — the audit trail of dashboard Verify clicks,
  gitignored.

Clicking Verify twenty times during a rehearsal must not reweight the training
set toward whatever got demonstrated most.

## Layout

| File | Job |
|---|---|
| `cli.py` | `batch`, `verify`, `check` commands |
| `runner.py` | the reset → run → decide → record loop |
| `signal.py` | **the single pass/fail decision** (the canary check) |
| `scope.py` | loads and validates the `verifier:` section of `scope.yaml` |
| `lab.py` | everything that touches Docker — nothing else imports `docker` |
| `outcomes.py` | the outcome record and its JSONL files |
| `telemetry.py` | **a stub** — the interface for Falco, with no Falco behind it |
| `adapters/` | one per technique family |

### Adapters

| Adapter | Techniques | How it triggers |
|---|---|---|
| `config_abuse` | T1548.003, T1552.001 | `sudo tar --checkpoint-action=exec`, and reading the key file |
| `lateral_ssh` | T1021.004 + T1550 | copies the key somewhere private, `chmod 600`, SSHes |
| `anchor_cve` | T1068 | runs a pre-placed exploit binary — brings none of its own |

An adapter's only freedom is *how it triggers* the technique. It never decides
its own result; `signal.py` does. That's what keeps results comparable.

> **A detail worth knowing.** OpenSSH refuses to use a private key that is
> world-readable — which is exactly what makes that key a finding. A verifier
> that naively ran `ssh -i /var/www/.ssh/id_rsa` would get "bad permissions",
> record a failure, and report a real vulnerability as not exploitable. The
> adapter copies the key somewhere private first, because that's what an
> attacker does.

## Safety

It executes real attack techniques, so:

- It only runs what's listed in `scope.yaml`. Anything else is refused.
- `hosts` in each entry is an allow-list of hosts it may start from.
- Per-edge overrides can fill in **parameters only** — never the adapter, the
  check, or the host list. An override can't widen what it's permitted to do.
- For escalation techniques it refuses to start as root, because "escalated to
  root" is meaningless if you began there. (Lateral movement is exempt: an
  attacker who already has root on the source host is a normal starting state.)
- It ships **no exploit code**, and `tests/test_pipeline.py` fails if any
  appears in `lab/exploits/` or is installed setuid.

## Not built yet

Honest list. None of these is faked in the meantime.

- **`telemetry.py` is a stub.** The spec wants Falco/eBPF capture so the same
  run that produces a label also produces syscall evidence. The interface is
  there; nothing is behind it. Evidence says `not captured` rather than printing
  a plausible-looking audit line.
- **No credential staging between hops.** A hop is verifiable only if the key is
  already on the source host. In the lab it always is. An attacker would carry
  it forward; the verifier can't yet, and says so instead of guessing.
- **No real CVE exploit, and nowhere to run one.** Needs both a genuine exploit
  binary and a genuinely vulnerable kernel — which containers cannot provide.
  The three-VM fallback in `docs/02` §6 is the route.
- **Reset is off during live verification.** `batch` resets before every run;
  the Verify button doesn't, because a container recreate per step would break
  demo pacing. Fine for read-only-ish techniques, wrong in general.
- **Scenario matrix is partly stubbed.** `full_chain` and `local_objective`
  exist; `early_stop`, `failed_escalation`, `benign_lookalike` and `background`
  need extra lab planting. The benign look-alike matters most — it's the
  false-positive answer in `docs/05` §2.
- **Dashboard has no "partial" badge.** The API returns `status: "partial"` and
  per-step reasons; the UI currently shows steps individually and the path as
  unverified. A third badge would tell the story better.

# Dashboard Wiring Log — `dhyani` branch

> **Scope of this document:** records every change made in the `dhyani` branch to connect the real
> pipeline modules to the FastAPI service and dashboard. Does not change or replace any existing
> `docs/0X_*.md` files — those reflect the full project plan. This file is branch-specific.

---

## What was done (in commit order)

### 1. Scaffold restore (`f29c66c`)
- Recovered Vite/React dashboard scaffold and FastAPI service from a GitHub Desktop stash.
- Resolved `dashboard/index.html` conflict in favour of the Vite entry point (not the plain-HTML
  `main`-branch placeholder).
- All `service/fixtures/*.json` and `service/main.py` restored to working state.

---

### 2. Wire `/api/network` → `environment_graph/facts.json` (`0b5f3c8`)

**Before:** endpoint read `service/fixtures/network.json` (hand-written, 4 hosts including
a dummy `admin01` that doesn't exist in the real lab).

**After:** endpoint calls `_load_facts()` + `_build_network_from_facts()` in `service/main.py`,
which reads `environment_graph/facts.json` directly.

**Field remap performed (facts.json → Host contract):**

| `facts.json` field | API contract field | Change |
|---|---|---|
| `hostname` | `hostname` | exact match |
| `role` | `role` | exact match |
| `os` | `os` | exact match |
| `kernel` | `kernel_version` | renamed |
| `asset_value` | `asset_value` | exact match |
| `entry.host == hostname` | `is_entry_point` | derived |
| `crown_jewel.host == hostname` | `is_crown_jewel` | derived |
| `accounts[]` (flat list) | `accounts[]` per host | grouped + `privilege` str → `privilege_level` int |
| `vectors[]` (flat list) | `vectors[]` per host | grouped |
| `reachability[].from` | `from_host` | renamed |
| `reachability[].to` | `to_host` | renamed |

**Dashboard — Network page now shows:**
- 3 nodes: `web01` (cyan/entry), `app01` (purple), `db01` (red/crown jewel)
- 2 directed edges: `web01 → app01 → db01` via ssh:22
- Host Inventory table: real asset values (web01=10, app01=30, db01=100), real vectors per host

**Also in this commit:** added `"database"` as an alias for `"db"` in `NetworkGraph.tsx`'s
`ROLE_COLORS` map — `facts.json` uses `"database"` as the role string for `db01`, but the
original colour map only had `"db"`. Without this, `db01` rendered grey instead of red.

---

### 3. Wire `/api/enumerate` → `enumerator/enumerate_paths()` (`0b5f3c8`)

**Before:** endpoint read `service/fixtures/paths.json` (hand-written fixture with 2 paths,
one of which was a fictional "Firewall Blocked" scenario).

**After:** endpoint imports `enumerate_paths` and `path_precision` from
`enumerator/enumerate.py` via `sys.path` injection and calls them in-process — no subprocess,
no file I/O, pure Python function call against the live `facts.json`.

**Translation layer (`_build_paths_from_enumerator`):**

The enumerator returns flat step dicts with `from`/`to` as `"host:priv"` strings. The frontend
expects rich `AttackPath`/`PathStep` objects. The translation:

- Parses `"web01:low"` → `source_host="web01"`, `source_account` looked up from `facts["accounts"]`
- Collapses cred-harvest steps (`to: "cred:X"`) into the adjacent lateral-move step's `credential`
  field — avoids exposing a `cred:` pseudo-node the frontend type system has no shape for
- Looks up `cve`, `cvss`, `features`, `verified_exploitable` from `facts["vectors"]` by `vector_id`
- Derives `risk_score = max(cvss)` across the path
- Derives `path_id = "path-{N:02d}"`, `name` from technique sequence
- Sets `overall_verified = null` (verifier doesn't exist yet)
- Flattens `discoverable_at` dict → human-readable string (`"web01 (low privilege)"`)

**Dashboard — Attack Paths page now shows:**

3 live-enumerated paths, all `web01 → db01`, risk score 7.8. Path 1 expanded:

| Step | From | To | Technique | CVSS |
|---|---|---|---|---|
| 1 | web01 (www-data) | app01 (appuser) | T1021.004+T1550 SSH reused cred | — |
| 2 | app01 (appuser) | app01 (root) | T1548.003 sudo misconfig | 7.8 |
| 3 | app01 (root) | db01 (dbuser) | T1021.004+T1550 SSH reused cred | — |
| 4 | db01 (dbuser) | db01 (root) | T1068 DirtyPipe CVE-2022-0847 | 7.8 |

Matches the canonical `web01 → app01 → db01` path described in the project slides and docs.

---

### 4. Wire `/api/status` — derive live metrics (`wire(status)` commit)

**Before:** all metrics read from `service/fixtures/status.json` (stale: 4 hosts, 2 paths,
50% precision — contradicted the real network and enumerate endpoints).

**After:** four fields derived live in the handler:

| Field | Source | Was |
|---|---|---|
| `hosts_count` | `len(facts["hosts"])` | 4 (wrong) → **3** |
| `vectors_count` | `len(facts["vectors"])` | 4 (wrong) → **3** |
| `enumerated_paths` | `len(_enumerate_paths(facts))` | 2 (wrong) → **3** |
| `precision` | `path_precision(facts, paths)` | "50.0%" (wrong) → **"100.0%"** |

Two fields remain fixture-sourced with explicit `TODO` comments in code:

| Field | Value | Why still a placeholder |
|---|---|---|
| `verified_paths` | 1 | Matches `verify.json` fixture (1 path `overall_verified:true`). No real verifier exists. |
| `chokepoints_identified` | 1 | No `chokepoint/` module exists yet. |

---

### 5. Honesty fixes (`7386374`)

**`service/fixtures/status.json`:**
- Added `_fixture_note` explaining which fields are live-derived vs placeholder
- Added `_verified_paths_note` on the `verified_paths` field
- Stale numbers (4 hosts, 4 vectors etc.) updated to match reality for the placeholder fields

**`dashboard/src/components/Sidebar.tsx`:**
- Renamed sidebar label `"Precision"` → `"Config Coverage"`
- Added `tooltip` prop to `MetricRow` component (native HTML `title` attribute, no new deps)
- Tooltip text on Config Coverage: *"Fraction of enumerated paths using vectors marked
  exploitable in config — not execution-verified."*
- `verified_paths` set to `1` to match `verify.json` fixture (eliminates sidebar vs badge
  contradiction)

---

## Current endpoint status

| Endpoint | Data source | Status |
|---|---|---|
| `GET /api/network` | `environment_graph/facts.json` (live) | ✅ **Real data** |
| `POST /api/enumerate` | `enumerator.enumerate_paths()` in-process | ✅ **Real data** |
| `GET /api/status` | Live (4 fields) + `status.json` (2 fields) | ✅ **Mostly live** |
| `POST /api/verify` | `service/fixtures/verify.json` | 🔒 **Mocked** — verifier not built |
| `GET /api/remediation` | `service/fixtures/remediation.json` | 🔒 **Mocked** — chokepoint engine not built |
| `POST /api/remediation/apply` | `service/fixtures/remediation.json` | 🔒 **Mocked** |
| `GET /api/status` (verified_paths) | `service/fixtures/status.json` | 🔒 **Placeholder** |

---

## What the dashboard shows right now

### Sidebar metrics
| Label | Value | Source |
|---|---|---|
| Hosts | 3 | live — `facts.json` |
| Vectors | 3 | live — `facts.json` |
| Paths | 3 | live — enumerator |
| Verified | 1 | fixture — `verify.json` |
| Config Coverage | 100.0% | live — enumerator precision |

### Network page
- 3 real nodes (web01, app01, db01) with correct colours and entry/crown flags
- 2 real edges (web01→app01, app01→db01 ssh:22)
- Host inventory table with real asset values and per-host vectors

### Attack Paths page
- 3 live-enumerated paths from DFS over `facts.json`
- Path 1: T1552.001 → T1021.004+T1550 → T1548.003 → T1021.004+T1550 → T1068 (DirtyPipe)
- Verified badge on path-01 (from `verify.json` fixture mock execution evidence)
- Grey "Unverified" badge on path-03 (verify.json only covers 2 paths)

### Remediation page
- Still reads `remediation.json` fixture — shows 3 ranked fixes with efficacy curve
- **Not real chokepoint output** — the real chokepoint engine doesn't exist yet

---

## What is NOT built yet (next steps)

- `verifier/` — execution verifier (Atomic Red Team wrappers). When built, wires to
  `POST /api/verify` and replaces `verify.json`.
- `chokepoint/` — real remediation engine using verified path outcomes. When built, wires to
  `GET /api/remediation`.
- `collectors/` — host fact collectors from live Docker lab. When built, `facts.json` is
  generated rather than hand-written.
- `scorer/` — ML exploitability model. When built, wires to `GET /api/status` precision fields.
- The `rank_chokepoints()` function inside `enumerator/enumerate.py` is a graph-structural
  placeholder (counts which vector appears on the most paths) — **it is not the real chokepoint
  engine**, which needs verified execution outcomes for weighted set-cover.

---

# Part 2 — Lab, collectors and the chokepoint engine

> Appended after the original wiring work. Closes three of the five gaps listed
> under "What is NOT built yet" above: `collectors/`, `chokepoint/`, and a
> restricted `knowledge_graph/`. `verifier/` and `scorer/` remain unbuilt, and
> the API now says so rather than covering for them.

## 6. `scope.yaml` — single source of truth

Doc 05 §6 asks for it; nothing had one. It now holds the seven techniques and
the evidence each requires, the detection rules, the lab inventory (roles, asset
values, entry, crown jewel) and a remediation template per technique.

Read by `collectors/derive.py` and `chokepoint/engine.py`. **Not** read by
`enumerator/enumerate.py`, which stays standard-library-only so the offline
quickstart keeps working on a bare clone.

## 7. `lab/` — the Docker lab

Three `debian:bookworm-slim` containers running sshd, on **two** `internal: true`
bridge networks with `app01` dual-homed. No published ports, no internet route.

The two-network layout is the point: `web01` genuinely cannot reach `db01`, and
the reachability probe *discovers* that by failing to connect, rather than the
topology being declared in a file.

| Host | Planted | Technique |
|---|---|---|
| `web01` | `/var/www/.ssh/id_rsa` at mode 0644 | T1552.001 |
| `app01` | `appuser ALL=(root) NOPASSWD: /bin/tar` | T1548.003 |
| `app01` + `db01` | the same deploy key in both `authorized_keys` | T1550 |
| `db01` | declared kernel 5.16.0 | T1068 |

### The container-kernel problem, and how it is handled

Containers share the host kernel, so `uname -r` is identical in all three and
cannot support the per-host kernel divergence the T1068 vector needs. Rather
than quietly writing a fake version into the facts, each image carries
`/etc/ascend/declared_kernel` and `probes/kernel.py` reports **both** values.
Every vector derived from a declared fact carries
`features.provenance: "declared"`, the collector prints it with a `!`, and the
evidence block states why. The VM fallback in docs/02 §6 turns the same fact
`observed` with no code change.

`app01` declares **5.10.150** — a *patched* 5.10 branch. It is there to prove the
rule is branch-aware: DirtyPipe was fixed in 5.10.102, so app01 is not flagged,
even though 5.10.150 is below the headline 5.16.11. A single-threshold check
would have produced a false positive.

## 8. `collectors/` — facts.json is now generated

Nine probes observe; `derive.py` judges; `scope.yaml` decides. Probes are handed
a `Transport` (`docker exec` today, SSH-to-VM later) and never shell out
directly.

Two pieces worth calling out at a review:

- **Credential reuse is detected cryptographically.** `sshkeys.py` parses the
  `openssh-key-v1` container in pure Python and computes the same
  `SHA256:...` fingerprint `ssh-keygen -lf` prints (asserted against the real
  binary in the test suite). The private key found on `web01` is matched against
  every `authorized_keys` entry on every host. The "reused key" claim is a
  fingerprint match, not a filename or comment guess — and the target hosts need
  no OpenSSH client installed.
- **Reachability is measured.** For every ordered host pair and every listening
  port, a probe opens a real TCP connection *from inside the source container*,
  by DNS name and by every address the target holds, and records the failure
  reason when it fails.

### Conditions deliberately declined

`environment_graph/collection_report.json` records what was examined and *not*
reported — the evidence that the rules discriminate:

| Host | Technique | Declined because |
|---|---|---|
| `app01` | T1552.001 | the same key at mode 0600 — readable only by its owner |
| `app01` | T1548.003 | `NOPASSWD: /bin/ls` — no documented shell escape |
| `app01` | T1068 | kernel 5.10.150 is at or above the 5.10 branch fix |
| `web01` | T1068 | kernel 5.4.0 is below the affected range |

### Acceptance criterion

Facts derived from a lab capture produce **the same 3 paths and the same
chokepoint ranking** as the hand-written reference file. Asserted by
`tests/test_pipeline.py::test_collected_facts_reproduce_the_reference_paths`.

### Offline path

`collectors/fixtures/lab_capture.json` is a recorded capture of the reference
lab. `collect.py --from-raw <capture>` replays it through the current rules with
no Docker present — useful for rule work, and it is what the test suite runs on.

## 9. `chokepoint/` — real remediation

Replaces `service/fixtures/remediation.json`, which referenced a vector id
(`vec-web-01`) that does not exist in `facts.json` and claimed 1 total path
while the enumerator found 3.

`build_remediation()` establishes each fix's effect by **removing it from a copy
of the facts and re-running the real enumerator**, then diffing the survivors
against the baseline — the same operation `/api/remediation/apply` performs, so
the predicted and the demonstrated effect cannot drift apart. Selection is
greedy weighted set-cover (the standard ln n + 1 approximation).

Candidate fixes are of two kinds, because they are genuinely different
remediations: removing a **vector**, and revoking a reused **credential**
everywhere it is accepted without touching the file it leaked from.

Result on the reference lab:

| rank | fix | cost | kills | |
|---|---|---|---|---|
| 1 | remove the exposed key on `web01` | 1 | 3/3 | recommended |
| 2 | revoke `app_deploy_key` across the estate | 2 | 3/3 | |
| 3 | patch CVE-2022-0847 on `db01` | 5 | 3/3 | |
| 4 | remove the NOPASSWD sudo rule on `app01` | 2 | 2/3 | |

Minimum cover: `{fix-01}`, size 1, cost 1, covers all paths.

## 10. Endpoint changes

| Endpoint | Before | After |
|---|---|---|
| `GET /api/network` | facts.json | facts.json **+ applied fixes** |
| `POST /api/enumerate` | enumerator on pristine facts | enumerator on the **patched** facts |
| `GET /api/remediation` | `remediation.json` fixture | `chokepoint.engine` |
| `POST /api/remediation/apply` | filtered a hard-coded list | **re-enumerates** the patched graph |
| `GET /api/status` | 4 live + 2 fixture fields | all live; `verified_paths` an honest 0 |
| `POST /api/verify` | replayed `verify.json` | `not_implemented`, empty results |

Only the applied fix ids are held in server state. Which paths survive is
re-derived per request; caching a path list is how a demo ends up showing
numbers that no longer follow from the graph.

### Two bugs found and fixed while wiring this

1. **Path ids were renumbered after a fix.** `_build_paths_from_enumerator`
   assigned `path-{N:02d}` positionally, so applying a fix produced a response
   that reported `path-01` eliminated *and* displayed a surviving path called
   `path-01`. Ids are now pinned to the baseline enumeration via a path
   signature. The human-readable `name` had the same bug and the same fix.
2. **`verified_exploitable` was `true` on every vector** in the hand-written
   facts, so "precision" read 1.00 and meant nothing. Vectors now carry
   `verified_exploitable: null` plus `config_exploitable`, and
   `path_precision()` returns *config coverage* and *execution precision*
   separately. The sidebar's "Config Coverage" label is now backed by the number
   it names.

## 11. Honesty changes

- Nothing in the repository claims execution verification. Asserted by
  `tests/test_pipeline.py::test_nothing_claims_execution_verification`.
- `/api/verify` returns `not_implemented` with empty results rather than
  replaying the fixture. Serving it would have put "Verified" badges on paths
  that were never executed while `/api/status` reported `verified_paths: 0` —
  one of the two would have had to be wrong. The fixture stays on disk as the
  shape the verifier will return.
- `verified_paths` is `0` by construction, not borrowed from a fixture.
- `environment_graph/facts.sample.json` keeps the hand-written reference; the
  shipped `facts.json` is the fallback for a clone with no Docker, labelled as
  illustrative in its own `_comment`.

## 12. Tests

`tests/test_pipeline.py` — 15 checks, runnable as a plain script or under
pytest, covering fingerprinting against the real `ssh-keygen`, the derivation
rules (including every declined condition), branch-aware kernel matching,
segmentation, the enumerator, the chokepoint engine, the apply/reset loop, and
the FastAPI JSON contract.

The last of those matters because `npm`/`corepack` is broken on the current dev
machine, so `tsc -b` could not be run: `test_responses_match_the_typescript_interfaces`
enforces every interface in `dashboard/src/types/index.ts` at the JSON boundary
instead, so an API change that would break the frontend build fails here first.

## 13. Still not built

- `verifier/` — execution verifier. Until it exists, precision is 0 everywhere.
- `scorer/` — ML exploitability model (Semester-1 M5).
- A root `docker-compose.yml` running the service and dashboard together.
- `demo.md` — the scripted walk-through from doc 05 §2.

---

# Part 3 — first live run of the lab

Docker installed; `bash lab/up.sh` → `python3 collectors/collect.py` run against
real containers for the first time. Three things changed as a result.

## 14. Docker's embedded DNS resolver was polluting the graph

Every host reported a second listening socket on a random high port bound to
`127.0.0.11` — Docker's embedded DNS resolver. It was becoming a reachability
target, so the sweep spent 6 extra attempts per run waiting for timeouts against
a socket that is unreachable by construction.

`probes/ports.py` now flags any listener bound to `127.0.0.0/8` or `::1`, and
`probes/reachability.py` skips them. Wildcard binds (`0.0.0.0`, `::`) are kept.
Reachability attempts: **12 → 6**, and the host inventory no longer carries a
phantom service.

## 15. The negative controls existed only in the fixture

The committed capture contained a 0600 copy of the deploy key and a harmless
`NOPASSWD: /bin/ls` rule; the actual lab did not. The first live run therefore
reported **2** declined conditions where the fixture produced 4 — the "our rules
discriminate" claim was only demonstrable offline.

Both are now planted in `lab/seed/app01.sh`, so a live run reproduces all four.
`collectors/fixtures/lab_capture.json` has been **regenerated from an actual
`--save-raw` run** rather than being hand-constructed, so the offline path now
replays a real recording.

## 16. Dockerfile layer ordering

`ARG ROLE` sat above the `apt-get install` layer, which put the arg value in the
cache key and ran apt once per role. Moving both ARGs below the install makes all
three images share one cached layer: 3 × 205MB images occupying **204.9MB** total,
and a full `down` → `up` cycle takes about 2 seconds.

## What the live run confirmed

| Claim | Evidence |
|---|---|
| key really is world-readable | `-rw-r--r-- www-data /var/www/.ssh/id_rsa` |
| sudo rule really is NOPASSWD | `sudo -l -U appuser` → `(root) NOPASSWD: /bin/tar` |
| it really is the same key on 3 hosts | `ssh-keygen -lf` gives one fingerprint for the private key on web01 and both `authorized_keys` |
| web01 really cannot reach db01 | `172.18.0.3:22` → *Network is unreachable* (a routing failure to db01's real address, not just a DNS miss) |
| app01 really is the pivot | from web01, `172.19.0.2` (dmz) open, `172.18.0.2` (core) unreachable |
| collection is deterministic | facts byte-identical across a full `down` → `up` → re-collect, timestamps aside |

Live-collected facts produce the same 3 paths and the same chokepoint ranking as
the hand-written reference. The full suite (15 checks) passes against the
regenerated real capture.

`/api/status` now reports `data_sources.facts: "docker:ascend-"` with a real
`collected_at`, so the dashboard can distinguish collected facts from the
hand-written fallback.

---

# Part 4 — enumerator cleanup

> References to `enumerator/enumerate.py` in Parts 1–3 above are left as
> written. They record what was true when those entries were made; the file is
> now `enumerator/pathfinder.py`.

## 17. `enumerate.py` renamed to `pathfinder.py`

The module was imported as `enumerate`, which is a Python builtin. Nothing broke
— all three importers use `from enumerate import ...`, which binds only the
named functions — but `import enumerate` anywhere in the process would have
shadowed the builtin, and `enumerator/` is injected onto `sys.path` by the
service, the chokepoint engine and the test suite alike. Renamed before the
module grows, and `pathfinder` says what it does.

Updated: the three import sites, the generated-file header in `dashboard/data.js`,
and every command in `QUICKSTART.md`, `demo.md`, `lab/README.md` and
`collectors/collect.py`'s closing hint.

## 18. Two small corrections in the same module

- `build_graph()` opened with a loop over `facts["hosts"]` whose body was
  `pass`, assigning to a `nodes` list that was then discarded. Removed.
- `chokepoint()`'s docstring described the real remediation engine as a
  "Semester 2" item. It exists now (`chokepoint/engine.py`, Part 9), so the
  docstring now says what the function actually is: a convenience counter that
  *infers* a fix's effect from the graph, kept so the module still gives a
  useful answer when run alone, as against the engine, which *measures* that
  effect by re-enumeration.

## 19. `enumerator/README.md` added

Documents the attacker state model — the search tracks the set of
`(host, privilege)` pairs and credentials held, which is why it is a state-space
search and not shortest-path — the three move types, why the search terminates,
the config-coverage/precision split, the input and output contract, and the
module's known limits (two-level privilege ladder, port-agnostic reachability,
all paths weighted equally until `scorer/` exists).

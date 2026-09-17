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

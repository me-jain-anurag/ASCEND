import datetime as _dt
import json
import sys
from pathlib import Path
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Make enumerator/ importable as a module without installing it.
_ENUMERATOR_DIR = str(Path(__file__).resolve().parent.parent / "enumerator")
if _ENUMERATOR_DIR not in sys.path:
    sys.path.insert(0, _ENUMERATOR_DIR)
from pathfinder import enumerate_paths as _enumerate_paths, path_precision as _path_precision

# Make chokepoint/ importable as a package from the repository root.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
from chokepoint.engine import (                      # noqa: E402
    build_remediation as _build_remediation,
    apply_fix_ids as _apply_fix_ids,
    eliminated_path_ids as _eliminated_path_ids,
    known_fix_ids as _known_fix_ids,
    baseline_path_ids as _baseline_path_ids,
    path_signature as _path_signature,
)

app = FastAPI(
    title="ASCEND Analysis Core API",
    version="1.0.0",
    description="Mock backend serving ER-schema-compliant fixtures for ASCEND Workstream C"
)

# Enable CORS for local Vite dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
FACTS_PATH   = Path(__file__).resolve().parent.parent / "environment_graph" / "facts.json"

def load_fixture(name: str) -> dict:
    file_path = FIXTURES_DIR / name
    if not file_path.exists():
        raise HTTPException(status_code=500, detail=f"Fixture file {name} not found")
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)

SCOPE_PATH = Path(__file__).resolve().parent.parent / "scope.yaml"


def _load_facts() -> dict:
    """Load environment_graph/facts.json — the PRISTINE lab topology.

    Pristine matters: fix ids are positional within the remediation ranking, so
    they are only meaningful against unmodified facts. Applied fixes are layered
    on top per request by _effective_facts(), never written back to the file.
    """
    if not FACTS_PATH.exists():
        raise HTTPException(status_code=500, detail="environment_graph/facts.json not found")
    with open(FACTS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _load_scope() -> dict:
    """Load scope.yaml (technique definitions + remediation templates)."""
    if not SCOPE_PATH.exists():
        raise HTTPException(status_code=500, detail="scope.yaml not found")
    try:
        import yaml
    except ImportError:
        raise HTTPException(status_code=500,
                            detail="PyYAML is required to read scope.yaml")
    with open(SCOPE_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _effective_facts(facts: dict, scope: dict) -> dict:
    """The facts as they stand after every fix the operator has applied.

    This is what makes the demo's closing beat a measurement rather than a
    claim: the paths that depended on a fixed vector are not filtered out of a
    response, they no longer exist in the graph being enumerated.
    """
    return _apply_fix_ids(facts, scope, state["applied_fixes"])

# Maps facts.json privilege strings to integer privilege_level values
# matching the frontend Account type contract.
_PRIV_LEVEL = {"low": 1, "medium": 2, "root": 3}

def _build_network_from_facts(facts: dict) -> dict:
    """
    Translates environment_graph/facts.json into the NetworkData contract
    (Host[] + ReachabilityEdge[]) that the frontend type system expects.

    Field remap summary:
      facts.hosts[].kernel         -> kernel_version   (rename)
      facts.entry.host == hostname -> is_entry_point   (derived)
      facts.crown_jewel.host == ?  -> is_crown_jewel   (derived)
      facts.accounts[] (flat)      -> hosts[].accounts (grouped by host;
                                       privilege str -> privilege_level int)
      facts.vectors[]  (flat)      -> hosts[].vectors  (grouped by host;
                                       features stubbed to {} if absent)
      facts.reachability[].from    -> from_host        (rename)
      facts.reachability[].to      -> to_host          (rename)
    """
    entry_host = facts["entry"]["host"]
    crown_host = facts["crown_jewel"]["host"]

    # Group accounts by host
    accounts_by_host: dict = {}
    for acct in facts.get("accounts", []):
        host = acct["host"]
        accounts_by_host.setdefault(host, []).append({
            "username": acct["username"],
            "type": acct["type"],
            "privilege_level": _PRIV_LEVEL.get(acct.get("privilege", "low"), 1),
        })

    # Group vectors by host
    vectors_by_host: dict = {}
    for vec in facts.get("vectors", []):
        host = vec["host"]
        vectors_by_host.setdefault(host, []).append({
            "vector_id": vec["vector_id"],
            "technique": vec["technique"],
            "technique_name": vec.get("technique_name"),
            "cve": vec.get("cve", None),
            "cvss": vec.get("cvss", 0.0),
            "features": vec.get("features", {}),
            "verified_exploitable": vec.get("verified_exploitable", None),
        })

    hosts = []
    for h in facts.get("hosts", []):
        hostname = h["hostname"]
        hosts.append({
            "hostname": hostname,
            "role": h["role"],
            "os": h["os"],
            "kernel_version": h.get("kernel", ""),
            "asset_value": h.get("asset_value", 0),
            "is_entry_point": hostname == entry_host,
            "is_crown_jewel": hostname == crown_host,
            "accounts": accounts_by_host.get(hostname, []),
            "vectors": vectors_by_host.get(hostname, []),
        })

    reachability = [
        {
            "from_host": r["from"],
            "to_host":   r["to"],
            "port":      r["port"],
            "service":   r["service"],
        }
        for r in facts.get("reachability", [])
    ]

    return {"hosts": hosts, "reachability": reachability}


def _build_paths_from_enumerator(facts: dict, id_map: dict | None = None) -> list:
    """
    Calls enumerator.enumerate_paths() in-process and translates its raw
    step-dict output into the AttackPath[] / PathStep[] contract the frontend
    type system expects.

    Translation decisions:
    - Credential-harvest steps (to: "cred:X") have no target host. They are
      collapsed into the immediately following lateral-move step by annotating
      that step's `credential` field. This avoids exposing a "cred" pseudo-node
      that the frontend type system has no shape for.
    - source_account / target_account are looked up from facts["accounts"] by
      (host, privilege). username defaults to the host's known service account.
    - risk_score = max(cvss) across all real vectors in the path.
    - overall_verified = null (verifier doesn't exist yet).
    - path_id comes from `id_map` (signature -> baseline id) when supplied, so
      a path keeps its id after a fix removes some of its siblings. Without a
      map it falls back to the positional "path-{N:02d}".
    """
    # Build fast lookup tables from facts
    vector_map = {v["vector_id"]: v for v in facts.get("vectors", [])}
    cred_map   = {c["cred_id"]: c for c in facts.get("credentials", [])}
    priv_to_int = {"low": 1, "medium": 2, "root": 3}

    def acct_for(host: str, priv: str) -> dict:
        """Find the account entry in facts for a given host + privilege level."""
        for a in facts.get("accounts", []):
            if a["host"] == host and a["privilege"] == priv:
                return {
                    "username": a["username"],
                    "type":     a["type"],
                    "privilege_level": priv_to_int.get(priv, 1),
                }
        # Fallback if not found
        return {"username": host, "type": "service", "privilege_level": priv_to_int.get(priv, 1)}

    def parse_node(label: str):
        """Split 'host:priv' label into (host, priv). Returns (None, None) for cred: labels."""
        if label.startswith("cred:"):
            return None, None
        parts = label.split(":", 1)
        return (parts[0], parts[1]) if len(parts) == 2 else (parts[0], "low")

    raw_paths = _enumerate_paths(facts)
    result = []
    id_map = id_map or {}

    for path_idx, raw_path in enumerate(raw_paths, 1):
        path_id = id_map.get(_path_signature(raw_path), f"path-{path_idx:02d}")
        # ── Collapse cred-harvest steps into their adjacent lateral step ─────
        # Pass 1: collect pending credentials keyed to the next host-to-host step
        pending_cred: dict | None = None
        host_steps = []   # steps that move between actual hosts

        for raw_step in raw_path:
            src_host, src_priv = parse_node(raw_step["from"])
            tgt_host, tgt_priv = parse_node(raw_step["to"])

            if tgt_host is None:
                # This is a cred-harvest step; stash it for the next move step
                cred_id = raw_step["to"].split(":", 1)[1]
                cred_data = cred_map.get(cred_id, {})
                _disc = cred_data.get("discoverable_at", "")
                if isinstance(_disc, dict):
                    _disc = f"{_disc.get('host', '')} ({_disc.get('privilege', '')} privilege)"
                pending_cred = {
                    "cred_id": cred_id,
                    "type":    cred_data.get("type", "credential"),
                    "discoverable_at": str(_disc),
                    # carry technique for step annotation
                    "_harvest_technique": raw_step["technique"],
                    "_harvest_technique_name": raw_step["technique_name"],
                    "_harvest_vector_id": raw_step.get("vector_id"),
                }
                continue

            # Resolve vector metadata from facts
            vid = raw_step.get("vector_id")
            vec_meta = vector_map.get(vid, {}) if vid else {}

            # If this step consumed a harvested cred, fold its technique in
            cred_for_step = None
            if pending_cred and raw_step.get("credential"):
                cred_for_step = {
                    "cred_id": pending_cred["cred_id"],
                    "type":    pending_cred["type"],
                    "discoverable_at": pending_cred["discoverable_at"],
                }
                pending_cred = None

            host_steps.append({
                "src_host": src_host, "src_priv": src_priv,
                "tgt_host": tgt_host, "tgt_priv": tgt_priv,
                "technique":      raw_step["technique"],
                "technique_name": raw_step["technique_name"],
                "vector_id":  vid,
                "vec_meta":   vec_meta,
                "credential": cred_for_step,
            })

        # ── Build PathStep list ───────────────────────────────────────────────
        steps = []
        cvss_values = []
        for step_idx, s in enumerate(host_steps, 1):
            vec = {
                "vector_id":          s["vector_id"],
                "technique":          s["technique"],
                "technique_name":     s.get("technique_name"),
                "cve":                s["vec_meta"].get("cve", None),
                "cvss":               s["vec_meta"].get("cvss", 0.0),
                "features":           s["vec_meta"].get("features", {}),
                "verified_exploitable": s["vec_meta"].get("verified_exploitable", None),
            }
            if vec["cvss"]:
                cvss_values.append(vec["cvss"])

            steps.append({
                "step_number":    step_idx,
                "source_host":    s["src_host"],
                "target_host":    s["tgt_host"],
                "source_account": acct_for(s["src_host"], s["src_priv"]),
                "target_account": acct_for(s["tgt_host"], s["tgt_priv"]),
                "vector":         vec,
                "credential":     s["credential"],
                "description":    (
                    f"{s['technique_name']}: {s['src_host']}:{s['src_priv']}"
                    f" → {s['tgt_host']}:{s['tgt_priv']}"
                ),
                "verified": None,
            })

        entry = facts["entry"]
        crown = facts["crown_jewel"]
        techniques = [st["vector"]["technique"] for st in steps]
        risk = round(max(cvss_values), 1) if cvss_values else 0.0

        result.append({
            "path_id":         path_id,
            # Numbered from the path's BASELINE id, not its position in this
            # response — otherwise the survivor of a fix is relabelled "Path 1"
            # while the panel reports Path 1 as eliminated.
            "name":            f"Path {path_id.split('-')[-1].lstrip('0') or '0'}: "
                               f"{' → '.join(dict.fromkeys(techniques))}",
            "length":          len(steps),
            "entry_host":      entry["host"],
            "crown_jewel_host": crown["host"],
            "overall_verified": None,
            "risk_score":      risk,
            "steps":           steps,
        })

    return result

# ── Runtime state ────────────────────────────────────────────────────────────
# Only the applied fix ids are stored. Everything else — which paths survive,
# how many were eliminated — is RE-DERIVED from the facts on each request by
# re-running the enumerator. Caching a path list here is how a demo ends up
# showing numbers that no longer follow from the graph.
state = {
    "active_scenario": "default",
    "applied_fixes": [],
}


class ApplyFixRequest(BaseModel):
    fix_id: str


class EnumerateRequest(BaseModel):
    scenario: Optional[str] = "default"


@app.get("/api/network")
def get_network():
    """Returns hosts and reachability edges.

    Data source: environment_graph/facts.json, generated by collectors/collect.py
    from the live Docker lab (or the hand-written fallback when no lab is up).
    Reflects any applied fixes, so remediating a vector removes it from the host
    inventory here too.
    """
    facts = _load_facts()
    scope = _load_scope()
    return _build_network_from_facts(_effective_facts(facts, scope))


@app.post("/api/enumerate")
def enumerate_paths_endpoint(payload: Optional[EnumerateRequest] = None):
    """Enumerates attack paths from entry point to crown jewel.

    Data source: enumerator.enumerate_paths() called in-process against the
    effective facts. When fixes have been applied the enumeration genuinely runs
    on the patched graph — eliminated paths are absent because they cannot be
    constructed, not because they were filtered from a list.

    The scenario parameter is accepted for API-contract compatibility and
    ignored; there is one real lab.
    """
    facts = _load_facts()
    scope = _load_scope()
    effective = _effective_facts(facts, scope)

    # Pin ids to the baseline so survivors keep their identity after a fix.
    paths = _build_paths_from_enumerator(effective, _baseline_path_ids(facts))
    raw_paths = _enumerate_paths(effective)
    precision = _path_precision(effective, raw_paths)
    eliminated = _eliminated_path_ids(facts, scope, state["applied_fixes"])

    return {
        "scenario":    "live",
        "name":        "Live Enumeration — environment_graph/facts.json",
        "entry_point": facts["entry"]["host"],
        "crown_jewel": facts["crown_jewel"]["host"],
        "total_paths": len(paths),
        "paths":       paths,
        "applied_fixes":        list(state["applied_fixes"]),
        "eliminated_path_ids":  eliminated,
        "config_coverage":      round(precision["config_coverage"], 4),
        "verification_status":  precision["verification_status"],
        "description": (
            f"Real-time DFS enumeration: {len(paths)} path(s) from "
            f"{facts['entry']['host']}:{facts['entry']['privilege']} to "
            f"{facts['crown_jewel']['host']}:{facts['crown_jewel']['privilege']}. "
            f"Config coverage {precision['config_covered']}/{precision['proposed']}. "
            f"Execution-verified {precision['verified']}/{precision['proposed']} "
            f"(no verifier built yet)."
            + (f" {len(state['applied_fixes'])} fix(es) applied; "
               f"{len(eliminated)} path(s) eliminated."
               if state["applied_fixes"] else "")
        ),
    }


@app.post("/api/verify")
def verify_paths():
    """Per-path and per-step execution-verification outcomes.

    THE VERIFIER DOES NOT EXIST YET, so this reports nothing verified rather
    than replaying service/fixtures/verify.json.

    The fixture is still on disk and still matches the VerifyData contract — it
    is what this endpoint will return in shape once verifier/ is built. But
    serving it would put "Verified" badges on paths that have never been
    executed, while /api/status correctly reports verified_paths: 0. One of the
    two would have to be wrong, and it is cheaper to show an empty truth than to
    explain a contradiction at a review.

    With results empty, the dashboard renders every path "Unverified", which is
    exactly the current state of knowledge.
    """
    # TODO(verifier/): return real execution outcomes. Milestone S1-M4.
    return {
        "execution_run_id": "none",
        "status":    "not_implemented",
        # VerifyData.timestamp is typed `string` in the frontend contract, so
        # this stays a string even though no run occurred.
        "timestamp": _dt.datetime.now(_dt.timezone.utc)
                        .replace(microsecond=0).isoformat(),
        "summary": {
            "paths_tested":   0,
            "paths_verified": 0,
            "paths_failed":   0,
            "precision":      0.0,
        },
        "results": {},
        "_mock": True,
        "_mock_note": (
            "No technique has been executed. The execution verifier is Semester-1 "
            "milestone S1-M4; until it exists every path is correctly Unverified. "
            "The response shape is fixed by service/fixtures/verify.json."
        ),
    }


@app.get("/api/remediation")
def get_remediation():
    """Ranked fixes and the fixes-versus-paths efficacy curve.

    Data source: chokepoint.engine.build_remediation() against the pristine
    facts. Each fix's paths_eliminated list is measured by removing that fix
    from a copy of the facts and re-running the enumerator — the same operation
    /api/remediation/apply performs, so the predicted and observed effects
    cannot drift apart.
    """
    facts = _load_facts()
    scope = _load_scope()
    plan = _build_remediation(facts, scope)
    plan["applied_fixes"] = list(state["applied_fixes"])
    return plan


@app.post("/api/remediation/apply")
def apply_remediation(req: ApplyFixRequest):
    """Applies a fix, then re-enumerates to report which paths it eliminated."""
    facts = _load_facts()
    scope = _load_scope()

    valid = _known_fix_ids(facts, scope)
    if req.fix_id not in valid:
        raise HTTPException(
            status_code=404,
            detail=f"Fix {req.fix_id} not found in the remediation plan. "
                   f"Known fixes: {', '.join(valid)}",
        )

    if req.fix_id not in state["applied_fixes"]:
        state["applied_fixes"].append(req.fix_id)

    plan = _build_remediation(facts, scope)
    target_fix = next(f for f in plan["ranked_fixes"] if f["fix_id"] == req.fix_id)

    eliminated = _eliminated_path_ids(facts, scope, state["applied_fixes"])
    remaining = len(_enumerate_paths(_effective_facts(facts, scope)))

    return {
        "status":       "applied",
        "applied_fix":  target_fix,
        "all_applied_fixes":   list(state["applied_fixes"]),
        "eliminated_path_ids": eliminated,
        "paths_remaining":     remaining,
        "message": (
            f"Applied '{target_fix['title']}'. Re-enumerated the graph: "
            f"{len(eliminated)} path(s) eliminated, {remaining} remaining."
        ),
        "_method": (
            "paths_remaining is the length of a fresh enumerate_paths() run "
            "over the patched facts, not a filtered list."
        ),
    }


@app.get("/api/status")
def get_status():
    """Run state and summary metrics.

    Live, derived from the real modules:
      hosts_count / vectors_count   environment_graph/facts.json
      enumerated_paths              enumerator.enumerate_paths()
      precision                     enumerator.path_precision() config coverage
      chokepoints_identified        chokepoint.engine minimum cover size

    Still a placeholder:
      verified_paths                no verifier exists; reported as 0, not
                                    borrowed from the verify.json fixture
    """
    facts = _load_facts()
    scope = _load_scope()
    effective = _effective_facts(facts, scope)

    raw_paths = _enumerate_paths(effective)
    precision = _path_precision(effective, raw_paths)
    plan = _build_remediation(facts, scope)
    eliminated = _eliminated_path_ids(facts, scope, state["applied_fixes"])

    fixture = load_fixture("status.json")

    summary_metrics = {
        # ── Derived from live data ───────────────────────────────────────────
        "hosts_count":      len(effective.get("hosts", [])),
        "vectors_count":    len(effective.get("vectors", [])),
        "enumerated_paths": len(raw_paths),
        # The sidebar labels this "Config Coverage", and this is that number:
        # the fraction of paths whose vectors all have the required configuration
        # present. It is NOT execution-verified precision.
        "precision":        f"{precision['config_coverage'] * 100:.1f}%",
        "chokepoints_identified": plan["minimum_cover"]["size"],

        # ── Honest zero, not a fixture value ─────────────────────────────────
        # Every vector carries verified_exploitable: null because nothing has
        # been executed. Showing the verify.json fixture's count here would put
        # a number on screen that no module produced.
        "verified_paths":   precision["verified"],

        # ── Runtime state ────────────────────────────────────────────────────
        "active_scenario":        state["active_scenario"],
        "applied_fixes_count":    len(state["applied_fixes"]),
        "eliminated_paths_count": len(eliminated),
    }

    return {
        "system":          fixture.get("system", "ASCEND Analysis Core"),
        "version":         fixture.get("version", "1.0.0-rc1"),
        "status":          fixture.get("status", "ready"),
        "lab_environment": fixture.get("lab_environment", "isolated-docker-network"),
        "summary_metrics": summary_metrics,
        "data_sources": {
            "facts":        facts.get("_meta", {}).get("source", "unknown"),
            "collected_at": facts.get("_meta", {}).get("collected_at"),
            "verifier":     "not built — verified_paths is 0 by construction",
        },
    }


@app.post("/api/reset")
def reset_state():
    """Reset demo run state: un-apply every fix."""
    state["active_scenario"] = "default"
    state["applied_fixes"] = []
    return {"status": "reset",
            "message": "Demo state reset. All fixes un-applied."}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)

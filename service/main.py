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
from enumerate import enumerate_paths as _enumerate_paths, path_precision as _path_precision

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

def _load_facts() -> dict:
    """Load environment_graph/facts.json (the real lab topology source)."""
    if not FACTS_PATH.exists():
        raise HTTPException(status_code=500, detail="environment_graph/facts.json not found")
    with open(FACTS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

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


def _build_paths_from_enumerator(facts: dict) -> list:
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
    - path_id = "path-{N:02d}" (stable ordinal, matches fixture convention).
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

    for path_idx, raw_path in enumerate(raw_paths, 1):
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
            "path_id":         f"path-{path_idx:02d}",
            "name":            f"Path {path_idx}: {' → '.join(dict.fromkeys(techniques))}",
            "length":          len(steps),
            "entry_host":      entry["host"],
            "crown_jewel_host": crown["host"],
            "overall_verified": None,
            "risk_score":      risk,
            "steps":           steps,
        })

    return result

# Internal runtime state for interactive demo persistence
state = {
    "active_scenario": "default",
    "applied_fixes": [],
    "eliminated_path_ids": []
}

class ApplyFixRequest(BaseModel):
    fix_id: str

class EnumerateRequest(BaseModel):
    scenario: Optional[str] = "default"

@app.get("/api/network")
def get_network():
    """Returns hosts and reachability edges.

    Data source: environment_graph/facts.json (real lab topology).
    Replaces the hand-written network.json fixture.
    """
    facts = _load_facts()
    return _build_network_from_facts(facts)

@app.post("/api/enumerate")
def enumerate_paths_endpoint(payload: Optional[EnumerateRequest] = None):
    """Enumerates attack paths from entry point to crown jewel.

    Data source: calls enumerator.enumerate_paths() in-process against
    environment_graph/facts.json. Replaces the fixture-based paths.json read.
    The scenario parameter is accepted for API-contract compatibility but
    ignored — the real enumerator runs against the single facts.json lab.
    """
    facts = _load_facts()
    paths = _build_paths_from_enumerator(facts)

    # Apply any previously-applied fixes (filter eliminated paths)
    if state["applied_fixes"]:
        paths = [p for p in paths if p["path_id"] not in state["eliminated_path_ids"]]

    precision = _path_precision(facts, _enumerate_paths(facts))

    return {
        "scenario":         "live",
        "name":             "Live Enumeration — environment_graph/facts.json",
        "entry_point":      facts["entry"]["host"],
        "crown_jewel":      facts["crown_jewel"]["host"],
        "total_paths":      len(paths),
        "paths":            paths,
        "description":      (
            f"Real-time DFS enumeration over {len(paths)} path(s) from "
            f"{facts['entry']['host']}:{facts['entry']['privilege']} "
            f"to {facts['crown_jewel']['host']}:{facts['crown_jewel']['privilege']}. "
            f"Precision: {precision['verified']}/{precision['proposed']} = {precision['precision']:.2f}"
        ),
    }

@app.post("/api/verify")
def verify_paths():
    """Performs per-path and per-step verification outcomes from execution verifier."""
    # TODO(Part A/B): replace fixture read with call into verifier
    verify_data = load_fixture("verify.json")
    return verify_data

@app.get("/api/remediation")
def get_remediation():
    """Returns ranked fixes and fixes-vs-paths efficacy curve."""
    # TODO(Part A/B): replace fixture read with call into chokepoint
    remediation_data = load_fixture("remediation.json")
    return remediation_data

@app.post("/api/remediation/apply")
def apply_remediation(req: ApplyFixRequest):
    """Applies a fix and returns eliminated attack paths."""
    # TODO(Part A/B): replace fixture read with call into chokepoint
    remediation_data = load_fixture("remediation.json")
    target_fix = next((f for f in remediation_data.get("ranked_fixes", []) if f["fix_id"] == req.fix_id), None)
    
    if not target_fix:
        raise HTTPException(status_code=404, detail=f"Fix {req.fix_id} not found in remediation plan")
    
    if req.fix_id not in state["applied_fixes"]:
        state["applied_fixes"].append(req.fix_id)
        for pid in target_fix.get("paths_eliminated", []):
            if pid not in state["eliminated_path_ids"]:
                state["eliminated_path_ids"].append(pid)
                
    return {
        "status": "applied",
        "applied_fix": target_fix,
        "all_applied_fixes": state["applied_fixes"],
        "eliminated_path_ids": state["eliminated_path_ids"],
        "message": f"Chokepoint fix '{target_fix['title']}' applied successfully. {len(state['eliminated_path_ids'])} attack path(s) eliminated."
    }

@app.get("/api/status")
def get_status():
    """Returns run state and summary metrics.

    Derived fields (live, from real modules):
      hosts_count       ← len(facts["hosts"])           via environment_graph/facts.json
      vectors_count     ← len(facts["vectors"])          via environment_graph/facts.json
      enumerated_paths  ← len(enumerate_paths(facts))   via enumerator/enumerate.py
      precision         ← path_precision(facts, paths)  via enumerator/enumerate.py

    Fixture-sourced placeholders (modules don't exist yet — NOT derived):
      verified_paths        ← status.json  # TODO: replace when verifier/ is built
      chokepoints_identified← status.json  # TODO: replace when chokepoint/ is built
    """
    facts = _load_facts()
    raw_paths = _enumerate_paths(facts)
    precision = _path_precision(facts, raw_paths)

    # Load fixture only for the two fields that still have no real module behind them
    fixture = load_fixture("status.json")
    fixture_metrics = fixture.get("summary_metrics", {})

    summary_metrics = {
        # ── Derived from live data ────────────────────────────────────────────
        "hosts_count":      len(facts.get("hosts", [])),
        "vectors_count":    len(facts.get("vectors", [])),
        "enumerated_paths": len(raw_paths),
        "precision":        f"{precision['precision'] * 100:.1f}%",

        # ── Fixture placeholders: verifier and chokepoint engine not built yet ─
        "verified_paths":        fixture_metrics.get("verified_paths", 0),
        "chokepoints_identified": fixture_metrics.get("chokepoints_identified", 0),

        # ── Runtime state (always live) ───────────────────────────────────────
        "active_scenario":       state["active_scenario"],
        "applied_fixes_count":   len(state["applied_fixes"]),
        "eliminated_paths_count": len(state["eliminated_path_ids"]),
    }

    return {
        "system":          fixture.get("system", "ASCEND Analysis Core"),
        "version":         fixture.get("version", "1.0.0-rc1"),
        "status":          fixture.get("status", "ready"),
        "lab_environment": fixture.get("lab_environment", "isolated-docker-network"),
        "summary_metrics": summary_metrics,
    }

@app.post("/api/reset")
def reset_state():
    """Helper endpoint to reset demo run state and applied fixes."""
    state["active_scenario"] = "default"
    state["applied_fixes"] = []
    state["eliminated_path_ids"] = []
    return {"status": "reset", "message": "Demo state successfully reset to initial conditions."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)

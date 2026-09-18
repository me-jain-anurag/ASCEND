import datetime as _dt
import json
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Optional, List
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

            # Attach the credential to EVERY step that uses it, not just the
            # first. An attacker who harvests a key keeps holding it, and the
            # enumerator says so on each lateral step; attaching it once meant
            # the second hop looked credential-less, and the verifier could not
            # tell which key to authenticate with.
            cred_for_step = None
            used_cred_id = raw_step.get("credential")
            if used_cred_id:
                cred_data = cred_map.get(used_cred_id, {})
                disc = cred_data.get("discoverable_at", "")
                if isinstance(disc, dict):
                    disc = f"{disc.get('host', '')} ({disc.get('privilege', '')} privilege)"
                cred_for_step = {
                    "cred_id": used_cred_id,
                    "type":    cred_data.get("type", "credential"),
                    "discoverable_at": str(disc),
                }
                if pending_cred and pending_cred["cred_id"] == used_cred_id:
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
            f"(POST /api/verify to run the techniques in the lab)."
            + (f" {len(state['applied_fixes'])} fix(es) applied; "
               f"{len(eliminated)} path(s) eliminated."
               if state["applied_fixes"] else "")
        ),
    }


def _verify_failure_detail(exc: Exception) -> str:
    """Explain a failed verification run in terms of what to actually do.

    /api/verify is the only endpoint that talks to Docker, so when the rest of
    the API is fine and this alone fails, the cause is almost always the
    process's access to the Docker socket rather than anything about the lab.
    Saying "is the lab up?" for a permission error sends people to restart
    containers that were never the problem.
    """
    text = f"{type(exc).__name__}: {exc}"

    if "Permission denied" in text or "PermissionError" in text:
        return (
            "Cannot reach the Docker socket: permission denied. The API process "
            "is not in the 'docker' group — this is about the terminal that "
            "started the server, not about the lab. Stop the server, run "
            "`newgrp docker` (or log out and back in), check `docker ps` works "
            "without sudo, then start it again. "
            f"[{text}]"
        )
    if "FileNotFoundError" in text or "No such file or directory" in text:
        return (
            "Cannot reach the Docker socket: it does not exist. Is the Docker "
            f"daemon running? `sudo systemctl start docker`. [{text}]"
        )
    if "not found" in text.lower() and "container" in text.lower():
        return (
            "The lab containers are not running. Start them with "
            f"`bash lab/up.sh`. [{text}]"
        )
    if "ModuleNotFoundError" in text:
        return (
            "The verifier's dependencies are missing. Install them with "
            f"`pip install -r verifier/requirements.txt`. [{text}]"
        )
    return f"Verification run failed. {text}"


def _credential_locations(facts: dict) -> dict:
    """{(cred_id, host): path} — where each credential sits on each host.

    Built from the collector's own evidence (features.found_at), so the verifier
    is told where a key is by the same probe that found it, rather than by a
    path written into the service.
    """
    out: dict[tuple[str, str], str] = {}
    for cred in facts.get("credentials", []):
        for loc in (cred.get("features") or {}).get("found_at", []):
            out[(cred["cred_id"], loc["host"])] = loc["path"]
    return out


def _verifier_edges(path: dict, facts: dict) -> list[dict]:
    """Translate one enumerated path into verifier edges.

    Each edge says which host to run on, which unprivileged account to start
    from, and any per-edge technique parameters. The parameters matter: both SSH
    hops in the lab are the same technique id, so without them the second hop
    would re-run the first hop's source and target.

    An edge that cannot be expressed is marked unsupported rather than dropped,
    so a path is never silently reported as shorter than it is.
    """
    creds = _credential_locations(facts)
    edges: list[dict] = []

    for step in path["steps"]:
        technique_id = step["vector"]["technique"].replace(" ", "")
        source_host = step["source_host"]
        target_host = step["target_host"]
        low_priv_user = step["source_account"]["username"]

        if source_host != target_host:
            # Lateral movement: run on the SOURCE host, log in to the target.
            credential = step.get("credential") or {}
            cred_id = credential.get("cred_id")
            key_path = creds.get((cred_id, source_host)) if cred_id else None

            if not key_path:
                # The attacker would carry a harvested key forward; the verifier
                # cannot stage credentials between hops yet, so it says so
                # instead of guessing a path.
                # TODO(verifier): stage the harvested credential onto the source
                # host so a hop can be verified even where the key is not
                # already present.
                edges.append({
                    "host": source_host,
                    "start_user": low_priv_user,
                    "technique_id": technique_id,
                    "unsupported": (
                        f"no location recorded for credential "
                        f"{cred_id or '(none)'} on {source_host}; the verifier "
                        f"cannot yet carry a harvested credential between hops"
                    ),
                })
                continue

            edges.append({
                "host": source_host,
                "start_user": low_priv_user,
                "technique_id": technique_id,
                "params": {
                    "key_path": key_path,
                    "to_host": target_host,
                    "to_user": step["target_account"]["username"],
                },
            })
        else:
            # Local escalation: run on the host, starting as the low-privilege
            # account the attacker already controls there.
            edges.append({
                "host": target_host,
                "start_user": low_priv_user,
                "technique_id": technique_id,
            })

    return edges


@app.post("/api/verify")
def verify_paths():
    """Execute each enumerated path in the lab and report what actually worked.

    Calls verifier.runner.verify_path IN-PROCESS against the live Docker lab.
    Every step outcome below came from running a real command in a container and
    checking whether the root-only canary token came back.

    Three step outcomes are possible, and they are not interchangeable:

      verified        the technique ran and privilege genuinely escalated
      failed          the technique ran and did not work — a real negative
      not executable  the technique was never attempted, because this lab
                      cannot meet a precondition (e.g. a kernel exploit needs a
                      vulnerable kernel, and containers share the host's)

    A path counts as verified only if every step verified. A path containing a
    not-executable step is reported as partial: not proven, and equally not
    disproven.
    """
    facts = _load_facts()
    scope_data = _load_scope()
    effective = _effective_facts(facts, scope_data)
    paths_list = _build_paths_from_enumerator(effective, _baseline_path_ids(facts))

    run_id = f"run-{uuid.uuid4().hex[:8]}"

    try:
        from verifier.runner import verify_path as _verify_path
        from verifier.outcomes import LIVE_PATH as _LIVE_REL
        from verifier.scope import load as _load_verifier_scope
        _LIVE_OUTCOMES = str(_ROOT / _LIVE_REL)
        vscope = _load_verifier_scope(SCOPE_PATH)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=_verify_failure_detail(exc))

    results: dict[str, Any] = {}
    for path in paths_list:
        edges = _verifier_edges(path, effective)

        runnable = [e for e in edges if "unsupported" not in e]
        try:
            # Live demo runs go to the audit trail, NOT to outcomes.jsonl:
            # repeated Verify clicks must not end up as training labels.
            outcome = _verify_path(
                runnable, vscope, output_path=_LIVE_OUTCOMES,
            ) if runnable else {
                "status": "failed", "edges": [], "not_executable": []
            }
        except Exception as exc:
            raise HTTPException(status_code=503, detail=_verify_failure_detail(exc))

        # Map edge outcomes back onto the path's steps, in order.
        by_index = {}
        runnable_i = 0
        for i, edge in enumerate(edges):
            if "unsupported" in edge:
                by_index[i] = {
                    "escalated": False,
                    "status": "not_executable",
                    "reason": edge["unsupported"],
                    "evidence": f"NOT EXECUTABLE: {edge['unsupported']}",
                }
            else:
                got = outcome["edges"][runnable_i] if runnable_i < len(outcome["edges"]) else None
                by_index[i] = got or {
                    "escalated": False,
                    "status": "not_attempted",
                    "reason": "an earlier step did not succeed",
                    "evidence": "NOT ATTEMPTED: an earlier step did not succeed",
                }
                runnable_i += 1

        verify_steps = []
        failed_at = None
        for i, step in enumerate(path["steps"]):
            data = by_index.get(i, {})
            ok = bool(data.get("escalated"))
            status = data.get("status", "not_attempted")
            if not ok and failed_at is None:
                failed_at = step["step_number"]
            verify_steps.append({
                "step_number": step["step_number"],
                "verified": ok,
                "status": status,
                "reason": data.get("reason", ""),
                "evidence": {
                    "technique": step["vector"]["technique"],
                    "exit_code": 0 if ok else 1,
                    "stdout": (data.get("evidence") or "")[:400],
                    # No syscall telemetry is captured yet; verifier/telemetry.py
                    # is an interface with no Falco behind it. Saying so beats
                    # printing a plausible-looking auditd line that nothing
                    # produced.
                    "telemetry": (
                        "not captured — verifier/telemetry.py is a stub; "
                        "Falco integration is not built"
                    ),
                },
            })

        blocked = [s for s in verify_steps if s["status"] == "not_executable"]
        attempted_ok = all(
            s["verified"] for s in verify_steps if s["status"] != "not_executable"
        )
        if all(s["verified"] for s in verify_steps):
            path_status = "verified"
        elif blocked and attempted_ok:
            path_status = "partial"
        else:
            path_status = "failed"

        results[path["path_id"]] = {
            "overall_verified": path_status == "verified",
            "status": path_status,
            "steps_verified": sum(1 for s in verify_steps if s["verified"]),
            "steps_total": len(verify_steps),
            "not_executable": [
                {"step_number": s["step_number"],
                 "technique": s["evidence"]["technique"],
                 "reason": s["reason"]}
                for s in blocked
            ],
            **({"failed_at_step": failed_at} if failed_at else {}),
            "steps": verify_steps,
        }

    verified_count = sum(1 for r in results.values() if r["overall_verified"])
    partial_count = sum(1 for r in results.values() if r["status"] == "partial")
    tested = len(results)

    resp = {
        "execution_run_id": run_id,
        "status": "completed",
        "timestamp": _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat(),
        "summary": {
            "paths_tested":   tested,
            "paths_verified": verified_count,
            "paths_failed":   tested - verified_count - partial_count,
            "paths_partial":  partial_count,
            # Path-finder precision: verified / proposed. Partial paths count
            # against it, because a path we could not finish executing is not
            # a path we have proven.
            "precision":      round(verified_count / tested, 4) if tested else 0.0,
        },
        "results": results,
    }
    state["last_verification"] = resp
    return resp


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

        # Execution-verified paths. 0 until /api/verify has been run, and it
        # counts only FULLY verified paths — a path with a step the lab cannot
        # execute is partial, not verified.
        "verified_paths": (
            state["last_verification"]["summary"]["paths_verified"]
            if state.get("last_verification") else 0
        ),
        "partial_paths": (
            state["last_verification"]["summary"].get("paths_partial", 0)
            if state.get("last_verification") else 0
        ),

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
        "verification": (
            {
                "run_id":   state["last_verification"]["execution_run_id"],
                "ran_at":   state["last_verification"]["timestamp"],
                "verified": state["last_verification"]["summary"]["paths_verified"],
                "partial":  state["last_verification"]["summary"].get("paths_partial", 0),
                "failed":   state["last_verification"]["summary"]["paths_failed"],
                "note": (
                    "A partial path had every executable step succeed but "
                    "contains at least one step this lab cannot run. It is "
                    "neither proven nor disproven."
                ),
            }
            if state.get("last_verification") else
            {"run_id": None, "note": "no verification run yet — POST /api/verify"}
        ),
        "data_sources": {
            "facts":        facts.get("_meta", {}).get("source", "unknown"),
            "collected_at": facts.get("_meta", {}).get("collected_at"),
            "verifier":     "live — execution verifier (isolated Docker lab)" if state.get("last_verification") else "ready",
        },
    }


@app.post("/api/reset")
def reset_state():
    """Reset demo run state: un-apply every fix."""
    state["active_scenario"] = "default"
    state["applied_fixes"] = []
    state["last_verification"] = None
    return {"status": "reset",
            "message": "Demo state reset. All fixes un-applied."}



if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)

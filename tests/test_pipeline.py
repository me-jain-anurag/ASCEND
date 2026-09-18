#!/usr/bin/env python3
"""
End-to-end regression tests for the ASCEND thin slice.

    python3 tests/test_pipeline.py        # standalone, no pytest needed
    pytest tests/test_pipeline.py         # also works

Covers the pipeline the demo runs on: raw capture -> derivation rules ->
enumerator -> chokepoint engine -> FastAPI contract. Tests that need an optional
dependency (ssh-keygen, fastapi) skip rather than fail.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "collectors"))
sys.path.insert(0, str(ROOT / "enumerator"))

import yaml                                              # noqa: E402
import derive                                            # noqa: E402
from pathfinder import enumerate_paths, path_precision    # noqa: E402
from chokepoint.engine import (                          # noqa: E402
    build_remediation, apply_fix_ids, eliminated_path_ids,
    known_fix_ids, baseline_path_ids,
)

CAPTURE = ROOT / "collectors" / "fixtures" / "lab_capture.json"
SCOPE = yaml.safe_load((ROOT / "scope.yaml").read_text())
KG = json.loads((ROOT / "knowledge_graph" / "pack.json").read_text())


class Skip(Exception):
    pass


def _facts_from_capture() -> tuple[dict, dict]:
    sys.path.insert(0, str(ROOT / "collectors"))
    import collect
    capture = json.loads(CAPTURE.read_text())
    return collect.build_facts(capture, SCOPE, KG, "test")


# ─── Collector: SSH key fingerprinting ────────────────────────────────────────

def test_fingerprints_match_ssh_keygen():
    """Our pure-Python fingerprint must equal OpenSSH's, or credential-reuse
    detection is comparing the wrong things."""
    if not shutil.which("ssh-keygen"):
        raise Skip("ssh-keygen not installed")
    import sshkeys
    with tempfile.TemporaryDirectory() as tmp:
        for keytype in ("ed25519", "rsa"):
            path = Path(tmp) / keytype
            subprocess.run(["ssh-keygen", "-t", keytype, "-N", "", "-C",
                            f"{keytype} probe", "-f", str(path)],
                           check=True, capture_output=True)
            expected = subprocess.run(["ssh-keygen", "-lf", f"{path}.pub"],
                                      capture_output=True, text=True).stdout.split()[1]
            priv = sshkeys.parse_private_key(path.read_text())
            pub = sshkeys.parse_public_key_line(Path(f"{path}.pub").read_text())
            assert priv["fingerprint"] == expected, keytype
            assert pub["fingerprint"] == expected, keytype
            assert priv["comment"] == f"{keytype} probe", keytype


# ─── Collector: derivation rules ──────────────────────────────────────────────

def test_derivation_finds_exactly_the_planted_vectors():
    facts, _ = _facts_from_capture()
    got = {v["vector_id"]: v["technique"] for v in facts["vectors"]}
    assert got == {
        "v_web01_credfile_id_rsa":     "T1552.001",
        "v_app01_sudo_tar":            "T1548.003",
        "v_db01_suid_find":            "T1548.001",
        "v_db01_kernel_cve_2022_0847": "T1068",
    }, got


def test_derivation_declines_the_conditions_it_should():
    """The rules must discriminate. A collector that flags everything is noise,
    and these four cases are the ones most likely to regress."""
    _, report = _facts_from_capture()
    reasons = {(s["host"], s["technique"]): s["reason"] for s in report["skipped"]}

    assert "owner" in reasons[("app01", "T1552.001")]          # 0600 key
    assert "shell escape" in reasons[("app01", "T1548.003")]   # NOPASSWD /bin/ls
    assert "branch fix" in reasons[("app01", "T1068")]         # patched 5.10
    assert "below the affected range" in reasons[("web01", "T1068")]


def test_kernel_matching_is_branch_aware():
    """5.15.30 is patched for DirtyPipe even though it is below 5.16.11. A naive
    single-threshold check calls it vulnerable; that is the bug this guards."""
    cases = {"5.4.0": False, "5.10.102": False, "5.10.150": False,
             "5.15.30": False, "5.16.0": True, "5.10.50": True, "5.17.0": False}
    for version, expect_vulnerable in cases.items():
        raw = {"kernel": {"effective_kernel": version, "provenance": "declared",
                          "observed_kernel": "6.0.0", "declared_kernel": version}}
        out, skipped = [], []
        derive._kernel("h", raw, SCOPE["rules"], KG, lambda t: t, out, skipped)
        assert bool(out) == expect_vulnerable, f"{version}: {out or skipped}"


def test_credential_reuse_is_detected_by_fingerprint():
    facts, _ = _facts_from_capture()
    assert len(facts["credentials"]) == 1
    cred = facts["credentials"][0]
    assert cred["cred_id"] == "app_deploy_key"
    assert sorted(g["host"] for g in cred["grants"]) == ["app01", "db01"]
    assert cred["features"]["reuse_count"] == 2
    # Discoverable from the READABLE copy on web01, not the 0600 copy on app01.
    assert cred["discoverable_at"] == {"host": "web01", "privilege": "low"}


def test_reachability_reflects_the_segmentation():
    """web01 and db01 share no network, so no edge between them may appear."""
    facts, _ = _facts_from_capture()
    edges = {(e["from"], e["to"]) for e in facts["reachability"]}
    assert ("web01", "db01") not in edges
    assert ("db01", "web01") not in edges
    assert ("web01", "app01") in edges
    assert ("app01", "db01") in edges


def test_nothing_claims_execution_verification():
    """The single most important invariant while verifier/ does not exist."""
    for path in (ROOT / "environment_graph" / "facts.json",
                 ROOT / "environment_graph" / "facts.sample.json"):
        facts = json.loads(path.read_text())
        for vec in facts["vectors"]:
            assert vec.get("verified_exploitable") is None, f"{path.name}:{vec['vector_id']}"
    facts, _ = _facts_from_capture()
    for vec in facts["vectors"]:
        assert vec["verified_exploitable"] is None
        assert vec["config_exploitable"] is True


# ─── Enumerator ───────────────────────────────────────────────────────────────

def test_collected_facts_reproduce_the_reference_paths():
    """The acceptance criterion for the collector: facts derived from a live lab
    probe must yield the same analysis as the hand-written reference."""
    collected, _ = _facts_from_capture()
    reference = json.loads((ROOT / "environment_graph" / "facts.sample.json").read_text())

    a, b = enumerate_paths(collected), enumerate_paths(reference)
    assert len(a) == len(b) > 0, (len(a), len(b))

    def shape(paths):
        return sorted(tuple(s["technique"] for s in p) for p in paths)
    assert shape(a) == shape(b), "technique sequences diverge from the reference"


def test_precision_separates_config_coverage_from_execution():
    facts, _ = _facts_from_capture()
    metrics = path_precision(facts, enumerate_paths(facts))
    assert metrics["config_coverage"] == 1.0
    assert metrics["precision"] == 0.0            # no verifier has run
    assert metrics["verified"] == 0
    assert metrics["verification_status"] == "none"


# ─── Chokepoint engine ────────────────────────────────────────────────────────

def test_chokepoint_ranks_the_reused_key_first():
    facts, _ = _facts_from_capture()
    plan = build_remediation(facts, SCOPE)
    total = plan["total_enumerated_paths"]
    top = plan["ranked_fixes"][0]
    assert top["rank"] == 1 and top["is_recommended_chokepoint"]
    # The exposed key is upstream of every route, so fixing it kills them all.
    assert top["target_vector"] == "v_web01_credfile_id_rsa"
    assert len(top["paths_eliminated"]) == total
    assert plan["minimum_cover"]["size"] == 1
    assert plan["minimum_cover"]["covers_all_paths"]
    # Among the fixes that cover everything, the cheapest must rank first.
    assert top["cost"] <= min(f["cost"] for f in plan["ranked_fixes"]
                              if len(f["paths_eliminated"]) == total)


def test_efficacy_curve_is_monotonic_and_starts_at_zero():
    facts, _ = _facts_from_capture()
    plan = build_remediation(facts, SCOPE)
    curve = plan["efficacy_curve"]
    assert curve[0] == {"fixes_applied": 0,
                        "paths_remaining": plan["total_enumerated_paths"],
                        "paths_eliminated": 0, "reduction_pct": 0.0}
    remaining = [pt["paths_remaining"] for pt in curve]
    assert remaining == sorted(remaining, reverse=True), remaining


def test_applying_a_fix_actually_removes_the_paths():
    """Elimination must be re-enumeration, not list filtering."""
    facts, _ = _facts_from_capture()
    sudo_fix = next(f for f in build_remediation(facts, SCOPE)["ranked_fixes"]
                    if f["target_vector"] == "v_app01_sudo_tar")

    baseline = enumerate_paths(facts)
    patched = apply_fix_ids(facts, SCOPE, [sudo_fix["fix_id"]])
    survivors = enumerate_paths(patched)

    # Removing a vector can only remove paths, never create them, and no
    # survivor may still rely on the vector that was removed.
    assert 0 < len(survivors) < len(baseline)
    assert all("v_app01_sudo_tar" not in [s.get("vector_id") for s in path]
               for path in survivors)

    eliminated = eliminated_path_ids(facts, SCOPE, [sudo_fix["fix_id"]])
    assert len(eliminated) == len(baseline) - len(survivors)
    assert set(eliminated) == set(sudo_fix["paths_eliminated"])


def test_fix_ids_resolve_and_path_ids_are_stable():
    facts, _ = _facts_from_capture()
    ids = known_fix_ids(facts, SCOPE)
    assert ids == sorted(ids) and ids[0] == "fix-01"

    baseline = baseline_path_ids(facts)
    expected = {f"path-{i:02d}" for i in range(1, len(enumerate_paths(facts)) + 1)}
    assert set(baseline.values()) == expected
    # A surviving path must keep its baseline id, never be renumbered into the
    # id of a path that was just eliminated.
    sudo_fix = next(f for f in build_remediation(facts, SCOPE)["ranked_fixes"]
                    if f["target_vector"] == "v_app01_sudo_tar")
    eliminated = set(eliminated_path_ids(facts, SCOPE, [sudo_fix["fix_id"]]))
    from chokepoint.engine import path_signature
    survivors = {baseline[path_signature(p)]
                 for p in enumerate_paths(apply_fix_ids(facts, SCOPE, [sudo_fix["fix_id"]]))}
    assert not (survivors & eliminated)


# ─── Service contract ─────────────────────────────────────────────────────────

def test_api_contract_and_apply_reset_loop():
    try:
        from fastapi.testclient import TestClient
    except ImportError:
        raise Skip("fastapi not installed (pip install -r service/requirements.txt)")
    sys.path.insert(0, str(ROOT / "service"))
    import main
    client = TestClient(main.app)
    client.post("/api/reset")

    net = client.get("/api/network").json()
    assert {h["hostname"] for h in net["hosts"]} == {"web01", "app01", "db01"}
    assert all("kernel_version" in h and "accounts" in h for h in net["hosts"])

    enum = client.post("/api/enumerate", json={}).json()
    total = enum["total_paths"]
    assert total > 0
    assert len(enum["paths"]) == total

    status = client.get("/api/status").json()["summary_metrics"]
    # Counts are asserted as relationships, not literals: the lab gains and
    # loses vectors as the scenario develops, and a hard-coded 3 here only
    # records what the lab happened to contain on the day it was written.
    assert status["enumerated_paths"] == total
    assert status["verified_paths"] <= total
    assert 1 <= status["chokepoints_identified"] <= status["vectors_count"]

    rem = client.get("/api/remediation").json()
    assert rem["ranked_fixes"] and rem["efficacy_curve"]
    for fix in rem["ranked_fixes"]:
        assert {"fix_id", "rank", "title", "cost", "paths_eliminated",
                "efficacy_percentage", "is_recommended_chokepoint"} <= set(fix)

    assert client.post("/api/remediation/apply",
                       json={"fix_id": "nope"}).status_code == 404

    # The top-ranked fix is the head of a cover, so it must remove at least one
    # path; and whatever it removes must come back on reset.
    top = rem["ranked_fixes"][0]["fix_id"]
    applied = client.post("/api/remediation/apply", json={"fix_id": top}).json()
    assert applied["paths_remaining"] < total
    assert client.post("/api/enumerate", json={}).json()["total_paths"] == \
        applied["paths_remaining"]

    client.post("/api/reset")
    assert client.post("/api/enumerate", json={}).json()["total_paths"] == total


# ─── Runner ───────────────────────────────────────────────────────────────────

def main() -> int:
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    passed = failed = skipped = 0
    for name, fn in tests:
        try:
            fn()
        except Skip as exc:
            print(f"  SKIP  {name}  ({exc})"); skipped += 1
        except AssertionError as exc:
            print(f"  FAIL  {name}\n          {exc}"); failed += 1
        except Exception as exc:                      # noqa: BLE001
            print(f"  ERROR {name}\n          {type(exc).__name__}: {exc}"); failed += 1
        else:
            print(f"  ok    {name}"); passed += 1
    print(f"\n{passed} passed, {failed} failed, {skipped} skipped")
    return 1 if failed else 0



# ─── TypeScript contract ──────────────────────────────────────────────────────
# The dashboard is built with `tsc -b`, which cannot run in every environment.
# These checks enforce the same interfaces from dashboard/src/types/index.ts at
# the JSON boundary, so an API change that would fail the frontend build fails
# here first.

_STR, _NUM, _BOOL = str, (int, float), bool
_OPT_BOOL = (bool, type(None))

_ACCOUNT = {"username": _STR, "type": _STR, "privilege_level": int}
_VECTOR = {"vector_id": (str, type(None)), "technique": _STR,
           "cve": (str, type(None)), "cvss": _NUM, "features": dict,
           "verified_exploitable": _OPT_BOOL}
_HOST = {"hostname": _STR, "role": _STR, "os": _STR, "kernel_version": _STR,
         "asset_value": _NUM, "is_entry_point": _BOOL, "is_crown_jewel": _BOOL,
         "accounts": list, "vectors": list}
_EDGE = {"from_host": _STR, "to_host": _STR, "port": int, "service": _STR}
_STEP = {"step_number": int, "source_host": _STR, "target_host": _STR,
         "source_account": dict, "target_account": dict, "vector": dict,
         "credential": (dict, type(None)), "description": _STR,
         "verified": _OPT_BOOL}
_PATH = {"path_id": _STR, "name": _STR, "length": int, "entry_host": _STR,
         "crown_jewel_host": _STR, "overall_verified": _OPT_BOOL,
         "risk_score": _NUM, "steps": list}
_FIX = {"fix_id": _STR, "rank": int, "title": _STR, "chokepoint_type": _STR,
        "target_host": _STR, "target_vector": _STR, "technique_broken": _STR,
        "cost": _NUM, "description": _STR, "paths_eliminated": list,
        "efficacy_percentage": _NUM, "is_recommended_chokepoint": _BOOL}
_POINT = {"fixes_applied": int, "paths_remaining": int,
          "paths_eliminated": int, "reduction_pct": _NUM}
_METRICS = {"hosts_count": int, "vectors_count": int, "enumerated_paths": int,
            "verified_paths": int, "precision": _STR,
            "chokepoints_identified": int, "active_scenario": _STR}
_VERIFY = {"execution_run_id": _STR, "status": _STR, "timestamp": _STR,
           "summary": dict, "results": dict}


def _check(obj, shape, where):
    for field, expected in shape.items():
        assert field in obj, f"{where}: missing required field {field!r}"
        value = obj[field]
        # bool is a subclass of int; keep the two distinct.
        if expected is int and isinstance(value, bool):
            raise AssertionError(f"{where}.{field}: bool where number expected")
        assert isinstance(value, expected), (
            f"{where}.{field}: {type(value).__name__} is not {expected}")


def test_responses_match_the_typescript_interfaces():
    try:
        from fastapi.testclient import TestClient
    except ImportError:
        raise Skip("fastapi not installed")
    sys.path.insert(0, str(ROOT / "service"))
    import main
    client = TestClient(main.app)
    client.post("/api/reset")

    net = client.get("/api/network").json()
    for host in net["hosts"]:
        _check(host, _HOST, "Host")
        for acct in host["accounts"]:
            _check(acct, _ACCOUNT, "Account")
        for vec in host["vectors"]:
            _check(vec, _VECTOR, "Vector")
    for edge in net["reachability"]:
        _check(edge, _EDGE, "ReachabilityEdge")

    enum = client.post("/api/enumerate", json={}).json()
    _check(enum, {"scenario": _STR, "name": _STR, "entry_point": _STR,
                  "crown_jewel": _STR, "total_paths": int, "paths": list,
                  "description": _STR}, "PathsResponse")
    for path in enum["paths"]:
        _check(path, _PATH, "AttackPath")
        for step in path["steps"]:
            _check(step, _STEP, "PathStep")
            _check(step["vector"], _VECTOR, "PathStep.vector")
            _check(step["source_account"], _ACCOUNT, "PathStep.source_account")
            _check(step["target_account"], _ACCOUNT, "PathStep.target_account")

    rem = client.get("/api/remediation").json()
    _check(rem, {"total_verified_paths": int, "ranked_fixes": list,
                 "efficacy_curve": list}, "RemediationData")
    for fix in rem["ranked_fixes"]:
        _check(fix, _FIX, "Fix")
    for point in rem["efficacy_curve"]:
        _check(point, _POINT, "EfficacyPoint")

    status = client.get("/api/status").json()
    _check(status, {"system": _STR, "version": _STR, "status": _STR,
                    "lab_environment": _STR, "summary_metrics": dict}, "StatusData")
    _check(status["summary_metrics"], _METRICS, "StatusMetrics")

    _check(client.post("/api/verify").json(), _VERIFY, "VerifyData")


# ─── Verifier: the honesty invariants ─────────────────────────────────────────
# These exist because the verifier previously shipped a "DirtyPipe exploit" that
# was a setuid-root stub calling setuid(0). It reported T1068 as verified on any
# kernel. A fabricated success is worse than no verifier at all, since every
# other number the project publishes then rests on it.

def test_no_exploit_code_or_binaries_are_shipped():
    """lab/exploits/ must hold documentation only — never a binary."""
    exploits = ROOT / "lab" / "exploits"
    if not exploits.is_dir():
        raise Skip("lab/exploits/ not present")
    unexpected = [p.name for p in exploits.iterdir()
                  if p.is_file() and p.suffix not in (".md", "")
                  or (p.is_file() and p.suffix == "" and p.name != ".gitkeep")]
    assert not unexpected, f"lab/exploits/ contains artifacts: {unexpected}"


def test_exploit_artifacts_are_never_installed_setuid():
    """A privesc exploit that needs a setuid bit is not demonstrating the bug.

    Installing one 4755 makes the verifier measure the file mode instead of the
    vulnerability, which is exactly how the fabricated T1068 pass was produced.
    """
    seed = ROOT / "lab" / "seed"
    for script in seed.glob("*.sh"):
        for lineno, line in enumerate(script.read_text().splitlines(), 1):
            code = line.split("#", 1)[0]
            if "/opt/exploits" in code and "install" in code:
                assert "4755" not in code and "u+s" not in code, (
                    f"{script.name}:{lineno} installs an exploit setuid: {line.strip()}"
                )


def test_kernel_exploit_is_not_executable_on_a_shared_kernel():
    """T1068 must report not_executable, never a pass or a fail, when the
    RUNNING kernel is not in the affected range."""
    sys.path.insert(0, str(ROOT))
    from verifier.adapters.anchor_cve import _kernel_is_vulnerable

    spec = {"affected_from": "5.8.0",
            "fixed_versions": ["5.10.102", "5.15.25", "5.16.11"]}

    # A modern host kernel — the container-lab reality.
    vulnerable, why = _kernel_is_vulnerable("7.2.6-x64v3-xanmod1", spec)
    assert not vulnerable
    assert "newer than every affected branch" in why

    # Genuinely vulnerable, and genuinely patched, on the same branch.
    assert _kernel_is_vulnerable("5.16.0", spec)[0] is True
    assert _kernel_is_vulnerable("5.16.11", spec)[0] is False
    assert _kernel_is_vulnerable("5.10.150", spec)[0] is False   # branch-patched
    assert _kernel_is_vulnerable("5.4.0", spec)[0] is False      # pre-affected
    assert _kernel_is_vulnerable("", spec)[0] is False           # unknown kernel


def test_adapter_result_state_cannot_contradict_itself():
    sys.path.insert(0, str(ROOT))
    from verifier.adapters import (AdapterResult, ESCALATED, NOT_ESCALATED,
                                   NOT_EXECUTABLE)

    assert AdapterResult(True, "", []).status == ESCALATED
    assert AdapterResult(False, "", []).status == NOT_ESCALATED
    blocked = AdapterResult(False, "", [], status=NOT_EXECUTABLE, reason="no kernel")
    assert blocked.status == NOT_EXECUTABLE and not blocked.escalated


def test_overrides_cannot_widen_what_the_verifier_may_run():
    """Per-edge overrides fill in parameters; they must not be able to change
    the adapter, the check, or the host allow-list."""
    sys.path.insert(0, str(ROOT))
    from verifier.runner import run_one
    from verifier.scope import load as load_scope

    scope = load_scope(ROOT / "scope.yaml")
    tech = scope.technique("T1021.004+T1550")
    for field in ("adapter", "check", "hosts", "id"):
        try:
            run_one(host="web01", start_user="www-data", technique=tech.raw,
                    scenario="test", scope=scope, do_reset=False,
                    overrides={field: "anything"})
        except ValueError as exc:
            assert field in str(exc)
        else:
            raise AssertionError(f"override of {field!r} was accepted")


def test_verify_endpoint_reports_blocked_steps_as_not_executable():
    """End-to-end: the live lab must produce partial paths with a stated
    reason, never a silent pass. Skips when the lab is not running."""
    try:
        from fastapi.testclient import TestClient
    except ImportError:
        raise Skip("fastapi not installed")
    sys.path.insert(0, str(ROOT / "service"))
    import main
    client = TestClient(main.app)
    client.post("/api/reset")

    resp = client.post("/api/verify")
    if resp.status_code == 503:
        raise Skip("lab not running (bash lab/up.sh)")
    data = resp.json()

    assert data["summary"]["paths_tested"] > 0
    for path_id, result in data["results"].items():
        assert result["status"] in ("verified", "partial", "failed"), path_id
        # A path is only "verified" if every single step verified.
        if result["status"] == "verified":
            assert all(s["verified"] for s in result["steps"]), path_id
        # Every blocked step must say why it was blocked.
        for step in result["steps"]:
            if step["status"] == "not_executable":
                assert step["reason"], f"{path_id} step {step['step_number']} has no reason"
                assert not step["verified"]

    # T1068 cannot be executed in a container lab, so no path may claim it.
    for path_id, result in data["results"].items():
        for step in result["steps"]:
            if step["evidence"]["technique"] == "T1068":
                assert not step["verified"], (
                    f"{path_id} claims T1068 verified — containers share the "
                    f"host kernel, so this cannot be genuine"
                )


def test_a_verified_path_has_every_step_executed():
    """db01 now has a second, container-executable route to root, so some paths
    can be proven end to end. A path may only claim `verified` when every step
    genuinely escalated — never when a step was merely skipped."""
    try:
        from fastapi.testclient import TestClient
    except ImportError:
        raise Skip("fastapi not installed")
    sys.path.insert(0, str(ROOT / "service"))
    import main
    client = TestClient(main.app)
    client.post("/api/reset")

    resp = client.post("/api/verify")
    if resp.status_code == 503:
        raise Skip("lab not running (bash lab/up.sh)")
    data = resp.json()

    for path_id, result in data["results"].items():
        if result["status"] != "verified":
            continue
        assert result["overall_verified"] is True, path_id
        assert result["steps_verified"] == result["steps_total"], path_id
        for step in result["steps"]:
            assert step["verified"], f"{path_id} step {step['step_number']}"
            assert step["status"] == "escalated", f"{path_id} step {step['step_number']}"
        assert not result["not_executable"], path_id

    summary = data["summary"]
    assert summary["paths_verified"] + summary["paths_partial"] + \
        summary["paths_failed"] == summary["paths_tested"]


def test_telemetry_is_not_fabricated():
    """telemetry.py is a stub, so the evidence must say so rather than printing
    a plausible-looking auditd line that nothing produced."""
    try:
        from fastapi.testclient import TestClient
    except ImportError:
        raise Skip("fastapi not installed")
    sys.path.insert(0, str(ROOT / "service"))
    import main
    client = TestClient(main.app)
    resp = client.post("/api/verify")
    if resp.status_code == 503:
        raise Skip("lab not running")
    for result in resp.json()["results"].values():
        for step in result["steps"]:
            telemetry = step["evidence"]["telemetry"]
            assert "not captured" in telemetry, telemetry

if __name__ == "__main__":
    sys.exit(main())

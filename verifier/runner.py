"""Core run loop — the reset → run → decide → record state machine.

The runner is ignorant of technique details; it delegates to adapters via the
registry in ``verifier.adapters``.  Two things it guarantees:

1. Every run starts clean and unprivileged.  The ``id -u != 0`` assertion
   catches a mis-planted scenario before it produces a garbage positive.
2. The label comes from the adapter's ``signal.py`` verdict, nothing else.
"""

from __future__ import annotations

import random
import uuid

from verifier.adapters import RunContext, get as get_adapter
from verifier.lab import (
    canary_token,
    container_image_digest,
    exec_as,
    reset,
)
from verifier.outcomes import Outcome, append
from verifier.scope import Scope
from verifier.telemetry import capture


# ── Scenario definitions ─────────────────────────────────────────────────────
# The batch matrix iterates these.  Each scenario produces a different class
# of label.  See the implementation spec §9 for the rationale.

SCENARIOS = [
    "full_chain",          # foothold → escalate → move → crown jewel
    "local_objective",     # escalate on the same host, no movement
]

# These require additional lab planting that may not yet exist:
#   "early_stop"           — foothold only, nothing further
#   "failed_escalation"    — attempt a technique planted to fail
#   "benign_lookalike"     — a legitimate admin SSH between hosts
#   "background"           — ordinary user/app traffic, no technique


def run_one(
    host: str,
    start_user: str,
    technique: dict,
    scenario: str,
    scope: Scope,
    *,
    seed: int = 0,
    output_path: str = "outcomes.jsonl",
    do_reset: bool = True,
) -> Outcome:
    """Execute one (host, technique, scenario) cell and record the outcome.

    This is the inner loop of both ``run_matrix`` (batch) and
    ``verify_path`` (live demo Verify button).
    """
    run_id = uuid.uuid4().hex[:12]

    # 1. Reset to clean state
    if do_reset:
        reset(host, mode=scope.reset_mode, compose_file=scope.compose_file,
              prefix=scope.container_prefix)

    # 2. Guard: start_user must be unprivileged
    code, out, _ = exec_as(
        host, start_user, ["id", "-u"], prefix=scope.container_prefix,
    )
    if out.strip() == "0":
        raise RuntimeError(
            f"start_user {start_user!r} on {host} is already root — "
            f"the label would be meaningless"
        )

    # 3. Get the expected canary token
    token = canary_token(host, scope.canary_path, prefix=scope.container_prefix)

    # 4. Build adapter context and run
    ctx = RunContext(
        host=host,
        start_user=start_user,
        technique=technique,
        canary_token=token,
        canary_path=scope.canary_path,
        run_id=run_id,
        container_prefix=scope.container_prefix,
    )

    with capture(run_id, host) as cap:
        adapter = get_adapter(technique["adapter"])
        result = adapter(ctx)

    # 5. Build and persist outcome
    outcome = Outcome(
        run_id=run_id,
        host=host,
        technique=technique["id"],
        scenario=scenario,
        escalated=result.escalated,
        evidence=result.evidence,
        raw_cmd=result.raw_cmd,
        telemetry_path=cap.path,
        seed=seed,
        lab_image_digest=container_image_digest(host, prefix=scope.container_prefix),
    )
    append(outcome, path=output_path)
    return outcome


def run_matrix(
    scope: Scope,
    *,
    seed: int = 1337,
    repeats: int = 20,
    output_path: str = "outcomes.jsonl",
) -> list[Outcome]:
    """Run the full batch matrix: every (host, technique, scenario) × repeats.

    Returns all outcomes.  At ~10-15s per run this can take hours for the
    full matrix — run it overnight with a fixed seed for reproducibility.
    """
    random.seed(seed)
    outcomes: list[Outcome] = []

    for tech in scope.techniques:
        for host in tech.hosts:
            for scenario in SCENARIOS:
                for rep in range(repeats):
                    print(
                        f"  [{tech.id}] {host}/{scenario} "
                        f"rep {rep + 1}/{repeats}...",
                        end=" ",
                        flush=True,
                    )
                    try:
                        o = run_one(
                            host=host,
                            start_user=tech.start_user,
                            technique=tech.raw,
                            scenario=scenario,
                            scope=scope,
                            seed=seed,
                            output_path=output_path,
                        )
                        outcomes.append(o)
                        tag = "PASS" if o.escalated else "FAIL"
                        print(tag)
                    except Exception as exc:
                        print(f"ERROR: {exc}")

    return outcomes


def verify_path(
    path_edges: list[dict],
    scope: Scope,
    *,
    output_path: str = "outcomes.jsonl",
) -> dict:
    """Live-verify a single enumerated path (the demo Verify button).

    *path_edges* is a list of dicts, each with ``host``, ``start_user``, and
    ``technique_id``.  Runs each edge's technique in order; a path verifies
    only if every edge escalates.
    """
    edges = []
    for edge in path_edges:
        tech = scope.technique(edge["technique_id"])
        o = run_one(
            host=edge["host"],
            start_user=edge.get("start_user", tech.start_user),
            technique=tech.raw,
            scenario="live",
            scope=scope,
            output_path=output_path,
        )
        edges.append({
            "edge": edge,
            "escalated": o.escalated,
            "run_id": o.run_id,
            "evidence": o.evidence,
        })
        if not o.escalated:
            break   # path is broken here; downstream edges unproven

    verified = (
        all(e["escalated"] for e in edges)
        and len(edges) == len(path_edges)
    )
    return {"verified": verified, "edges": edges}

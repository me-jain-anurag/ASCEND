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

from verifier.adapters import NOT_EXECUTABLE, RunContext, get as get_adapter
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
    overrides: dict | None = None,
) -> Outcome:
    """Execute one (host, technique, scenario) cell and record the outcome.

    This is the inner loop of both ``run_matrix`` (batch) and
    ``verify_path`` (live demo Verify button).

    *overrides* are per-run technique fields merged over the scope.yaml entry.
    They exist because one scope entry can describe a technique that appears
    several times in a path with different parameters: the lab's two SSH hops
    (web01 -> app01 and app01 -> db01) are both "T1021.004+T1550", and without
    per-edge overrides the second hop would re-run the first hop's parameters
    and report a leg as verified that was never tested.

    Overrides may only fill in technique PARAMETERS. The adapter, the check and
    the host allow-list still come from scope.yaml, so an override can never
    widen what the verifier is permitted to do.
    """
    run_id = uuid.uuid4().hex[:12]

    if overrides:
        protected = {"id", "adapter", "check", "hosts"}
        rejected = protected & set(overrides)
        if rejected:
            raise ValueError(
                f"overrides may not change {sorted(rejected)} — those define "
                f"what the verifier is allowed to run and come from scope.yaml"
            )
        technique = {**technique, **overrides}

    # 1. Reset to clean state
    if do_reset:
        reset(host, mode=scope.reset_mode, compose_file=scope.compose_file,
              prefix=scope.container_prefix)

    # 2. Guard: for a PRIVILEGE-ESCALATION technique the starting account must
    #    be unprivileged, or the label is meaningless — "escalated to root" is
    #    trivially true if you began as root.
    #
    #    It does not apply to lateral movement. There the question is whether a
    #    credential opens a session on another host, and an attacker who already
    #    took root on the current host is a legitimate, common starting state.
    #    Applying the guard there rejected a real path: on path-03 the attacker
    #    escalates on app01 and only then hops to db01.
    if technique.get("requires_unprivileged_start", True):
        code, out, _ = exec_as(
            host, start_user, ["id", "-u"], prefix=scope.container_prefix,
        )
        if out.strip() == "0":
            raise RuntimeError(
                f"start_user {start_user!r} on {host} is already root — "
                f"the label for {technique.get('id', 'this technique')} "
                f"would be meaningless"
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
        status=result.status,
        reason=result.reason,
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
    do_reset: bool = False,
) -> dict:
    """Live-verify a single enumerated path (the demo Verify button).

    *path_edges* is a list of dicts with ``host``, ``start_user``,
    ``technique_id``, and an optional ``params`` dict of per-edge technique
    overrides (see :func:`run_one`).

    A path has three possible verdicts, and the distinction matters:

    ``verified``   every edge ran and escalated.
    ``failed``     an edge ran and did not escalate — a real negative result.
    ``partial``    every edge that could be attempted escalated, but at least
                   one could not be attempted in this lab at all. The path is
                   NOT verified; neither has it been shown not to work.

    Without ``partial`` the lab's own limitations would be reported as evidence
    against the attack path, which is a different and false claim.

    Reset defaults to off here: the demo re-verifies interactively and a
    recreate per edge would take the button out of demo timing. The batch
    matrix, which produces training labels, always resets.
    """
    edges = []
    for edge in path_edges:
        tech = scope.technique(edge["technique_id"])
        outcome = run_one(
            host=edge["host"],
            start_user=edge.get("start_user", tech.start_user),
            technique=tech.raw,
            scenario="live",
            scope=scope,
            output_path=output_path,
            do_reset=do_reset,
            overrides=edge.get("params"),
        )
        edges.append({
            "edge": edge,
            "escalated": outcome.escalated,
            "status": outcome.status,
            "reason": outcome.reason,
            "run_id": outcome.run_id,
            "evidence": outcome.evidence,
        })
        # Stop on a genuine failure: downstream edges start from a foothold the
        # attacker never obtained, so running them would prove nothing. A
        # not_executable edge stops the walk for the same reason.
        if not outcome.escalated:
            break

    attempted = [e for e in edges if e["status"] != NOT_EXECUTABLE]
    blocked = [e for e in edges if e["status"] == NOT_EXECUTABLE]
    complete = len(edges) == len(path_edges)

    if complete and all(e["escalated"] for e in edges):
        status = "verified"
    elif blocked and all(e["escalated"] for e in attempted):
        status = "partial"
    else:
        status = "failed"

    return {
        "verified": status == "verified",
        "status": status,
        "edges": edges,
        "edges_total": len(path_edges),
        "edges_escalated": sum(1 for e in edges if e["escalated"]),
        "not_executable": [
            {"technique_id": e["edge"]["technique_id"], "reason": e["reason"]}
            for e in blocked
        ],
    }

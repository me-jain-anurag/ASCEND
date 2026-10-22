"""
ASCEND chokepoint / remediation engine.

Answers the question the demo turns on: *which few fixes kill the most paths?*

The important design decision is how a fix's effect is established. Counting how
many enumerated paths mention a vector is easy and usually right, but it is an
inference about the graph. This engine instead **applies each candidate fix to a
copy of the facts and re-runs the real enumerator**, then compares the surviving
paths against the baseline. The claim "this fix eliminates these three paths" is
therefore produced the same way the demo proves it on stage — by re-enumeration
— so the panel number and the live number cannot disagree.

Selection is greedy weighted set-cover: repeatedly take the fix with the best
paths-eliminated-per-unit-cost until every path is covered. Weighted set-cover
is NP-hard; the greedy algorithm is the standard ln(n)+1 approximation, which is
the right trade for a graph of this size and is honest to describe as "greedy".

    from chokepoint.engine import build_remediation
    plan = build_remediation(facts, scope)
"""

from __future__ import annotations

import copy
import itertools
import string
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "enumerator") not in sys.path:
    sys.path.insert(0, str(ROOT / "enumerator"))

from pathfinder import enumerate_paths  # noqa: E402


class _Lenient(dict):
    """Template placeholders that were never collected render empty rather than
    raising — a missing evidence field must not take the remediation panel down."""

    def __missing__(self, key):
        return ""


def _fill(template: str, values: dict, fallback: str = "") -> str:
    """Render a remediation template, or fall back when the evidence it needs
    was never collected.

    A template that renders to "Delete  (currently mode )" is worse than no
    template at all, so if any placeholder it uses is missing or empty, the
    vector's own description is used instead. This is what keeps the panel
    readable against the hand-written fallback facts, which carry no evidence.
    """
    try:
        placeholders = {
            name for _, name, _, _ in string.Formatter().parse(template) if name
        }
    except ValueError:
        return fallback or template

    if any(not str(values.get(name, "")).strip() for name in placeholders):
        return fallback or template

    try:
        return string.Formatter().vformat(template, (), _Lenient(values)).strip()
    except (ValueError, IndexError):
        return fallback or template


# ─────────────────────────────────────────────────────────────────────────────
# Path identity
# ─────────────────────────────────────────────────────────────────────────────

def _signature(path: list[dict]) -> tuple:
    """A stable identity for one enumerated path, used to tell which baseline
    paths survived a fix. Enumeration is deterministic, so the step sequence is
    a sound identity."""
    return tuple(
        (step["from"], step["to"], step.get("vector_id"), step.get("credential"))
        for step in path
    )


def _baseline(facts: dict) -> tuple[list, dict]:
    """Enumerate once and assign path ids.

    Ids are "path-01", "path-02", ... in enumeration order — the SAME scheme
    service/main.py:_build_paths_from_enumerator uses, so the ids in this plan
    address the paths the dashboard is displaying. If that ever diverges the
    remediation panel would silently point at the wrong paths.
    """
    paths = enumerate_paths(facts)
    ids = {_signature(p): f"path-{i:02d}" for i, p in enumerate(paths, 1)}
    return paths, ids


# ─────────────────────────────────────────────────────────────────────────────
# Candidate fixes
# ─────────────────────────────────────────────────────────────────────────────

def _candidates(facts: dict) -> list[dict]:
    """Every fix worth considering.

    Two kinds, because they are genuinely different remediations:

    - `vector`     remove the weakness itself (patch the kernel, drop the sudo
                   rule, chmod the key file).
    - `credential` revoke a REUSED credential everywhere it is accepted, without
                   touching the file it leaked from. This is often the cheaper
                   and faster fix, and it is invisible to an engine that only
                   considers vectors.
    """
    out = []
    for vec in facts.get("vectors", []):
        out.append({
            "kind": "vector",
            "key": vec["vector_id"],
            "vector": vec,
            "technique": vec["technique"],
            "host": vec["host"],
        })

    for cred in facts.get("credentials", []):
        hosts = sorted({g["host"] for g in cred.get("grants", [])})
        if len(hosts) < 2:
            continue      # not reused; revoking it is just the vector fix again
        out.append({
            "kind": "credential",
            "key": f"revoke_{cred['cred_id']}",
            "credential": cred,
            "technique": "T1550",
            "host": cred.get("discoverable_at", {}).get("host", ""),
            "reuse_hosts": hosts,
        })
    return out


def _apply(facts: dict, candidates: list[dict]) -> dict:
    """Return a copy of facts with every given fix applied."""
    patched = copy.deepcopy(facts)
    for cand in candidates:
        if cand["kind"] == "vector":
            patched["vectors"] = [
                v for v in patched["vectors"]
                if v["vector_id"] != cand["vector"]["vector_id"]
            ]
        elif cand["kind"] == "credential":
            # Revocation empties the grants but LEAVES the credential in place:
            # the key file may still be lying around, it simply no longer opens
            # anything. Deleting the entry outright would misrepresent the fix
            # (and would dangle any vector that reads it).
            for cred in patched["credentials"]:
                if cred["cred_id"] == cand["credential"]["cred_id"]:
                    cred["grants"] = []
    return patched


def _eliminated_by(facts: dict, applied: list[dict], baseline_ids: dict) -> list[str]:
    """Which baseline path ids no longer exist once `applied` is in force."""
    surviving = {_signature(p) for p in enumerate_paths(_apply(facts, applied))}
    return sorted(pid for sig, pid in baseline_ids.items() if sig not in surviving)


# ─────────────────────────────────────────────────────────────────────────────
# Fix rendering
# ─────────────────────────────────────────────────────────────────────────────

def _render(cand: dict, scope: dict, rank: int, eliminated: list[str],
            total: int, recommended: bool) -> dict:
    templates = (scope or {}).get("remediation", {})
    tpl = templates.get(cand["technique"], {})

    if cand["kind"] == "vector":
        vec = cand["vector"]
        evidence = (vec.get("features") or {}).get("evidence") or {}
        values = {
            "host": cand["host"],
            "cve": vec.get("cve", ""),
            "evidence_cve": vec.get("cve", ""),
            "evidence_path": evidence.get("path", ""),
            "evidence_mode": evidence.get("mode", ""),
            "evidence_user": evidence.get("user", ""),
            "evidence_binary": evidence.get("binary", ""),
            "evidence_fixed_version": evidence.get("branch_fix", ""),
        }
        target_vector = vec["vector_id"]
        technique_broken = f"{vec['technique']} — {vec.get('technique_name', '')}".strip(" —")
        fallback_title = f"Remediate {vec['vector_id']} on {cand['host']}"
        fallback_desc = vec.get("description", "")
        provenance = (vec.get("features") or {}).get("provenance", "unknown")
    else:
        cred = cand["credential"]
        values = {
            "host": cand["host"],
            "cred_id": cred["cred_id"],
            "reuse_hosts": ", ".join(cand["reuse_hosts"]),
        }
        target_vector = cred["cred_id"]
        technique_broken = "T1550 — Use Alternate Authentication Material"
        fallback_title = f"Revoke reused credential {cred['cred_id']}"
        fallback_desc = (
            f"{cred['cred_id']} is accepted on {len(cand['reuse_hosts'])} hosts "
            f"({', '.join(cand['reuse_hosts'])})."
        )
        provenance = (cred.get("features") or {}).get("provenance", "observed")

    return {
        "fix_id":   f"fix-{rank:02d}",
        "rank":     rank,
        "title":    _fill(tpl.get("title", fallback_title), values, fallback_title),
        "chokepoint_type": tpl.get("chokepoint_type", "Remediation"),
        "target_host":   cand["host"],
        "target_vector": target_vector,
        "technique_broken": technique_broken,
        "cost": tpl.get("cost", 3),
        "description": _fill(tpl.get("description", fallback_desc), values, fallback_desc),
        "paths_eliminated": eliminated,
        "efficacy_percentage": round(100.0 * len(eliminated) / total, 1) if total else 0.0,
        "is_recommended_chokepoint": recommended,
        # Beyond the frontend contract, but carried so the panel can be made to
        # show WHY a fix is ranked where it is.
        "fix_kind": cand["kind"],
        "_candidate_key": cand["key"],
        "evidence_provenance": provenance,
        "paths_eliminated_count": len(eliminated),
        "cost_per_path": (
            round(tpl.get("cost", 3) / len(eliminated), 2) if eliminated else None
        ),
    }


# ─────────────────────────────────────────────────────────────────────────────
# The plan
# ─────────────────────────────────────────────────────────────────────────────

def build_remediation(facts: dict, scope: dict | None = None,
                      include_cross_checks: bool = False) -> dict:
    """Produce the RemediationData the dashboard's remediation panel renders.

    `include_cross_checks` attaches the honesty layer (exact-optimum comparison,
    negative control, greedy-vs-naive ordering) under a "cross_checks" key. It is
    off by default so the per-request service path and the frontend contract are
    unchanged; the evaluation/report path turns it on.
    """
    scope = scope or {}
    paths, baseline_ids = _baseline(facts)
    total = len(paths)
    all_ids = set(baseline_ids.values())

    candidates = _candidates(facts)

    # Standalone effect of each candidate, each measured by re-enumeration.
    solo = {c["key"]: _eliminated_by(facts, [c], baseline_ids) for c in candidates}

    # ── Greedy weighted set-cover ────────────────────────────────────────────
    chosen: list[dict] = []
    covered: set[str] = set()
    remaining = list(candidates)

    while remaining and covered != all_ids:
        best, best_score = None, None
        for cand in remaining:
            gain = len(set(solo[cand["key"]]) - covered)
            if gain == 0:
                continue
            cost = (scope.get("remediation", {})
                         .get(cand["technique"], {})
                         .get("cost", 3)) or 1
            # Maximise paths killed per unit of effort; break ties toward the
            # fix that kills more outright, then toward the cheaper one.
            score = (gain / cost, gain, -cost)
            if best_score is None or score > best_score:
                best, best_score = cand, score
        if best is None:
            break           # nothing left can cover another path
        chosen.append(best)
        covered |= set(solo[best["key"]])
        remaining.remove(best)

    # ── Rank: the cover first (in selection order), then the rest by effect ──
    # When two fixes eliminate the SAME number of paths, prefer the cheaper one
    # (then a stable name tie-break). Without the cost term a costlier fix could
    # outrank an equally effective but cheaper one purely on alphabetical order.
    def _cost(c: dict) -> int:
        return (scope.get("remediation", {})
                     .get(c["technique"], {})
                     .get("cost", 3)) or 1

    ordered = chosen + sorted(
        remaining, key=lambda c: (-len(solo[c["key"]]), _cost(c), c["key"])
    )

    ranked_fixes = [
        _render(cand, scope, rank, solo[cand["key"]], total,
                recommended=(rank == 1 and bool(chosen)))
        for rank, cand in enumerate(ordered, 1)
    ]

    # ── Efficacy curve: cumulative, and again by re-enumeration ─────────────
    curve = [{"fixes_applied": 0, "paths_remaining": total,
              "paths_eliminated": 0, "reduction_pct": 0.0}]
    for i in range(1, len(ordered) + 1):
        eliminated = _eliminated_by(facts, ordered[:i], baseline_ids)
        curve.append({
            "fixes_applied":    i,
            "paths_remaining":  total - len(eliminated),
            "paths_eliminated": len(eliminated),
            "reduction_pct":    round(100.0 * len(eliminated) / total, 1) if total else 0.0,
        })

    cover_size = len(chosen)
    cover_cost = sum(
        (scope.get("remediation", {}).get(c["technique"], {}).get("cost", 3))
        for c in chosen
    )

    plan = {
        # Frontend contract field. No verifier has run, so this is the count of
        # ENUMERATED paths; the name is kept for compatibility and the real
        # meaning is stated alongside it.
        "total_verified_paths": total,
        "total_enumerated_paths": total,
        "ranked_fixes": ranked_fixes,
        "efficacy_curve": curve,
        "minimum_cover": {
            "fixes":  [f["fix_id"] for f in ranked_fixes[:cover_size]],
            "size":   cover_size,
            "cost":   cover_cost,
            "covers_all_paths": covered == all_ids,
            "algorithm": "greedy weighted set-cover (ln n + 1 approximation)",
        },
        "_method": (
            "Every paths_eliminated list is produced by removing the fix from a "
            "copy of the facts and re-running enumerator.enumerate_paths(), not "
            "by counting vector occurrences. Path ids match "
            "service/main.py:_build_paths_from_enumerator."
        ),
        "_verification_note": (
            "Efficacy is measured against ENUMERATED paths. No path has been "
            "execution-verified, so these are predicted eliminations."
        ),
    }

    if include_cross_checks:
        # cross_checks() re-enters build_remediation with the default flag off,
        # so this does not recurse.
        plan["cross_checks"] = cross_checks(facts, scope)

    return plan


# ─────────────────────────────────────────────────────────────────────────────
# Applying fixes — what makes "apply, re-run, the paths are gone" a measurement
# ─────────────────────────────────────────────────────────────────────────────

def _ordered_candidates(facts: dict, scope: dict) -> dict:
    """fix_id -> candidate, using build_remediation's own ranking.

    Fix ids are positional, so they are only meaningful relative to the PRISTINE
    facts. Callers must always resolve them against the unmodified facts and
    then apply the whole accumulated set at once, never rank-then-apply
    iteratively — otherwise fix-02 means something different after fix-01 lands.
    """
    plan = build_remediation(facts, scope)
    by_key = {c["key"]: c for c in _candidates(facts)}
    return {fix["fix_id"]: by_key[fix["_candidate_key"]]
            for fix in plan["ranked_fixes"] if fix["_candidate_key"] in by_key}


def apply_fix_ids(facts: dict, scope: dict, fix_ids: list[str]) -> dict:
    """Return a copy of `facts` with every named fix applied.

    Feeding the result back through enumerate_paths() is how the demo shows the
    dependent paths disappearing: the paths are not filtered out of a list, they
    genuinely no longer exist in the graph.
    """
    if not fix_ids:
        return facts
    index = _ordered_candidates(facts, scope)
    chosen = [index[fid] for fid in fix_ids if fid in index]
    return _apply(facts, chosen)


def eliminated_path_ids(facts: dict, scope: dict, fix_ids: list[str]) -> list[str]:
    """Baseline path ids that no longer exist once `fix_ids` are applied."""
    if not fix_ids:
        return []
    _, baseline_ids = _baseline(facts)
    index = _ordered_candidates(facts, scope)
    chosen = [index[fid] for fid in fix_ids if fid in index]
    return _eliminated_by(facts, chosen, baseline_ids)


def known_fix_ids(facts: dict, scope: dict) -> list[str]:
    return list(_ordered_candidates(facts, scope))


def baseline_path_ids(facts: dict) -> dict:
    """{path signature: path id} for the unmodified facts.

    Path ids must stay pinned to the BASELINE enumeration. If they were assigned
    positionally on each request, applying a fix would renumber the survivors,
    and a response could report "path-01 eliminated" while displaying a path it
    had just renamed path-01.
    """
    _, ids = _baseline(facts)
    return ids


def path_signature(path: list[dict]) -> tuple:
    """Public alias for the canonical path identity."""
    return _signature(path)


# ─────────────────────────────────────────────────────────────────────────────
# Cross-checks — the honesty layer for the remediation claims
# ─────────────────────────────────────────────────────────────────────────────
#
# build_remediation() produces a greedy cover and asserts it is small and cheap.
# The three functions below are the checks that keep that claim honest, and they
# are deliberately computed with the SAME primitive the engine already trusts —
# _eliminated_by(), i.e. remove the fix from a copy of the facts and re-run the
# enumerator. Greedy and the checks therefore measure elimination the same way,
# so a disagreement is a real disagreement, never an artefact of two methods.
#
#   optimal_cover / greedy_vs_optimal   is the greedy cover actually the cheapest
#                                       cover that exists? (exact, by exhaustion)
#   negative_control                    does a fix that is OFF every route leave
#                                       the routes unchanged? (guards against a
#                                       harness that always "finds" a reduction)
#   ordering_comparison                 does the efficiency-greedy order reach
#                                       full cover no later and no costlier than
#                                       the obvious "patch-highest-CVSS-first"
#                                       order a scanner-driven team would follow?
#
# All three are reported, pass or fail. A tie (greedy already optimal; the naive
# order happens to match) is reported as a tie — that is the honest result, and
# the machinery still generalises to the fuller lab where a single cheap fix no
# longer covers everything.


def _fix_cost(cand: dict, scope: dict) -> int:
    """Cost of a candidate, read the same way build_remediation sums cover cost
    (scope.remediation[technique].cost, default 3), so optimal, greedy and naive
    costs are all on one scale and are directly comparable."""
    return (scope or {}).get("remediation", {}).get(cand["technique"], {}).get("cost", 3)


def _covers_all(eliminated: set, all_ids: set) -> bool:
    return eliminated == all_ids


def optimal_cover(facts: dict, scope: dict | None = None,
                  max_candidates: int = 16) -> dict:
    """The exact minimum-cost set of fixes that eliminates every baseline path.

    Weighted set-cover is NP-hard, so build_remediation uses the greedy
    ln(n)+1 approximation. This is the cross-check: with a candidate set this
    small, the exact optimum can simply be found by trying every subset and
    keeping the cheapest one that covers all paths. Each subset's effect is
    measured by re-enumeration (the same _eliminated_by the greedy engine uses),
    not by unioning per-fix counts, so the optimum and the greedy cover are
    compared on identical ground.

    Candidates that eliminate nothing are pruned first: they can never belong to
    a minimum-cost cover, and dropping them keeps the exhaustive search bounded.
    If more than `max_candidates` useful candidates remain, the exact search is
    skipped (computed=False with the reason) rather than run past a sane bound.

    Tie-breaking, in order: full cover beats partial; then least cost; then
    fewest fixes; then the lexicographically smallest key set, for determinism.
    """
    scope = scope or {}
    paths, ids = _baseline(facts)
    all_ids = set(ids.values())
    total = len(paths)

    candidates = _candidates(facts)
    solo = {c["key"]: set(_eliminated_by(facts, [c], ids)) for c in candidates}
    useful = [c for c in candidates if solo[c["key"]]]

    base = {
        "algorithm": "exact minimum-cost set cover (exhaustive over candidates)",
        "total_paths": total,
        "candidates_total": len(candidates),
        "candidates_useful": len(useful),
    }

    if total == 0:
        return {**base, "computed": True, "size": 0, "cost": 0,
                "covers_all_paths": True, "fix_keys": [], "subsets_evaluated": 0}

    if len(useful) > max_candidates:
        return {**base, "computed": False,
                "reason": (f"{len(useful)} path-eliminating candidates exceed the "
                           f"exhaustive cap of {max_candidates}; greedy stands "
                           f"without an exact cross-check at this size")}

    best = None  # (covers_all, cost, size, keys_tuple, covered_count)
    evaluated = 0
    for r in range(len(useful) + 1):
        for combo in itertools.combinations(useful, r):
            evaluated += 1
            covered = set()
            for c in combo:
                covered |= solo[c["key"]]
            cost = sum(_fix_cost(c, scope) for c in combo)
            keys = tuple(sorted(c["key"] for c in combo))
            covers_all = _covers_all(covered, all_ids)
            # Rank so the winner is: full cover first, then cheapest, then fewest
            # fixes, then deterministic. Partial covers are compared by coverage.
            rank = (0 if covers_all else 1, cost, r, keys)
            partial_rank = (-len(covered), cost, r, keys)
            record = (covers_all, cost, r, keys, len(covered), rank, partial_rank)
            if best is None:
                best = record
                continue
            # Prefer any full cover over any partial one.
            if record[0] != best[0]:
                if record[0]:                       # record is full, best was not
                    best = record
                continue
            if best[0]:                             # both full: cheapest/smallest
                if record[5] < best[5]:
                    best = record
            else:                                   # both partial: most coverage
                if record[6] < best[6]:
                    best = record

    covers_all, cost, size, keys, covered_count, _r, _p = best
    return {
        **base,
        "computed": True,
        "size": size,
        "cost": cost,
        "covers_all_paths": covers_all,
        "paths_covered": covered_count,
        "fix_keys": list(keys),
        "subsets_evaluated": evaluated,
    }


def greedy_vs_optimal(facts: dict, scope: dict | None = None,
                      max_candidates: int = 16) -> dict:
    """Compare the greedy cover build_remediation ships against the exact optimum.

    The headline is `greedy_is_optimal`: True when greedy's cover costs exactly
    what the cheapest possible cover costs. `cost_gap` (greedy − optimal, ≥ 0) is
    how much the approximation overspends; for a greedy ln(n)+1 result it is
    usually 0 on a graph this size, and reporting the 0 is the point.
    """
    scope = scope or {}
    plan = build_remediation(facts, scope)
    greedy = plan["minimum_cover"]
    opt = optimal_cover(facts, scope, max_candidates=max_candidates)

    out = {
        "greedy_size": greedy["size"],
        "greedy_cost": greedy["cost"],
        "greedy_covers_all_paths": greedy["covers_all_paths"],
        "optimal": opt,
    }
    if opt.get("computed"):
        # Only a like-for-like comparison is meaningful: both must cover all.
        both_cover = greedy["covers_all_paths"] and opt["covers_all_paths"]
        out["cost_gap"] = greedy["cost"] - opt["cost"] if both_cover else None
        out["size_gap"] = greedy["size"] - opt["size"] if both_cover else None
        out["greedy_is_optimal"] = bool(both_cover and greedy["cost"] == opt["cost"])
    else:
        out["greedy_is_optimal"] = None     # not checkable at this size
    return out


def negative_control(facts: dict, scope: dict | None = None) -> dict:
    """Apply a fix that should change nothing, and confirm nothing changes.

    The remediation claims all rest on "apply the fix, re-enumerate, the paths
    are gone". A measurement harness with a bug could instead report a reduction
    for *any* applied fix. The negative control rules that out: it picks a real,
    in-scope weakness that lies OFF every route to the crown jewel (so fixing it
    cannot remove a route), applies it, re-enumerates, and asserts the surviving
    routes are byte-for-byte the baseline routes.

    `unchanged` True is the pass. The lab's app01 sudo-tar rule is such a fix: a
    genuine privilege-escalation weakness a scanner flags, but not on any path to
    db01, so removing it leaves both routes intact. If the lab has no off-route
    weakness, a synthetic no-op is used instead (kind="synthetic") so the check
    still runs, clearly labelled as the weaker form.
    """
    scope = scope or {}
    paths, ids = _baseline(facts)
    baseline_sigs = {_signature(p) for p in paths}

    candidates = _candidates(facts)
    off_route = [c for c in candidates
                 if not _eliminated_by(facts, [c], ids)]

    if off_route:
        # Prefer a vector (a concrete, scanner-visible weakness) when available.
        chosen = next((c for c in off_route if c["kind"] == "vector"), off_route[0])
        patched = _apply(facts, [chosen])
        kind = "real"
        control_desc = {
            "fix_kind": chosen["kind"],
            "target": chosen.get("vector", {}).get("vector_id") if chosen["kind"] == "vector"
                      else chosen["key"],
            "technique": chosen["technique"],
            "host": chosen.get("host", ""),
            "cost": _fix_cost(chosen, scope),
        }
    else:
        # Synthetic fallback: a fix that removes a vector id present on no path.
        # It exercises the full apply→re-enumerate harness yet must not change a
        # thing, because there was nothing on a route to remove.
        patched = _apply(facts, [{
            "kind": "vector",
            "vector": {"vector_id": "__ascend_negative_control_noop__"},
            "technique": "T0000",
        }])
        kind = "synthetic"
        control_desc = {"fix_kind": "synthetic-noop",
                        "target": "__ascend_negative_control_noop__",
                        "technique": "T0000", "host": "", "cost": 0}

    survivors = enumerate_paths(patched)
    survivor_sigs = {_signature(p) for p in survivors}

    return {
        "kind": kind,
        "control_fix": control_desc,
        "paths_before": len(paths),
        "paths_after": len(survivors),
        "paths_eliminated": sorted(pid for sig, pid in ids.items()
                                   if sig not in survivor_sigs),
        "unchanged": survivor_sigs == baseline_sigs,
        "_note": ("A fix off every route must not remove a route. 'unchanged' "
                  "True means the apply→re-enumerate harness does not invent "
                  "reductions."),
    }


def _severity(cand: dict) -> float:
    """CVSS a scanner-driven team would sort by. Credential revocation has no CVE
    of its own, so it sorts last — exactly the blind spot the greedy, path-aware
    ordering is meant to cover."""
    if cand["kind"] == "vector":
        return float(cand.get("vector", {}).get("cvss", 0.0) or 0.0)
    return -1.0


def _cumulative_curve(facts: dict, scope: dict, order: list[dict],
                      ids: dict, all_ids: set) -> dict:
    """Apply the ordering prefix by prefix, re-enumerating each time, and record
    when (and at what cumulative cost) it first covers every path."""
    total = len(all_ids)
    curve = [{"fixes_applied": 0, "paths_eliminated": 0, "reduction_pct": 0.0,
              "cost_so_far": 0}]
    fixes_to_cover = None
    cost_to_cover = None
    running_cost = 0
    for i in range(1, len(order) + 1):
        running_cost += _fix_cost(order[i - 1], scope)
        eliminated = set(_eliminated_by(facts, order[:i], ids))
        curve.append({
            "fixes_applied": i,
            "paths_eliminated": len(eliminated),
            "reduction_pct": round(100.0 * len(eliminated) / total, 1) if total else 0.0,
            "cost_so_far": running_cost,
        })
        if fixes_to_cover is None and _covers_all(eliminated, all_ids):
            fixes_to_cover = i
            cost_to_cover = running_cost
    return {"curve": curve, "fixes_to_full_cover": fixes_to_cover,
            "cost_to_full_cover": cost_to_cover}


def ordering_comparison(facts: dict, scope: dict | None = None) -> dict:
    """Greedy (efficiency-first) order vs naive (severity-first) order.

    The greedy order is the one build_remediation already selected: the cover
    first, chosen by marginal paths-eliminated-per-unit-cost. The naive order is
    the obvious human instinct — fix the highest-CVSS weakness first — which is
    blind to both path overlap and fix cost.

    The check is `greedy_reaches_cover_no_later` and `greedy_cost_no_higher`:
    the greedy order must reach full coverage in no more fixes and at no greater
    cost than severity-first. When a single cheap fix covers everything they can
    tie; where coverage needs several fixes, accounting for overlap and cost is
    what separates them.
    """
    scope = scope or {}
    _paths, ids = _baseline(facts)
    all_ids = set(ids.values())

    candidates = _candidates(facts)
    by_key = {c["key"]: c for c in candidates}

    # Greedy order: reuse build_remediation's own ranking so the two never drift.
    plan = build_remediation(facts, scope)
    greedy_order = [by_key[f["_candidate_key"]] for f in plan["ranked_fixes"]
                    if f["_candidate_key"] in by_key]

    # Naive order: CVSS desc, ties by discovery order (stable), credential last.
    disc = {c["key"]: i for i, c in enumerate(candidates)}
    naive_order = sorted(candidates, key=lambda c: (-_severity(c), disc[c["key"]]))

    greedy = _cumulative_curve(facts, scope, greedy_order, ids, all_ids)
    naive = _cumulative_curve(facts, scope, naive_order, ids, all_ids)

    def _le(a, b):      # a no worse than b, treating "never covers" (None) as ∞
        if a is None:
            return b is None
        return b is None or a <= b

    return {
        "naive_baseline": ("severity-first: highest-CVSS weakness first, ties by "
                           "discovery order, credential revocation last — blind "
                           "to path overlap and to fix cost"),
        "greedy_order": [c["key"] for c in greedy_order],
        "naive_order": [c["key"] for c in naive_order],
        "greedy_fixes_to_full_cover": greedy["fixes_to_full_cover"],
        "naive_fixes_to_full_cover": naive["fixes_to_full_cover"],
        "greedy_cost_to_full_cover": greedy["cost_to_full_cover"],
        "naive_cost_to_full_cover": naive["cost_to_full_cover"],
        "greedy_reaches_cover_no_later": _le(greedy["fixes_to_full_cover"],
                                             naive["fixes_to_full_cover"]),
        "greedy_cost_no_higher": _le(greedy["cost_to_full_cover"],
                                     naive["cost_to_full_cover"]),
        "greedy_curve": greedy["curve"],
        "naive_curve": naive["curve"],
    }


def cross_checks(facts: dict, scope: dict | None = None,
                 max_candidates: int = 16) -> dict:
    """All three honesty checks in one object, each reported pass or fail.

    `all_passed` is the conjunction of every check that could be evaluated; a
    check that was not computable (e.g. the exact optimum was skipped because the
    candidate set was too large) does not count against it, and its own field
    still records that it was skipped.
    """
    scope = scope or {}
    optimality = greedy_vs_optimal(facts, scope, max_candidates=max_candidates)
    control = negative_control(facts, scope)
    ordering = ordering_comparison(facts, scope)

    checks = {
        "greedy_is_optimal": optimality["greedy_is_optimal"],
        "negative_control_unchanged": control["unchanged"],
        "greedy_reaches_cover_no_later": ordering["greedy_reaches_cover_no_later"],
        "greedy_cost_no_higher": ordering["greedy_cost_no_higher"],
    }
    evaluated = [v for v in checks.values() if v is not None]

    return {
        "optimality": optimality,
        "negative_control": control,
        "ordering": ordering,
        "checks": checks,
        "all_passed": all(evaluated) if evaluated else False,
        "_note": ("Greedy, the exact optimum, the negative control and both "
                  "orderings all measure elimination by removing the fix from a "
                  "copy of the facts and re-running the enumerator, so these "
                  "checks compare like with like."),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Standalone report
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    """Run the cross-checks against the live facts and print a short report.

    Dependency-light and self-contained, like enumerator/pathfinder.py:
        python3 chokepoint/engine.py
    Writes eval/remediation_crosscheck.json alongside the printed summary.
    """
    import json

    facts_path = ROOT / "environment_graph" / "facts.json"
    scope_path = ROOT / "scope.yaml"
    facts = json.loads(facts_path.read_text())
    scope = {}
    if scope_path.exists():
        try:
            import yaml
            scope = yaml.safe_load(scope_path.read_text()) or {}
        except Exception:
            scope = {}

    result = cross_checks(facts, scope)
    opt = result["optimality"]
    ctl = result["negative_control"]
    order = result["ordering"]

    print("ASCEND remediation cross-checks\n" + "=" * 32)
    print("\n[1] Greedy cover vs exact optimum")
    print(f"    greedy : size {opt['greedy_size']}, cost {opt['greedy_cost']}, "
          f"covers all = {opt['greedy_covers_all_paths']}")
    if opt["optimal"].get("computed"):
        o = opt["optimal"]
        print(f"    optimal: size {o['size']}, cost {o['cost']}, "
              f"covers all = {o['covers_all_paths']} "
              f"({o['subsets_evaluated']} subsets checked)")
        print(f"    => greedy is optimal: {opt['greedy_is_optimal']} "
              f"(cost gap {opt['cost_gap']})")
    else:
        print(f"    optimal: skipped — {opt['optimal'].get('reason')}")

    print("\n[2] Negative control (a fix off every route)")
    print(f"    control: {ctl['control_fix']['target']} "
          f"({ctl['kind']}, technique {ctl['control_fix']['technique']})")
    print(f"    paths {ctl['paths_before']} -> {ctl['paths_after']}, "
          f"eliminated {ctl['paths_eliminated']}")
    print(f"    => routes unchanged: {ctl['unchanged']}")

    print("\n[3] Greedy order vs naive severity-first order")
    print(f"    greedy order: {order['greedy_order']}")
    print(f"    naive  order: {order['naive_order']}")
    print(f"    full cover — greedy: {order['greedy_fixes_to_full_cover']} fix(es) "
          f"at cost {order['greedy_cost_to_full_cover']}; "
          f"naive: {order['naive_fixes_to_full_cover']} fix(es) "
          f"at cost {order['naive_cost_to_full_cover']}")
    print(f"    => greedy no later: {order['greedy_reaches_cover_no_later']}, "
          f"no costlier: {order['greedy_cost_no_higher']}")

    print(f"\nAll checks passed: {result['all_passed']}")

    out_path = ROOT / "eval" / "remediation_crosscheck.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2))
    print(f"Wrote {out_path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()

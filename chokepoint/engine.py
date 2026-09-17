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

def build_remediation(facts: dict, scope: dict | None = None) -> dict:
    """Produce the RemediationData the dashboard's remediation panel renders."""
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
    ordered = chosen + sorted(
        remaining, key=lambda c: (-len(solo[c["key"]]), c["key"])
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

    return {
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

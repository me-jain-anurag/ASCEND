#!/usr/bin/env python3
"""
ASCEND path enumerator.

Reads an environment-facts file and enumerates every privilege-escalation path
from the entry foothold to the crown jewel, labelling each edge with its MITRE
ATT&CK technique. Then runs the minimal chokepoint step: which single vector,
if removed, kills the most paths.

This is the REAL algorithm (a depth-first search over the attacker's
(host, privilege) state space, exactly as described in docs/04 "How does path
enumeration actually work?"). Only the input is small; the same code scales to
the collected facts of the full lab.

No third-party dependencies. Run:  python3 enumerator/pathfinder.py
Outputs:  eval/analysis.json  and  dashboard/data.js
"""

import json
import os
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FACTS = os.path.join(ROOT, "environment_graph", "facts.json")
ANALYSIS = os.path.join(ROOT, "eval", "analysis.json")
DATA_JS = os.path.join(ROOT, "dashboard", "data.js")

PRIV = {"low": 1, "root": 2}  # ordered privilege levels

MAX_DEPTH = 12     # longest path searched, in steps
MAX_PATHS = 1000   # stop searching once this many paths are found
COLLAPSE_MODES = ("none", "reorder", "minimal")
COLLAPSE = "minimal"  # report distinct routes, not every ordering of them


def node_label(host, priv):
    return f"{host}:{priv}"


def load_facts(path):
    with open(path) as f:
        return json.load(f)


def enumerate_paths(facts, max_depth=MAX_DEPTH, max_paths=MAX_PATHS, collapse=COLLAPSE):
    """The paths only. See search() for what the caps and collapse modes do."""
    return search(facts, max_depth, max_paths, collapse)[0]


def search(facts, max_depth=MAX_DEPTH, max_paths=MAX_PATHS, collapse=COLLAPSE):
    """DFS over attacker state. A state is (frozenset of (host, priv) controlled,
    frozenset of credential ids held). Returns (paths, stats); each path is an
    ordered list of steps {from, to, technique, technique_name, vector_id}.

    stats says what the search left out, so a path count can be trusted:
      cut_at_depth    branches abandoned at max_depth without reaching the goal
      hit_path_cap    True if the search stopped at max_paths; more may exist
      enumerated      paths found before collapsing
      merged_reorder  paths dropped as the same steps in a different order
      dropped_extra   paths dropped because a found path does the same with
                      fewer steps (a superset path has a step it never needed)

    collapse: "minimal" (the default) merges reorderings and drops superset
    paths, so each path is a distinct route with no unneeded step. "reorder"
    only merges reorderings; "none" keeps every raw ordering the DFS found.
    """
    if collapse not in COLLAPSE_MODES:
        raise ValueError(f"collapse must be one of {COLLAPSE_MODES}, got {collapse!r}")

    entry = facts["entry"]
    goal = facts["crown_jewel"]
    reach = {(r["from"], r["to"]) for r in facts["reachability"]}
    creds = {c["cred_id"]: c for c in facts["credentials"]}
    vectors = facts["vectors"]

    def controls(state, host, priv):
        want = PRIV[priv]
        return any(h == host and PRIV[p] >= want for (h, p) in state)

    def reachable(state, target_host):
        # attacker can reach target if any controlled host has a route to it
        return any((h, target_host) in reach for (h, _p) in state)

    start_state = (frozenset({(entry["host"], entry["privilege"])}), frozenset())
    goal_reached = lambda st: (goal["host"], goal["privilege"]) in st[0]

    paths = []
    stats = {"max_depth": max_depth, "max_paths": max_paths, "collapse": collapse,
             "cut_at_depth": 0, "hit_path_cap": False}

    def moves(state):
        """Yield every legal (step_dict, new_state) from the current state."""
        controlled, held = state

        # 1) HARVEST credentials from a readable file (T1552.001-style vectors)
        for v in vectors:
            if v["kind"] != "credential_access":
                continue
            req = v["requires"]
            if not controls(controlled, req["host"], req["privilege"]):
                continue
            cred_id = v["reads_credential"]
            if cred_id in held:
                continue
            step = {
                "from": node_label(req["host"], req["privilege"]),
                "to": f"cred:{cred_id}",
                "technique": v["technique"],
                "technique_name": v["technique_name"],
                "vector_id": v["vector_id"],
            }
            yield step, (controlled, held | {cred_id})

        # 2) MOVE laterally using a held credential (T1021.004 + T1550 reuse)
        for cred_id in held:
            cred = creds[cred_id]
            for grant in cred["grants"]:
                gh, gp = grant["host"], grant["privilege"]
                if (gh, gp) in controlled:
                    continue
                if not reachable(controlled, gh):
                    continue
                src = next(h for (h, _p) in controlled if (h, gh) in reach)
                step = {
                    "from": node_label(src, next(p for (h, p) in controlled if h == src)),
                    "to": node_label(gh, gp),
                    "technique": "T1021.004+T1550",
                    "technique_name": "Remote Services: SSH (reused credential)",
                    "vector_id": None,
                    "credential": cred_id,
                }
                yield step, (controlled | {(gh, gp)}, held)

        # 3) ESCALATE locally on a controlled host (sudo / SUID / kernel exploit)
        for v in vectors:
            if v["kind"] != "privilege_escalation_local":
                continue
            req = v["requires"]
            gains = v["gains"]
            if not controls(controlled, req["host"], req["privilege"]):
                continue
            if (gains["host"], gains["privilege"]) in controlled:
                continue
            step = {
                "from": node_label(req["host"], req["privilege"]),
                "to": node_label(gains["host"], gains["privilege"]),
                "technique": v["technique"],
                "technique_name": v["technique_name"],
                "vector_id": v["vector_id"],
            }
            yield step, (controlled | {(gains["host"], gains["privilege"])}, held)

    def dfs(state, trail, seen_states):
        if len(paths) >= max_paths:
            stats["hit_path_cap"] = True
            return
        if goal_reached(state):
            paths.append(list(trail))
            return
        if len(trail) >= max_depth:
            stats["cut_at_depth"] += 1
            return
        for step, new_state in moves(state):
            if new_state in seen_states:
                continue
            dfs(new_state, trail + [step], seen_states | {new_state})

    dfs(start_state, [], {start_state})
    stats["enumerated"] = len(paths)
    kept, stats["merged_reorder"], stats["dropped_extra"] = collapse_paths(paths, collapse)
    return kept, stats


def _action(step):
    """What a step does, independent of where it sits in the path. A lateral
    move's `from` label is left out: it names whichever controlled account the
    search happened to list first, not a different action."""
    return (step["to"], step["technique"], step.get("vector_id"), step.get("credential"))


def collapse_paths(paths, mode):
    """Returns (kept, merged_reorder, dropped_extra). Keeps the first path of each
    group, so the result stays deterministic and in search order."""
    if mode == "none":
        return list(paths), 0, 0
    kept, seen = [], set()
    for path in paths:
        actions = frozenset(_action(s) for s in path)
        if actions not in seen:
            seen.add(actions)
            kept.append((path, actions))
    merged = len(paths) - len(kept)
    if mode == "reorder":
        return [p for p, _ in kept], merged, 0
    minimal = [p for p, a in kept if not any(b < a for _, b in kept)]
    return minimal, merged, len(kept) - len(minimal)


def time_search(facts, runs=50, **kwargs):
    """Wall-clock enumeration time over repeated runs, in milliseconds. Covers
    the search only; verification time is reported separately by the verifier."""
    samples = []
    for _ in range(runs):
        start = time.perf_counter()
        search(facts, **kwargs)
        samples.append((time.perf_counter() - start) * 1000)
    samples.sort()

    def pct(q):
        return round(samples[min(len(samples) - 1, int(q * len(samples)))], 3)
    return {"runs": runs, "p50_ms": pct(0.50), "p95_ms": pct(0.95), "p99_ms": pct(0.99)}


def chokepoint(paths):
    """Convenience summary for the command-line report: how many paths each
    vector lies on.

    This is a COUNTER, not the remediation engine. It infers a fix's effect from
    the graph; chokepoint/engine.py measures it by removing the fix from a copy
    of the facts and re-running enumerate_paths(). The service and dashboard use
    the engine. This stays here so `python3 enumerator/pathfinder.py` gives a
    useful answer on its own, with no dependencies."""
    total = len(paths)
    counts = {}
    labels = {}
    for path in paths:
        seen = set()
        for step in path:
            vid = step.get("vector_id")
            if vid and vid not in seen:
                counts[vid] = counts.get(vid, 0) + 1
                labels[vid] = f'{step["technique"]} — {step["technique_name"]}'
                seen.add(vid)
    ranking = [
        {
            "vector_id": vid,
            "on_paths": n,
            "total_paths": total,
            "paths_eliminated_if_fixed": n,
            "technique": labels[vid],
        }
        for vid, n in sorted(counts.items(), key=lambda kv: -kv[1])
    ]
    return ranking


def build_graph(facts):
    """Nodes and edges for the dashboard network view.

    One node per host; privilege is shown as an annotation rather than as a
    separate node, because the dashboard draws a network, not the state space
    the search actually walks.
    """
    node_ids = set()
    edges = []
    for r in facts["reachability"]:
        for hid in (r["from"], r["to"]):
            node_ids.add(hid)
        edges.append({"source": r["from"], "target": r["to"], "kind": "reach",
                      "label": f'{r["service"]}/{r["port"]}'})
    host_meta = {h["hostname"]: h for h in facts["hosts"]}
    graph_nodes = []
    for hid in sorted(node_ids):
        m = host_meta.get(hid, {})
        graph_nodes.append({
            "id": hid,
            "role": m.get("role", "host"),
            "asset_value": m.get("asset_value", 0),
            "is_entry": hid == facts["entry"]["host"],
            "is_crown": hid == facts["crown_jewel"]["host"],
        })
    return {"nodes": graph_nodes, "edges": edges}


def path_precision(facts, paths):
    """Two different claims, reported separately, because conflating them is the
    easiest way for this project to overstate what it knows.

    config_coverage  — the fraction of enumerated paths whose every vector has
                       the configuration the technique requires. This is what a
                       collector can establish by reading a host. It says "the
                       door is unlocked", not "we walked through it".

    precision        — the fraction of paths that were VERIFIED BY EXECUTION.
                       Only the verifier can raise this above zero. Until
                       verifier/ exists it is 0, and that is the correct value
                       to display rather than a placeholder.

    A vector's `config_exploitable` is set by collectors/derive.py. The older
    hand-written facts files carry only `verified_exploitable`; for those it is
    read as a configuration claim, since nothing in them was ever executed.
    """
    executed = {}
    configured = {}
    for v in facts["vectors"]:
        vid = v["vector_id"]
        executed[vid] = v.get("verified_exploitable") is True
        if v.get("config_exploitable") is not None:
            configured[vid] = bool(v["config_exploitable"])
        else:
            configured[vid] = bool(v.get("verified_exploitable"))

    def all_true(path, table):
        vids = [s["vector_id"] for s in path if s.get("vector_id")]
        return all(table.get(v, False) for v in vids)

    total = len(paths)
    verified = sum(1 for p in paths if all_true(p, executed))
    covered = sum(1 for p in paths if all_true(p, configured))

    return {
        "proposed": total,
        "verified": verified,
        "precision": (verified / total) if total else 0.0,
        "config_covered": covered,
        "config_coverage": (covered / total) if total else 0.0,
        "verification_status": (
            "none" if verified == 0 else
            "complete" if verified == total else "partial"
        ),
    }


def main():
    facts = load_facts(FACTS)
    paths, stats = search(facts)
    stats["raw_orderings"] = len(search(facts, collapse="none")[0])
    stats["after_reorder_merge"] = len(search(facts, collapse="reorder")[0])
    timing = time_search(facts)
    ranking = chokepoint(paths)
    graph = build_graph(facts)
    precision = path_precision(facts, paths)

    result = {
        "entry": facts["entry"],
        "crown_jewel": facts["crown_jewel"],
        "graph": graph,
        "paths": paths,
        "chokepoints": ranking,
        "path_finder": precision,
        "search": stats,
        "timing": timing,
    }

    os.makedirs(os.path.dirname(ANALYSIS), exist_ok=True)
    with open(ANALYSIS, "w") as f:
        json.dump(result, f, indent=2)
    with open(DATA_JS, "w") as f:
        f.write("// Generated by enumerator/pathfinder.py — do not edit by hand.\n")
        f.write("window.ASCEND_DATA = ")
        json.dump(result, f, indent=2)
        f.write(";\n")

    # --- console report ---
    print(f"Entry: {facts['entry']['host']}:{facts['entry']['privilege']}  "
          f"-> Crown jewel: {facts['crown_jewel']['host']}:{facts['crown_jewel']['privilege']}")
    print(f"\nEnumerated {len(paths)} attack path(s):\n")
    for i, path in enumerate(paths, 1):
        print(f"  Path {i}:")
        for step in path:
            print(f"    {step['from']:>16}  --[{step['technique']}]-->  {step['to']}")
        print()
    print(f"Config coverage (paths whose vectors are all config-present): "
          f"{precision['config_covered']}/{precision['proposed']} = "
          f"{precision['config_coverage']:.2f}")
    print(f"Path-finder precision (EXECUTION-verified / proposed): "
          f"{precision['verified']}/{precision['proposed']} = "
          f"{precision['precision']:.2f}"
          + ("   <- no verifier has run; this is the honest value, not a gap"
             if precision["verification_status"] == "none" else "") + "\n")
    print(f"Search: depth cap {stats['max_depth']}, path cap {stats['max_paths']}"
          f"{' (HIT, more paths may exist)' if stats['hit_path_cap'] else ''}, "
          f"{stats['cut_at_depth']} branch(es) cut at the depth cap")
    print(f"  {stats['raw_orderings']} raw orderings -> {stats['after_reorder_merge']} after "
          f"merging reorderings -> {len(paths)} distinct route(s) with no unneeded steps")
    print(f"Enumeration time over {timing['runs']} runs: p50 {timing['p50_ms']} ms, "
          f"p95 {timing['p95_ms']} ms, p99 {timing['p99_ms']} ms\n")
    print("Chokepoints (fixes ranked by paths eliminated):")
    for c in ranking:
        print(f"    {c['vector_id']:<24} kills {c['paths_eliminated_if_fixed']}/"
              f"{c['total_paths']} paths   [{c['technique']}]")
    print(f"\nWrote {os.path.relpath(ANALYSIS, ROOT)} and {os.path.relpath(DATA_JS, ROOT)}")


if __name__ == "__main__":
    main()

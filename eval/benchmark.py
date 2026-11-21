#!/usr/bin/env python3
"""Reproducible multi-variant benchmark harness for ASCEND (Paper & Eval).

Generates N=40 seeded lab variants (seed=1337), splits strictly by variant_id,
and produces script-generated JSON tables in eval/ for:
  1. Exploitability Scorer vs. Named Baselines (Majority, CVSS >= 7, Static Flag)
     + 3-tier Feature Ablation + GBDT comparator (eval/scorer_benchmark.json)
  2. Chokepoint Remediation vs. Exact Optimal, CVSS-First, and Random Order
     across all attackable variants (eval/remediation_benchmark.json)
  3. Collector Decoy False-Positive Rate & Enumeration Scalability (4 -> 64 hosts)
     against the p95 < 5000 ms SLO (eval/scalability_benchmark.json)
  4. Unified summary (eval/benchmark_summary.json) + variant_outcomes.jsonl
"""

from __future__ import annotations

import json
import random
import statistics
import sys
import time
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "enumerator"))

from chokepoint.engine import (  # noqa: E402
    apply_fix_ids,
    build_remediation,
    greedy_vs_optimal,
    ordering_comparison,
)
from generator.catalogue import load_host_types, load_weaknesses  # noqa: E402
from generator.variants import (  # noqa: E402
    blueprint_to_facts,
    generate_variants,
    materialize_variant_outcomes,
)
from pathfinder import enumerate_paths  # noqa: E402
from scorer.model import train_and_evaluate  # noqa: E402

EVAL_DIR = ROOT / "eval"
SCOPE = yaml.safe_load((ROOT / "scope.yaml").read_text())


def _random_ordering_cost(
    facts: dict[str, Any],
    scope: dict[str, Any],
    *,
    trials: int = 20,
    seed: int = 1337,
) -> tuple[float, float]:
    """Average (fixes_to_full_cover, cost_to_full_cover) under random fix ordering."""
    plan = build_remediation(facts, scope)
    fixes = plan["ranked_fixes"]
    if not fixes or plan["total_enumerated_paths"] == 0:
        return 0.0, 0.0

    rng = random.Random(seed)
    fix_counts: list[int] = []
    costs: list[float] = []
    for _ in range(trials):
        order = list(fixes)
        rng.shuffle(order)
        applied: list[str] = []
        cost_acc = 0.0
        for f in order:
            applied.append(f["fix_id"])
            cost_acc += float(f["cost"])
            if len(enumerate_paths(apply_fix_ids(facts, scope, applied))) == 0:
                fix_counts.append(len(applied))
                costs.append(cost_acc)
                break
    if not fix_counts:
        return float(len(fixes)), sum(float(f["cost"]) for f in fixes)
    return round(statistics.mean(fix_counts), 3), round(statistics.mean(costs), 3)


def _scale_synthetic_graph(num_hosts: int, seed: int = 1337) -> dict[str, Any]:
    """Build a deterministic tiered Linux network of *num_hosts* hosts for latency scaling."""
    rng = random.Random(seed + num_hosts)
    n_web = max(1, num_hosts // 8)
    n_db = max(1, num_hosts // 8)
    n_pivots = max(1, num_hosts - n_web - n_db)

    hosts = []
    accounts = []
    vectors = []
    reachability = []
    grants = []

    web_ids = [f"web{i+1:02d}" for i in range(n_web)]
    piv_ids = [f"app{i+1:02d}" for i in range(n_pivots)]
    db_ids = [f"db{i+1:02d}" for i in range(n_db)]

    for wid in web_ids:
        hosts.append({"hostname": wid, "role": "web", "os": "Debian 12", "kernel": "5.4.0", "asset_value": 10})
        accounts += [
            {"host": wid, "username": "www-data", "privilege": "low", "type": "service"},
            {"host": wid, "username": "root", "privilege": "root", "type": "system"},
        ]
    vectors.append({
        "vector_id": "v_web01_key",
        "host": "web01",
        "technique": "T1552.001",
        "technique_name": "Credentials In Files",
        "cvss": 5.5,
        "kind": "credential_access",
        "reads_credential": "app_deploy_key",
        "requires": {"host": "web01", "privilege": "low"},
        "config_exploitable": True,
        "verified_exploitable": None,
        "features": {"provenance": "declared"},
    })

    for idx, pid in enumerate(piv_ids):
        hosts.append({"hostname": pid, "role": "app", "os": "Debian 12", "kernel": "5.10.150", "asset_value": 30})
        accounts += [
            {"host": pid, "username": "appuser", "privilege": "low", "type": "service"},
            {"host": pid, "username": "root", "privilege": "root", "type": "system"},
        ]
        # Connect first 2 pivots to key reuse so path count stays realistic while graph scales
        if idx < 2:
            grants.append({"host": pid, "account": "appuser", "privilege": "low"})
        if rng.random() < 0.3:
            vectors.append({
                "vector_id": f"v_{pid}_sudo",
                "host": pid,
                "technique": "T1548.003",
                "technique_name": "Sudo",
                "cvss": 7.8,
                "kind": "privilege_escalation_local",
                "requires": {"host": pid, "privilege": "low"},
                "gains": {"host": pid, "privilege": "root"},
                "config_exploitable": True,
                "verified_exploitable": None,
                "features": {"provenance": "declared"},
            })

    for idx, did in enumerate(db_ids):
        hosts.append({"hostname": did, "role": "database", "os": "Debian 12", "kernel": "5.16.0", "asset_value": 100 if idx == 0 else 80})
        accounts += [
            {"host": did, "username": "dbuser", "privilege": "low", "type": "service"},
            {"host": did, "username": "root", "privilege": "root", "type": "system"},
        ]
        if idx == 0:
            grants.append({"host": did, "account": "dbuser", "privilege": "low"})
            vectors.append({
                "vector_id": f"v_{did}_suid",
                "host": did,
                "technique": "T1548.001",
                "technique_name": "Setuid",
                "cvss": 7.8,
                "kind": "privilege_escalation_local",
                "requires": {"host": pid, "privilege": "low"},
                "gains": {"host": pid, "privilege": "root"},
                "config_exploitable": True,
                "verified_exploitable": None,
                "features": {"provenance": "declared"},
            })

    for w in web_ids:
        for p in piv_ids:
            reachability.append({"from": w, "to": p, "port": 22, "service": "ssh"})
    for p in piv_ids:
        for d in db_ids:
            reachability.append({"from": p, "to": d, "port": 22, "service": "ssh"})

    return {
        "entry": {"host": "web01", "account": "www-data", "privilege": "low"},
        "crown_jewel": {"host": "db01", "privilege": "root"},
        "hosts": hosts,
        "accounts": accounts,
        "reachability": reachability,
        "credentials": [{
            "cred_id": "app_deploy_key",
            "type": "ssh_private_key",
            "discoverable_at": {"host": "web01", "privilege": "low"},
            "grants": grants,
            "features": {"provenance": "declared", "reuse_count": len(grants)},
        }],
        "vectors": vectors,
    }


def run_benchmark(n_variants: int = 40, seed: int = 1337) -> dict[str, Any]:
    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    roles = load_host_types()
    weaknesses = load_weaknesses()

    variants = generate_variants(n=n_variants, seed=seed, roles=roles, weaknesses=weaknesses)
    outcomes = materialize_variant_outcomes(variants, roles=roles, weaknesses=weaknesses)

    # Persist variant_outcomes.jsonl (same schema as outcomes.jsonl, explicitly labelled)
    outcomes_file = EVAL_DIR / "variant_outcomes.jsonl"
    with outcomes_file.open("w", encoding="utf-8") as fh:
        for rec in outcomes:
            fh.write(json.dumps(rec) + "\n")

    # ── Experiment 1: ML Exploitability Scorer vs Named Baselines ─────────────
    _, scorer_report = train_and_evaluate(
        None, records_override=outcomes, seed=seed
    )
    scorer_payload = scorer_report.to_dict()
    (EVAL_DIR / "scorer_benchmark.json").write_text(
        json.dumps(scorer_payload, indent=2) + "\n", encoding="utf-8"
    )

    # ── Experiment 2: Chokepoint Remediation vs Exact / CVSS / Random ─────────
    rem_rows: list[dict[str, Any]] = []
    hardened_checked = 0
    hardened_false_alarms = 0
    total_decoys_declined = 0

    for bp in variants:
        facts, report = blueprint_to_facts(bp, roles=roles, weaknesses=weaknesses)
        total_decoys_declined += len(report["skipped"])
        paths = enumerate_paths(facts)
        if bp.get("hardened"):
            hardened_checked += 1
            hardened_false_alarms += len(paths)
            continue
        if not paths:
            continue

        order = ordering_comparison(facts, SCOPE)
        gvo = greedy_vs_optimal(facts, SCOPE)
        rand_fixes, rand_cost = _random_ordering_cost(facts, SCOPE, trials=15, seed=seed)

        rem_rows.append({
            "variant_id": bp["variant_id"],
            "hosts": len(facts["hosts"]),
            "paths": len(paths),
            "greedy_fixes": order["greedy_fixes_to_full_cover"],
            "greedy_cost": order["greedy_cost_to_full_cover"],
            "optimal_cost": gvo["optimal"]["cost"] if gvo["optimal"]["computed"] else None,
            "greedy_is_optimal": gvo["greedy_is_optimal"],
            "cvss_fixes": order["naive_fixes_to_full_cover"],
            "cvss_cost": order["naive_cost_to_full_cover"],
            "random_fixes": rand_fixes,
            "random_cost": rand_cost,
        })

    remediation_summary = {
        "seed": seed,
        "variants_total": len(variants),
        "variants_with_paths": len(rem_rows),
        "mean_paths_per_variant": round(statistics.mean(r["paths"] for r in rem_rows), 2) if rem_rows else 0.0,
        "mean_greedy_fixes": round(statistics.mean(r["greedy_fixes"] for r in rem_rows), 2) if rem_rows else 0.0,
        "mean_greedy_cost": round(statistics.mean(r["greedy_cost"] for r in rem_rows), 2) if rem_rows else 0.0,
        "mean_cvss_fixes": round(statistics.mean(r["cvss_fixes"] for r in rem_rows), 2) if rem_rows else 0.0,
        "mean_cvss_cost": round(statistics.mean(r["cvss_cost"] for r in rem_rows), 2) if rem_rows else 0.0,
        "mean_random_fixes": round(statistics.mean(r["random_fixes"] for r in rem_rows), 2) if rem_rows else 0.0,
        "mean_random_cost": round(statistics.mean(r["random_cost"] for r in rem_rows), 2) if rem_rows else 0.0,
        "greedy_optimal_rate": round(
            sum(1 for r in rem_rows if r["greedy_is_optimal"]) / len(rem_rows), 4
        ) if rem_rows else 1.0,
        "cost_reduction_vs_cvss_pct": round(
            (1.0 - statistics.mean(r["greedy_cost"] for r in rem_rows) / statistics.mean(r["cvss_cost"] for r in rem_rows)) * 100.0,
            2,
        ) if rem_rows else 0.0,
        "cost_reduction_vs_random_pct": round(
            (1.0 - statistics.mean(r["greedy_cost"] for r in rem_rows) / statistics.mean(r["random_cost"] for r in rem_rows)) * 100.0,
            2,
        ) if rem_rows else 0.0,
        "per_variant": rem_rows,
    }
    (EVAL_DIR / "remediation_benchmark.json").write_text(
        json.dumps(remediation_summary, indent=2) + "\n", encoding="utf-8"
    )

    # ── Experiment 3: Decoy FP Rate & Enumeration Scalability (4 -> 64 hosts) ─
    scale_rows = []
    for n_hosts in (4, 8, 16, 32, 64):
        g = _scale_synthetic_graph(n_hosts, seed=seed)
        timings_ms = []
        n_paths = 0
        for _ in range(15):
            t0 = time.perf_counter()
            n_paths = len(enumerate_paths(g))
            timings_ms.append((time.perf_counter() - t0) * 1000.0)
        timings_ms.sort()
        p50 = round(timings_ms[len(timings_ms) // 2], 3)
        p95 = round(timings_ms[int(len(timings_ms) * 0.95)], 3)
        p99 = round(timings_ms[-1], 3)
        scale_rows.append({
            "hosts": n_hosts,
            "paths": n_paths,
            "p50_ms": p50,
            "p95_ms": p95,
            "p99_ms": p99,
            "meets_5s_slo": p95 < 5000.0,
        })

    scalability_payload = {
        "seed": seed,
        "slo_ms": 5000.0,
        "hardened_variants_checked": hardened_checked,
        "hardened_false_alarm_paths": hardened_false_alarms,
        "decoys_examined_and_declined": total_decoys_declined,
        "decoy_false_positive_rate": 0.0 if hardened_false_alarms == 0 else round(
            hardened_false_alarms / max(1, hardened_checked), 4
        ),
        "scaling": scale_rows,
    }
    (EVAL_DIR / "scalability_benchmark.json").write_text(
        json.dumps(scalability_payload, indent=2) + "\n", encoding="utf-8"
    )

    summary = {
        "seed": seed,
        "n_variants": n_variants,
        "scorer": scorer_payload,
        "remediation": {k: v for k, v in remediation_summary.items() if k != "per_variant"},
        "scalability": scalability_payload,
    }
    (EVAL_DIR / "benchmark_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    return summary


if __name__ == "__main__":
    res = run_benchmark()
    print("=== SCORER (HELD-OUT TEST VARIANTS) ===")
    for b in res["scorer"]["baselines"]:
        print(f"  [BASELINE] {b['name']:32s} Acc={b['accuracy']:.3f} MacroF1={b['macro_f1']:.3f} Brier={b['brier_score']:.3f}")
    for m in res["scorer"]["ablations"]:
        print(f"  [MODEL]    {m['name']:38s} Acc={m['accuracy']:.3f} MacroF1={m['macro_f1']:.3f} AUC={m['roc_auc']} Brier={m['brier_score']:.3f}")
    print("\n=== REMEDIATION (ACROSS VARIANTS) ===")
    print(json.dumps(res["remediation"], indent=2))
    print("\n=== SCALABILITY (4 -> 64 HOSTS) ===")
    for s in res["scalability"]["scaling"]:
        print(f"  {s['hosts']:2d} hosts -> p50={s['p50_ms']}ms p95={s['p95_ms']}ms SLO={s['meets_5s_slo']}")

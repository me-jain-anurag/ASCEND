"""CLI entry point: ``python3 -m scorer``."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "enumerator"))

from pathfinder import enumerate_paths  # noqa: E402
from scorer.model import score_environment  # noqa: E402


def main() -> int:
    facts_path = ROOT / "environment_graph" / "facts.json"
    variant_outcomes = ROOT / "eval" / "variant_outcomes.jsonl"
    outcomes_path = variant_outcomes if variant_outcomes.exists() else (ROOT / "outcomes.jsonl")

    facts = json.loads(facts_path.read_text(encoding="utf-8"))
    raw_paths = enumerate_paths(facts)
    paths = [
        {
            "path_id": f"path-{i:02d}",
            "steps": [
                {
                    "step_number": idx,
                    "source_host": s["from"].split(":")[0],
                    "vector": {"technique": s["technique"], "vector_id": s.get("vector_id")},
                    "credential": {"cred_id": s["credential"]} if s.get("credential") else None,
                }
                for idx, s in enumerate(p, 1)
            ],
        }
        for i, p in enumerate(raw_paths, 1)
    ]

    result = score_environment(facts, paths, outcomes_path)
    out_path = ROOT / "eval" / "scorer_report.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    m = result["model"]
    print("ASCEND Exploitability Scorer")
    print("================================")
    print(f"Model:      {m['model_type']} ({m['status']})")
    print(f"Source:     {m['label_source']} ({outcomes_path.name})")
    print(
        f"Outcomes:   {m['records_total']} total -> {m['records_trainable']} trainable "
        f"({m['records_positives']}+ / {m['records_negatives']}-, "
        f"{m['records_excluded_not_executable']} not_executable excluded, "
        f"{m['records_flagged_param_mismatch']} param mismatches flagged)"
    )
    if m["trained"] and m["baselines"]:
        print(f"Split:      {m['split_strategy']}")
        for row in m["baselines"] + m["ablations"]:
            print(
                f"  [{row['kind']:8s}] {row['name']:38s} "
                f"Acc={row['accuracy']:.3f} MacroF1={row['macro_f1']:.3f} Brier={row['brier_score']:.3f}"
            )
    for c in m["caveats"]:
        print(f"Note:       {c}")
    print(f"Report:     {out_path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""CLI entry point for the ASCEND exploitability scorer (`python3 -m scorer`)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "enumerator") not in sys.path:
    sys.path.insert(0, str(ROOT / "enumerator"))

from pathfinder import enumerate_paths  # noqa: E402
from scorer.model import score_environment  # noqa: E402


def main() -> int:
    facts_path = ROOT / "environment_graph" / "facts.json"
    outcomes_path = ROOT / "outcomes.jsonl"
    out_path = ROOT / "eval" / "scorer_report.json"

    facts = json.loads(facts_path.read_text(encoding="utf-8"))
    raw_paths = enumerate_paths(facts)
    # Minimal path wrapper matching service/main.py structure
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
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    m = result["model"]
    print("ASCEND Exploitability Scorer\n" + "=" * 32)
    print(f"Model:      {m['model_type']}")
    print(f"Outcomes:   {m['records_total']} total -> {m['records_trainable']} trainable "
          f"({m['records_excluded_not_executable']} not_executable excluded, "
          f"{m['records_flagged_param_mismatch']} batch param mismatches flagged)")
    if m["cv_folds"]:
        print(f"CV ({m['cv_folds']}-fold): accuracy={m['cv_accuracy']}, brier={m['cv_brier_score']}")
    print("\nPath exploitability scores:")
    for pid, ps in result["path_scores"].items():
        flag = " [contains unverified-in-lab step]" if ps["contains_unverified_step"] else ""
        print(f"  {pid}: p={ps['joint_probability']:.4f}{flag}")
    if m["caveats"]:
        print("\nHonesty caveats:")
        for c in m["caveats"]:
            print(f"  - {c}")
    print(f"\nWrote {out_path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

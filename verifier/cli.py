"""CLI entry point for the execution verifier.

Usage:
    python -m verifier batch  --scope scope.yaml --seed 1337 --repeats 20
    python -m verifier verify < path.json
    python -m verifier check  --scope scope.yaml
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(
        prog="verifier",
        description="ASCEND execution verifier — run techniques, record outcomes",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # ── batch ─────────────────────────────────────────────────────────────
    b = sub.add_parser("batch", help="generate the labelled dataset")
    b.add_argument("--scope", default="scope.yaml",
                    help="path to scope.yaml (default: scope.yaml)")
    b.add_argument("--seed", type=int, default=1337,
                    help="RNG seed for reproducibility (default: 1337)")
    b.add_argument("--repeats", type=int, default=20,
                    help="runs per (host, technique, scenario) cell (default: 20)")
    b.add_argument("--output", default="outcomes.jsonl",
                    help="output JSONL path (default: outcomes.jsonl)")

    # ── verify ────────────────────────────────────────────────────────────
    v = sub.add_parser("verify",
                        help="live-verify one enumerated path (JSON on stdin)")
    v.add_argument("--scope", default="scope.yaml")
    v.add_argument("--output", default="outcomes.jsonl")

    # ── check ─────────────────────────────────────────────────────────────
    c = sub.add_parser("check",
                        help="health check — verify canary on all lab hosts")
    c.add_argument("--scope", default="scope.yaml")

    args = p.parse_args(argv)

    # Resolve scope path relative to repo root if not absolute
    scope_path = Path(args.scope)
    if not scope_path.is_absolute():
        repo_root = Path(__file__).resolve().parent.parent
        scope_path = repo_root / scope_path

    from verifier.scope import load
    scope = load(scope_path)

    if args.cmd == "batch":
        _cmd_batch(scope, args)
    elif args.cmd == "verify":
        _cmd_verify(scope, args)
    elif args.cmd == "check":
        _cmd_check(scope)


def _cmd_batch(scope, args) -> None:
    from verifier.runner import run_matrix

    print(f"ASCEND verifier — batch run")
    print(f"  scope:   {args.scope}")
    print(f"  seed:    {args.seed}")
    print(f"  repeats: {args.repeats}")
    print(f"  output:  {args.output}")
    print(f"  techniques: {len(scope.techniques)}")
    print()

    outcomes = run_matrix(
        scope,
        seed=args.seed,
        repeats=args.repeats,
        output_path=args.output,
    )

    # Summary
    positives = sum(1 for o in outcomes if o.escalated)
    negatives = len(outcomes) - positives
    print(f"\n{'=' * 60}")
    print(f"Batch complete: {len(outcomes)} runs")
    print(f"  Positives (escalated):     {positives}")
    print(f"  Negatives (not escalated): {negatives}")
    print(f"  Output: {args.output}")


def _cmd_verify(scope, args) -> None:
    from verifier.runner import verify_path

    path_json = json.load(sys.stdin)
    result = verify_path(path_json, scope, output_path=args.output)
    print(json.dumps(result, indent=2))


def _cmd_check(scope) -> None:
    from verifier.lab import canary_token, exec_as

    print("ASCEND verifier — health check")
    print(f"  canary_path: {scope.canary_path}")
    print()

    # Collect all unique hosts across techniques
    hosts = set()
    for t in scope.techniques:
        hosts.update(t.hosts)

    all_ok = True
    for host in sorted(hosts):
        try:
            # 1. Check exec_as works
            code, out, _ = exec_as(
                host, "root", ["id", "-u"],
                prefix=scope.container_prefix,
            )
            if code != 0 or out.strip() != "0":
                print(f"  {host}: FAIL — cannot exec as root")
                all_ok = False
                continue

            # 2. Check canary is present and readable
            token = canary_token(
                host, scope.canary_path,
                prefix=scope.container_prefix,
            )
            print(f"  {host}: OK — canary={token[:8]}...")

        except Exception as exc:
            print(f"  {host}: ERROR — {exc}")
            all_ok = False

    print()
    if all_ok:
        print("All hosts healthy.")
    else:
        print("Some hosts failed — check the lab is up (bash lab/up.sh).")
        sys.exit(1)


if __name__ == "__main__":
    main()

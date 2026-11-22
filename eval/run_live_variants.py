#!/usr/bin/env python3
"""Live Docker multi-variant execution runner for ASCEND.

Generates N seeded lab variants from ``generator/variants.py``, emits each
variant's compose + per-host seeds + ``scope.yaml``, boots the containers via
Docker Compose, runs the live canary verifier (recording real ``escalated``,
``not_escalated``, and ``not_executable`` verdicts with
``label_source="live_docker_canary"``), and tears down cleanly.

Usage (on a machine with Docker):
    python3 eval/run_live_variants.py --count 10 --seed 1337
    python3 eval/run_live_variants.py --count 40 --seed 1337 --output eval/variant_outcomes.jsonl

Dry-run (verifies emission, scope parity, and orchestration without Docker):
    python3 eval/run_live_variants.py --count 5 --seed 1337 --dry-run
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from generator.catalogue import load_host_types, load_weaknesses  # noqa: E402
from generator.emit import emit_compose, emit_seed  # noqa: E402
from generator.scope import emit_scope  # noqa: E402
from generator.variants import blueprint_to_facts, generate_variants  # noqa: E402


def materialize_variant_workspace(
    blueprint: dict[str, Any],
    out_dir: Path,
    roles: dict[str, Any],
    weaknesses: dict[str, Any],
) -> tuple[Path, Path]:
    """Emit Dockerfile/common assets, per-host seed scripts, compose, and scope.yaml."""
    out_dir.mkdir(parents=True, exist_ok=True)
    seed_dir = out_dir / "seed"
    seed_dir.mkdir(exist_ok=True)

    # Copy base lab Dockerfile, entrypoint, bootstrap, and common.sh
    lab_dir = ROOT / "lab"
    for fname in ("Dockerfile", "entrypoint.sh", "bootstrap.sh"):
        src = lab_dir / fname
        if src.exists():
            shutil.copy2(src, out_dir / fname)
    common_sh = lab_dir / "seed" / "common.sh"
    if common_sh.exists():
        shutil.copy2(common_sh, seed_dir / "common.sh")
    keys_dir = lab_dir / "keys"
    if keys_dir.exists():
        shutil.copytree(keys_dir, out_dir / "keys", dirs_exist_ok=True)

    for h in blueprint["hosts"]:
        seed_text = emit_seed(h, roles, weaknesses)
        seed_path = seed_dir / f"{h['id']}.sh"
        seed_path.write_text(seed_text, encoding="utf-8")
        seed_path.chmod(0o755)

    compose_path = out_dir / "docker-compose.yml"
    compose_path.write_text(emit_compose(blueprint, roles, weaknesses), encoding="utf-8")

    scope_path = out_dir / "scope.yaml"
    scope_path.write_text(emit_scope(blueprint, roles, weaknesses), encoding="utf-8")
    return compose_path, scope_path


def run_variant_live(
    blueprint: dict[str, Any],
    *,
    roles: dict[str, Any],
    weaknesses: dict[str, Any],
    dry_run: bool = False,
) -> list[dict[str, Any]]:
    """Bring up one generated variant in Docker, run verifier, and tear down."""
    vid = blueprint["variant_id"]
    split = blueprint["split"]
    facts, _ = blueprint_to_facts(blueprint, roles=roles, weaknesses=weaknesses)

    with tempfile.TemporaryDirectory(prefix=f"ascend_{vid}_") as tmp:
        ws = Path(tmp)
        compose_path, scope_path = materialize_variant_workspace(
            blueprint, ws, roles, weaknesses
        )
        if dry_run:
            return [{
                "variant_id": vid,
                "split": split,
                "hosts": len(blueprint["hosts"]),
                "compose_emitted": compose_path.exists(),
                "scope_emitted": scope_path.exists(),
                "dry_run": True,
            }]

        from verifier.runner import run_one
        from verifier.scope import load as load_verifier_scope

        records: list[dict[str, Any]] = []
        vscope = load_verifier_scope(scope_path)
        try:
            subprocess.run(
                ["docker", "compose", "-f", str(compose_path), "up", "-d", "--build"],
                check=True,
                capture_output=True,
                text=True,
            )
            tmp_out = ws / "outcomes.jsonl"
            for tech in vscope.techniques:
                for host in tech.hosts:
                    o = run_one(
                        host=host,
                        start_user=tech.start_user,
                        technique=tech.raw,
                        scenario=vid,
                        scope=vscope,
                        seed=blueprint.get("seed", 1337),
                        output_path=str(tmp_out),
                        do_reset=False,
                    )
                    vec = next(
                        (v for v in facts["vectors"] if v["host"] == host and v["technique"] == tech.id),
                        {},
                    )
                    records.append({
                        "variant_id": vid,
                        "split": split,
                        "host": host,
                        "technique": tech.id,
                        "escalated": o.escalated,
                        "status": o.status,
                        "reason": o.reason,
                        "evidence": o.evidence,
                        "kernel_version": o.kernel_version,
                        "host_facts_ref": f"{vid}:{host}:{tech.id}",
                        "label_source": "live_docker_canary",
                        "cvss": vec.get("cvss"),
                        "host_asset_value": next(
                            (h["asset_value"] for h in facts["hosts"] if h["hostname"] == host), 0
                        ),
                        "reuse_count": (
                            facts["credentials"][0]["features"]["reuse_count"]
                            if facts["credentials"] else 0
                        ),
                        "features_snapshot": dict(vec.get("features") or {}),
                    })
        finally:
            subprocess.run(
                ["docker", "compose", "-f", str(compose_path), "down", "-v", "--remove-orphans"],
                check=False,
                capture_output=True,
                text=True,
            )
        return records


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run generated ASCEND variants in live Docker.")
    parser.add_argument("--count", type=int, default=10, help="Number of variants to run")
    parser.add_argument("--seed", type=int, default=1337, help="Generator seed")
    parser.add_argument("--dry-run", action="store_true", help="Emit & validate without Docker")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "eval" / "live_variant_outcomes.jsonl",
        help="Destination JSONL path for live canary outcomes",
    )
    args = parser.parse_args(argv)

    roles = load_host_types()
    weaknesses = load_weaknesses()
    variants = generate_variants(n=args.count, seed=args.seed, roles=roles, weaknesses=weaknesses)

    all_records: list[dict[str, Any]] = []
    for bp in variants:
        recs = run_variant_live(bp, roles=roles, weaknesses=weaknesses, dry_run=args.dry_run)
        all_records.extend(recs)
        print(f"  [{bp['variant_id']}] ({bp['split']}) -> {len(recs)} record(s)")

    if not args.dry_run:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as fh:
            for rec in all_records:
                fh.write(json.dumps(rec) + "\n")
        print(f"Wrote {len(all_records)} live canary outcomes to {args.output}")
    else:
        print(f"Dry-run OK: {len(all_records)} variant workspaces materialized & validated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

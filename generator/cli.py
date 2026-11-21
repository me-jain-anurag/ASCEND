"""Generate a buildable lab directory from a scenario blueprint.

    python3 -m generator.cli generator/blueprints/current_lab.yaml -o /tmp/lab

Emits docker-compose.yml and per-host seed/<host>.sh, and copies the static lab
scaffolding (Dockerfile, entrypoint.sh, bootstrap.sh, down.sh, seed/common.sh,
exploits/) so the output directory builds with `bash up.sh` the same way lab/ does.
scope.yaml emission is a later increment; for now the generated lab reuses the
repo's scope.yaml.
"""

from __future__ import annotations

import argparse
import pathlib
import shutil
import sys

from generator.blueprint import load_blueprint, validate
from generator.catalogue import ROOT, load_host_types, load_weaknesses
from generator.emit import emit_compose, emit_seed
from generator.scope import emit_scope

LAB = ROOT / "lab"
# Static scaffolding copied verbatim from lab/ into a generated lab.
_COPY_FILES = ["Dockerfile", "entrypoint.sh", "bootstrap.sh", "down.sh"]


def generate(blueprint_path: str, out_dir: str, backend: str = "container") -> list[str]:
    """Write a buildable lab to out_dir. Returns the list of files written."""
    roles = load_host_types()
    weaknesses = load_weaknesses()
    blueprint = load_blueprint(blueprint_path)

    errors = validate(blueprint, roles, weaknesses, backend=backend)
    if errors:
        raise ValueError("invalid blueprint:\n  - " + "\n  - ".join(errors))

    out = pathlib.Path(out_dir)
    (out / "seed").mkdir(parents=True, exist_ok=True)
    written: list[str] = []

    (out / "docker-compose.yml").write_text(emit_compose(blueprint, roles, weaknesses))
    written.append("docker-compose.yml")

    (out / "scope.yaml").write_text(emit_scope(blueprint, roles, weaknesses))
    written.append("scope.yaml")

    shutil.copy2(LAB / "seed" / "common.sh", out / "seed" / "common.sh")
    written.append("seed/common.sh")

    for host in blueprint.get("hosts") or []:
        rel = f"seed/{host['id']}.sh"
        (out / rel).write_text(emit_seed(host, roles, weaknesses))
        written.append(rel)

    for name in _COPY_FILES:
        src = LAB / name
        if src.exists():
            shutil.copy2(src, out / name)
            written.append(name)

    exploits = LAB / "exploits"
    if exploits.exists():
        shutil.copytree(exploits, out / "exploits", dirs_exist_ok=True)
        written.append("exploits/")

    return written


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Generate an ASCEND lab from a blueprint.")
    ap.add_argument("blueprint", help="path to a scenario blueprint YAML")
    ap.add_argument("-o", "--out", required=True, help="output directory")
    ap.add_argument("--backend", choices=["container", "vm"], default="container")
    ap.add_argument("--check", action="store_true", help="validate only; write nothing")
    args = ap.parse_args(argv)

    if args.check:
        errors = validate(
            load_blueprint(args.blueprint),
            load_host_types(),
            load_weaknesses(),
            backend=args.backend,
        )
        if errors:
            print("INVALID:\n  - " + "\n  - ".join(errors), file=sys.stderr)
            return 1
        print("blueprint is valid")
        return 0

    try:
        written = generate(args.blueprint, args.out, backend=args.backend)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 1
    print(f"wrote {len(written)} files to {args.out}:")
    for w in written:
        print(f"  {w}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Load and validate the weakness catalogue and host-type defaults."""

from __future__ import annotations

import pathlib

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
CATALOGUE_DIR = ROOT / "catalogue"

VALID_EXECUTABLE_IN = {"container", "vm", "either"}
VALID_STATUS = {"active", "planned"}


def load_host_types(path: pathlib.Path | None = None) -> dict:
    """Return {role_name: role_def}. Raises ValueError on a malformed file."""
    path = path or CATALOGUE_DIR / "host_types.yaml"
    data = yaml.safe_load(path.read_text()) or {}
    roles = data.get("roles") or {}
    if not roles:
        raise ValueError("host_types.yaml defines no roles")
    for name, role in roles.items():
        account = role.get("account") or {}
        for field in ("name", "uid", "home"):
            if field not in account:
                raise ValueError(f"role {name!r}: account.{field} missing")
        if "default_kernel" not in role:
            raise ValueError(f"role {name!r}: default_kernel missing")
        role.setdefault("networks", [])
    return roles


def load_weaknesses(path: pathlib.Path | None = None) -> dict:
    """Return {weakness_id: weakness_def}. Raises ValueError on a malformed file."""
    directory = path or CATALOGUE_DIR / "weaknesses"
    out: dict = {}
    for f in sorted(pathlib.Path(directory).glob("*.yaml")):
        w = yaml.safe_load(f.read_text()) or {}
        wid = w.get("id")
        if not wid:
            raise ValueError(f"{f.name}: missing id")
        if wid in out:
            raise ValueError(f"duplicate weakness id {wid!r} ({f.name})")
        if not w.get("technique"):
            raise ValueError(f"{wid}: missing technique")
        executable_in = w.get("executable_in", "either")
        if executable_in not in VALID_EXECUTABLE_IN:
            raise ValueError(
                f"{wid}: executable_in must be one of {sorted(VALID_EXECUTABLE_IN)}"
            )
        status = w.setdefault("status", "active")
        if status not in VALID_STATUS:
            raise ValueError(f"{wid}: status must be one of {sorted(VALID_STATUS)}")
        w.setdefault("params", {})
        w["_file"] = f.name
        out[wid] = w
    if not out:
        raise ValueError(f"no weaknesses found under {directory}")
    return out

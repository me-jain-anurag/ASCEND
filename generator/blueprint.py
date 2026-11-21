"""Load, normalise and validate a scenario blueprint against the catalogue."""

from __future__ import annotations

import pathlib

import yaml

from generator.catalogue import load_host_types, load_weaknesses


def load_blueprint(path) -> dict:
    return yaml.safe_load(pathlib.Path(path).read_text()) or {}


def normalize_weaknesses(raw) -> list[dict]:
    """Accept either a bare id string or a {id, params} map; return [{id, params}]."""
    out = []
    for item in raw or []:
        if isinstance(item, str):
            out.append({"id": item, "params": {}})
        elif isinstance(item, dict):
            wid = item.get("id")
            if not wid:
                raise ValueError(f"weakness entry missing id: {item!r}")
            out.append({"id": wid, "params": item.get("params") or {}})
        else:
            raise ValueError(f"bad weakness entry: {item!r}")
    return out


def validate(
    blueprint: dict,
    roles: dict | None = None,
    weaknesses: dict | None = None,
    backend: str = "container",
) -> list[str]:
    """Return a list of human-readable errors; empty means the blueprint is valid.

    Placing a `vm`-only weakness on a `container` backend is allowed (it will
    report not_executable, by design) and is NOT an error.
    """
    roles = roles if roles is not None else load_host_types()
    weaknesses = weaknesses if weaknesses is not None else load_weaknesses()
    errors: list[str] = []

    hosts = blueprint.get("hosts") or []
    if not hosts:
        errors.append("blueprint has no hosts")

    seen: set[str] = set()
    for h in hosts:
        hid = h.get("id")
        if not hid:
            errors.append(f"host missing id: {h!r}")
            continue
        if hid in seen:
            errors.append(f"duplicate host id {hid!r}")
        seen.add(hid)

        if h.get("role") not in roles:
            errors.append(f"{hid}: unknown role {h.get('role')!r}")

        try:
            wlist = normalize_weaknesses(h.get("weaknesses"))
        except ValueError as e:
            errors.append(f"{hid}: {e}")
            continue
        for w in wlist:
            wk = weaknesses.get(w["id"])
            if wk is None:
                errors.append(f"{hid}: unknown weakness {w['id']!r}")
                continue
            if wk.get("status") == "planned":
                errors.append(
                    f"{hid}: weakness {w['id']!r} is 'planned', not yet plantable"
                )

    entry = blueprint.get("entry") or {}
    if entry.get("host") not in seen:
        errors.append(f"entry.host {entry.get('host')!r} is not a defined host")
    crown = blueprint.get("crown_jewel") or {}
    if crown.get("host") not in seen:
        errors.append(f"crown_jewel.host {crown.get('host')!r} is not a defined host")

    return errors

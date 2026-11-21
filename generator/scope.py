"""Emit a complete scope.yaml for a blueprint.

The techniques / rules / remediation / verifier-header sections are static (they
describe the seven in-scope techniques and the derivation rules), so they are
taken verbatim from the repo's base scope.yaml. Only the two per-blueprint
sections are regenerated:

  inventory            — entry, crown jewel, and per-host role + asset_value
  verifier.techniques  — one entry per plantable weakness instance, plus the
                         single aggregated lateral-SSH entry for reused keys

The verifier reads these as data, so the generated file need not match the
hand-written one byte for byte; it must match it *semantically* (same inventory,
same set of verifier instances). tests/test_generator.py checks that parity.
"""

from __future__ import annotations

import copy
import pathlib

import yaml

from generator.blueprint import normalize_weaknesses
from generator.catalogue import ROOT
from generator.emit import _host_context, _subst

BASE_SCOPE = ROOT / "scope.yaml"
# The reused-key vector is lateral movement with alternate auth material.
LATERAL_ID = "T1021.004+T1550"


def _subst_tree(obj, ctx):
    """Substitute {placeholders} through a nested structure, leaving {canary}
    and any other runtime token (not in ctx) untouched for the adapter."""
    if isinstance(obj, str):
        return _subst(obj, ctx)
    if isinstance(obj, list):
        return [_subst_tree(x, ctx) for x in obj]
    if isinstance(obj, dict):
        return {k: _subst_tree(v, ctx) for k, v in obj.items()}
    return obj


def build_inventory(blueprint: dict) -> dict:
    hosts = {}
    for h in blueprint.get("hosts") or []:
        hosts[h["id"]] = {"role": h["role"], "asset_value": h.get("asset")}
    entry = blueprint.get("entry") or {}
    crown = blueprint.get("crown_jewel") or {}
    return {
        "entry": {
            "host": entry.get("host"),
            "account": entry.get("account"),
            "privilege": entry.get("privilege", "low"),
        },
        "crown_jewel": {
            "host": crown.get("host"),
            "privilege": crown.get("privilege", "root"),
        },
        "hosts": hosts,
    }


def build_verifier_techniques(blueprint: dict, roles: dict, weaknesses: dict) -> list:
    """One verifier entry per local weakness instance, plus a single aggregated
    lateral-SSH entry when any host accepts the reused key."""
    local_entries: list = []
    accepts: list = []   # [(host_id, user)] — hosts carrying a lateral weakness
    harvest: list = []   # [(host_id, user, key_path)] — hosts exposing a key
    order: list = []     # blueprint host order, for the lateral hosts list

    for h in blueprint.get("hosts") or []:
        role_def = roles[h["role"]]
        order.append(h["id"])
        for w in normalize_weaknesses(h.get("weaknesses")):
            wk = weaknesses[w["id"]]
            verify = wk.get("verify") or {}
            scope = verify.get("scope", "local")
            adapter = verify.get("adapter")
            if not adapter or scope == "decoy":
                continue  # decoys and un-wired weaknesses have nothing to run

            ctx = _host_context(h, role_def, wk, w["params"])
            start_user = _subst(str(verify.get("start_user", "{user}")), ctx)

            if scope == "lateral":
                accepts.append((h["id"], ctx["user"]))
                continue

            entry = {
                "id": wk["technique"],
                "adapter": adapter,
                "check": verify.get("check"),
                "hosts": [h["id"]],
                "start_user": start_user,
            }
            for k, v in (verify.get("params") or {}).items():
                entry[k] = _subst_tree(v, ctx)

            if verify.get("check") == "credential_read":
                harvest.append((h["id"], ctx["user"], entry.get("key_path")))
            local_entries.append(entry)

    entries = list(local_entries)

    if accepts:
        # Start where the key is first exposed (the harvest host); fall back to
        # the first accepting host if nothing exposes a key.
        if harvest:
            start_host, start_user, key_path = harvest[0]
        else:
            start_host, start_user, key_path = accepts[0][0], accepts[0][1], None
        members = {start_host} | {a[0] for a in accepts}
        hosts = [hid for hid in order if hid in members]
        to_host, to_user = accepts[0]
        entries.append({
            "id": LATERAL_ID,
            "adapter": "lateral_ssh",
            "check": "canary_on_target",
            "requires_unprivileged_start": False,
            "hosts": hosts,
            "start_user": start_user,
            "key_path": key_path,
            "to_host": to_host,
            "to_user": to_user,
        })

    return entries


def build_scope(blueprint: dict, roles: dict, weaknesses: dict, base_path=None) -> dict:
    """Return the full scope dict (base + regenerated inventory/verifier)."""
    base = yaml.safe_load(pathlib.Path(base_path or BASE_SCOPE).read_text())
    data = copy.deepcopy(base)
    data["inventory"] = build_inventory(blueprint)
    data.setdefault("verifier", {})
    data["verifier"]["techniques"] = build_verifier_techniques(blueprint, roles, weaknesses)
    return data


def emit_scope(blueprint: dict, roles: dict, weaknesses: dict, base_path=None) -> str:
    data = build_scope(blueprint, roles, weaknesses, base_path=base_path)
    return yaml.safe_dump(data, sort_keys=False, default_flow_style=False, width=100)

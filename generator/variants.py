"""Seeded multi-variant blueprint generator for ASCEND evaluation and training.

Addresses the single-lab circularity shortfall (docs/11 section 2, item 2):
generates N >= 30 diverse, valid lab blueprints from catalogue/ with:
  - varied topology size (4 to 10 hosts across web, app, ci, database roles)
  - varied branching factor (1 to 3 dual-homed pivot hosts)
  - genuinely exploitable weaknesses (escalated = 1)
  - runtime-mitigated negatives (not_escalated = 0: sudo NOEXEC, nosuid SUID,
    sshd DenyUsers — statically visible to scanners, fail live execution)
  - collector decoys (declined before enumeration, measuring FP rate)
  - deterministic variant-grouped train / val / test splits (70 / 15 / 15) so
    no host or variant ever leaks across splits.
"""

from __future__ import annotations

import hashlib
import random
from typing import Any

from generator.blueprint import normalize_weaknesses, validate
from generator.catalogue import load_host_types, load_weaknesses


# Default CVSS & EPSS priors per weakness/technique (NVD / FIRST reference priors
# used for feature extraction and baseline comparison in Assessment mode).
_TECHNIQUE_META: dict[str, dict[str, Any]] = {
    "T1552.001": {
        "name": "Unsecured Credentials: Credentials In Files",
        "cvss": 5.5,
        "epss": 0.18,
    },
    "T1548.003": {
        "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "cvss": 7.8,
        "epss": 0.42,
    },
    "T1548.001": {
        "name": "Abuse Elevation Control Mechanism: Setuid and Setgid",
        "cvss": 7.8,
        "epss": 0.36,
    },
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "cvss": 7.8,
        "epss": 0.94,
        "cve": "CVE-2022-0847",
    },
    "T1550": {
        "name": "Use Alternate Authentication Material",
        "cvss": 6.5,
        "epss": 0.31,
    },
    "T1021.004+T1550": {
        "name": "Remote Services: SSH (Reused Key)",
        "cvss": 6.5,
        "epss": 0.31,
    },
    "T1611": {
        "name": "Escape to Host",
        "cvss": 8.8,
        "epss": 0.55,
    },
}

_DECOY_BINARIES = ("/bin/ls", "/bin/df", "/usr/bin/uptime")
_SUDO_BINARIES = ("/bin/tar", "/usr/bin/find", "/usr/bin/vim")
_SUID_BINARIES = ("/usr/bin/find", "/usr/bin/python3", "/usr/bin/vim")


def assign_split(variant_id: str, seed: int = 1337) -> str:
    """Deterministic variant-level split assignment (70% train / 15% val / 15% test).

    Splitting by variant_id guarantees every host and finding from a given lab
    variant lives on exactly one side of the split (zero host/variant leakage).
    """
    digest = hashlib.sha256(f"{seed}:{variant_id}".encode("utf-8")).hexdigest()
    bucket = int(digest[:8], 16) % 100
    if bucket < 70:
        return "train"
    if bucket < 85:
        return "val"
    return "test"


def generate_variants(
    n: int = 40,
    *,
    seed: int = 1337,
    roles: dict | None = None,
    weaknesses: dict | None = None,
) -> list[dict[str, Any]]:
    """Generate *n* validated, seeded lab blueprints covering diverse topologies."""
    roles = roles if roles is not None else load_host_types()
    weaknesses = weaknesses if weaknesses is not None else load_weaknesses()
    rng = random.Random(seed)

    variants: list[dict[str, Any]] = []
    for idx in range(1, n + 1):
        vid = f"var-{idx:03d}"
        n_pivots = rng.choice([1, 2, 2, 3])
        n_dbs = rng.choice([1, 1, 2])
        include_extra_web = rng.random() < 0.35

        hosts: list[dict[str, Any]] = []

        # Entry web host (always has readable_ssh_key in attackable variants,
        # except ~10% hardened/decoy-only variants for zero-path negative tests)
        is_hardened_variant = (idx % 10 == 0)
        web_weaknesses: list[Any] = [] if is_hardened_variant else ["readable_ssh_key"]
        if rng.random() < 0.4:
            web_weaknesses.append({
                "id": "decoy_nopasswd",
                "params": {"binary": rng.choice(_DECOY_BINARIES)},
            })
        hosts.append({
            "id": "web01",
            "role": "web",
            "asset": 10,
            "weaknesses": web_weaknesses,
        })

        if include_extra_web:
            w2_weak: list[Any] = []
            if not is_hardened_variant and rng.random() < 0.5:
                w2_weak.append("nopasswd_sudo_noexec")
            else:
                w2_weak.append({
                    "id": "decoy_nopasswd",
                    "params": {"binary": rng.choice(_DECOY_BINARIES)},
                })
            hosts.append({
                "id": "web02",
                "role": "web",
                "asset": 15,
                "weaknesses": w2_weak,
            })

        # Dual-homed pivot tier (app + ci hosts)
        pivot_ids: list[str] = []
        for p in range(n_pivots):
            role = "app" if p % 2 == 0 else "ci"
            pid = f"{role}{p // 2 + 1:02d}"
            pivot_ids.append(pid)
            p_weak: list[Any] = []

            if is_hardened_variant:
                p_weak.append({
                    "id": "decoy_nopasswd",
                    "params": {"binary": rng.choice(_DECOY_BINARIES)},
                })
            else:
                # Key acceptance: first pivot usually accepts; others mix real vs sshd-blocked
                if p == 0 or rng.random() < 0.65:
                    p_weak.append({
                        "id": "accepts_shared_key",
                        "params": {"store_correct_copy": p == 0},
                    })
                else:
                    p_weak.append("ssh_key_blocked_allowusers")

                # Local privilege escalation on pivot: mix of real vs runtime-mitigated
                roll = rng.random()
                if roll < 0.38:
                    p_weak.append({
                        "id": "nopasswd_sudo",
                        "params": {"binary": rng.choice(_SUDO_BINARIES)},
                    })
                elif roll < 0.72:
                    p_weak.append({
                        "id": "nopasswd_sudo_noexec",
                        "params": {"binary": rng.choice(_SUDO_BINARIES)},
                    })
                elif roll < 0.90:
                    p_weak.append("suid_nosuid_mount")

                # Collector decoy on ~60% of pivots
                if rng.random() < 0.60:
                    p_weak.append({
                        "id": "decoy_nopasswd",
                        "params": {"binary": rng.choice(_DECOY_BINARIES)},
                    })

            hosts.append({
                "id": pid,
                "role": role,
                "asset": 30 if role == "app" else 50,
                "weaknesses": p_weak,
            })

        # Database tier (core-only); db01 is always the crown jewel
        for d in range(n_dbs):
            did = f"db{d + 1:02d}"
            d_weak: list[Any] = []
            if is_hardened_variant:
                d_weak.append({
                    "id": "decoy_nopasswd",
                    "params": {"binary": rng.choice(_DECOY_BINARIES)},
                })
            else:
                # Primary DB accepts shared key in most variants; occasionally blocked
                if d == 0 and rng.random() < 0.85:
                    d_weak.append("accepts_shared_key")
                elif rng.random() < 0.5:
                    d_weak.append("accepts_shared_key")
                else:
                    d_weak.append("ssh_key_blocked_allowusers")

                # Local escalation on DB: mix of real SUID, real sudo, mitigated SUID, mitigated sudo, and DirtyPipe
                if rng.random() < 0.70:
                    d_weak.append({
                        "id": "suid_binary",
                        "params": {"suid_path": rng.choice(_SUID_BINARIES)},
                    })
                else:
                    d_weak.append("suid_nosuid_mount")

                if rng.random() < 0.35:
                    d_weak.append({
                        "id": "nopasswd_sudo",
                        "params": {"binary": rng.choice(_SUDO_BINARIES)},
                    })
                elif rng.random() < 0.55:
                    d_weak.append("nopasswd_sudo_noexec")

                if rng.random() < 0.45:
                    d_weak.append("dirtypipe_kernel")

            hosts.append({
                "id": did,
                "role": "database",
                "asset": 100 if d == 0 else 80,
                "weaknesses": d_weak,
            })

        bp: dict[str, Any] = {
            "scenario": vid,
            "variant_id": vid,
            "split": assign_split(vid, seed=seed),
            "seed": seed,
            "hardened": is_hardened_variant,
            "description": (
                f"Seeded variant {vid} ({len(hosts)} hosts, {n_pivots} pivot(s), "
                f"{n_dbs} db(s), {'hardened' if is_hardened_variant else 'mixed'})"
            ),
            "hosts": hosts,
            "entry": {"host": "web01", "account": "www-data", "privilege": "low"},
            "crown_jewel": {"host": "db01", "privilege": "root"},
        }

        errs = validate(bp, roles=roles, weaknesses=weaknesses)
        if errs:
            raise ValueError(f"Generated invalid blueprint {vid}: {errs}")
        variants.append(bp)

    return variants


def blueprint_to_facts(
    blueprint: dict[str, Any],
    roles: dict | None = None,
    weaknesses: dict | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Materialize a ``facts.json``-compatible graph + collection report from a blueprint.

    Explicitly marks provenance as ``declared`` (blueprint-derived, not live
    Docker capture) and records collector-declined decoys in ``skipped``.
    """
    roles = roles if roles is not None else load_host_types()
    weaknesses = weaknesses if weaknesses is not None else load_weaknesses()

    hosts_out: list[dict[str, Any]] = []
    accounts_out: list[dict[str, Any]] = []
    vectors_out: list[dict[str, Any]] = []
    skipped_out: list[dict[str, Any]] = []
    host_nets: dict[str, set[str]] = {}
    key_grants: list[dict[str, Any]] = []
    key_found_at: list[dict[str, Any]] = []
    discoverable_at: dict[str, str] | None = None

    for h in blueprint.get("hosts") or []:
        hid = h["id"]
        role = h["role"]
        role_def = roles[role]
        acct = role_def["account"]
        nets = set(h.get("networks") or role_def.get("networks") or [])
        host_nets[hid] = nets
        kernel = role_def["default_kernel"]
        wlist = normalize_weaknesses(h.get("weaknesses"))

        # Check kernel override from host_build
        for w in wlist:
            hb = (weaknesses[w["id"]].get("host_build") or {})
            if hb.get("declared_kernel"):
                kernel = hb["declared_kernel"]

        hosts_out.append({
            "hostname": hid,
            "role": role,
            "os": "Debian 12 (bookworm)",
            "kernel": kernel,
            "asset_value": h.get("asset", 10),
        })
        accounts_out.append({
            "host": hid,
            "username": acct["name"],
            "privilege": "low",
            "type": "service",
        })
        accounts_out.append({
            "host": hid,
            "username": "root",
            "privilege": "root",
            "type": "system",
        })

        for w in wlist:
            wid = w["id"]
            wk = weaknesses[wid]
            params = dict(wk.get("params") or {})
            params.update(w.get("params") or {})
            kind = wk.get("kind", "exploitable")
            tech = wk["technique"]

            if kind == "decoy":
                skipped_out.append({
                    "host": hid,
                    "technique": tech,
                    "rule": f"NOPASSWD: {params.get('binary', '/bin/ls')}",
                    "reason": f"{params.get('binary', '/bin/ls')} has no documented shell escape",
                })
                continue

            if wid in ("accepts_shared_key", "ssh_key_blocked_allowusers"):
                key_grants.append({
                    "host": hid,
                    "username": acct["name"],
                    "privilege": "low",
                    "mitigation": wk.get("mitigation"),
                    "weakness_id": wid,
                })
                if wid == "accepts_shared_key" and params.get("store_correct_copy"):
                    key_found_at.append({
                        "host": hid,
                        "path": f"{acct['home']}/.ssh/id_rsa",
                        "mode": "0600",
                    })
                    skipped_out.append({
                        "host": hid,
                        "technique": "T1552.001",
                        "path": f"{acct['home']}/.ssh/id_rsa",
                        "reason": "mode 0600 — readable only by owner",
                    })
                continue

            tmeta = _TECHNIQUE_META.get(tech, {"name": wk.get("title", tech), "cvss": 5.0, "epss": 0.2})
            mitigation = wk.get("mitigation")
            vid = f"v_{hid}_{wid}"
            vec: dict[str, Any] = {
                "vector_id": vid,
                "host": hid,
                "technique": tech,
                "technique_name": tmeta["name"],
                "cve": params.get("cve") or tmeta.get("cve"),
                "cvss": tmeta["cvss"],
                "kind": "credential_access" if tech == "T1552.001" else "privilege_escalation_local",
                "requires": {"host": hid, "privilege": "low"},
                **({"reads_credential": "app_deploy_key"} if tech == "T1552.001" else {"gains": {"host": hid, "privilege": "root"}}),
                "config_exploitable": True,
                "verified_exploitable": None,
                "features": {
                    "provenance": "declared",
                    "weakness_id": wid,
                    "executable_in": wk.get("executable_in", "either"),
                    "epss_prior": tmeta["epss"],
                    "sudo_noexec": mitigation == "sudo_noexec",
                    "nosuid_mount": mitigation == "nosuid_mount",
                    "sshd_deny_users": mitigation == "sshd_deny_users",
                    "is_dual_homed": len(nets) > 1,
                    "kernel_in_affected_range": tech == "T1068",
                },
            }
            if wid == "readable_ssh_key":
                discoverable_at = {"host": hid, "privilege": "low"}
                key_found_at.append({
                    "host": hid,
                    "path": f"{acct['home']}/.ssh/id_rsa",
                    "mode": "0644",
                })
            vectors_out.append(vec)

    # Reachability edges: hosts sharing a Docker network can reach each other on SSH (22)
    reachability: list[dict[str, Any]] = []
    host_ids = [h["hostname"] for h in hosts_out]
    for src in host_ids:
        for dst in host_ids:
            if src == dst:
                continue
            if host_nets[src] & host_nets[dst]:
                reachability.append({
                    "from": src,
                    "to": dst,
                    "port": 22,
                    "service": "ssh",
                })

    credentials_out: list[dict[str, Any]] = []
    if discoverable_at and len(key_grants) >= 1:
        credentials_out.append({
            "cred_id": "app_deploy_key",
            "type": "ssh_private_key",
            "discoverable_at": discoverable_at,
            "grants": [
                {"host": g["host"], "account": g["username"], "privilege": g["privilege"]}
                for g in key_grants
            ],
            "features": {
                "provenance": "declared",
                "reuse_count": len(key_grants),
                "found_at": key_found_at,
                "blocked_hosts": [
                    g["host"] for g in key_grants if g.get("mitigation") == "sshd_deny_users"
                ],
            },
        })

    facts = {
        "_meta": {
            "source": f"blueprint:{blueprint.get('scenario', 'variant')}",
            "variant_id": blueprint.get("variant_id", blueprint.get("scenario")),
            "split": blueprint.get("split", "train"),
            "mode": "lab_blueprint",
        },
        "entry": blueprint["entry"],
        "crown_jewel": blueprint["crown_jewel"],
        "hosts": hosts_out,
        "accounts": accounts_out,
        "reachability": reachability,
        "credentials": credentials_out,
        "vectors": vectors_out,
    }
    report = {
        "hosts_probed": host_ids,
        "counts": {"vectors": len(vectors_out), "skipped": len(skipped_out)},
        "skipped": skipped_out,
    }
    return facts, report


def materialize_variant_outcomes(
    variants: list[dict[str, Any]],
    roles: dict | None = None,
    weaknesses: dict | None = None,
    *,
    backend: str = "container",
) -> list[dict[str, Any]]:
    """Produce structured outcome records from generated blueprints for offline benchmarking.

    Every record is explicitly tagged ``label_source="catalogue_ground_truth"`` so
    it is never confused with a live Docker canary run; live runs from
    ``verifier/runner.py`` use the same schema and replace these records directly.
    """
    roles = roles if roles is not None else load_host_types()
    weaknesses = weaknesses if weaknesses is not None else load_weaknesses()

    records: list[dict[str, Any]] = []
    for bp in variants:
        vid = bp.get("variant_id", bp.get("scenario", "unknown"))
        split = bp.get("split", "train")
        facts, _ = blueprint_to_facts(bp, roles=roles, weaknesses=weaknesses)

        # Local vectors
        for vec in facts["vectors"]:
            wid = (vec.get("features") or {}).get("weakness_id", "")
            wk = weaknesses.get(wid, {})
            exec_in = wk.get("executable_in", "either")
            expected = wk.get("expected_outcome", "escalated")

            if backend == "container" and exec_in == "vm":
                status = "not_executable"
                escalated = False
                reason = "shared-kernel container cannot execute VM-only kernel exploit"
            elif expected == "not_escalated":
                status = "not_escalated"
                escalated = False
                reason = f"mitigated at runtime ({wk.get('mitigation', 'runtime_mitigated')})"
            else:
                status = "escalated"
                escalated = True
                reason = ""

            records.append({
                "variant_id": vid,
                "split": split,
                "host": vec["host"],
                "technique": vec["technique"],
                "weakness_id": wid,
                "vector_id": vec["vector_id"],
                "escalated": escalated,
                "status": status,
                "reason": reason,
                "label_source": "catalogue_ground_truth",
                "host_facts_ref": f"{vid}:{vec['host']}:{vec['technique']}",
                "features_snapshot": dict(vec.get("features") or {}),
                "cvss": vec.get("cvss"),
                "host_asset_value": next(
                    (h["asset_value"] for h in facts["hosts"] if h["hostname"] == vec["host"]),
                    0,
                ),
                "reuse_count": (
                    facts["credentials"][0]["features"]["reuse_count"]
                    if facts["credentials"] else 0
                ),
            })

        # Lateral SSH grants (one outcome per target host accepting/blocking the shared key)
        if facts["credentials"]:
            cred = facts["credentials"][0]
            blocked = set((cred.get("features") or {}).get("blocked_hosts") or [])
            reuse_count = (cred.get("features") or {}).get("reuse_count", 0)
            for grant in cred.get("grants", []):
                gh = grant["host"]
                is_blocked = gh in blocked
                records.append({
                    "variant_id": vid,
                    "split": split,
                    "host": gh,
                    "technique": "T1021.004+T1550",
                    "weakness_id": "ssh_key_blocked_allowusers" if is_blocked else "accepts_shared_key",
                    "vector_id": f"v_{gh}_lateral_ssh",
                    "escalated": not is_blocked,
                    "status": "not_escalated" if is_blocked else "escalated",
                    "reason": "sshd DenyUsers policy rejected login" if is_blocked else "",
                    "label_source": "catalogue_ground_truth",
                    "host_facts_ref": f"{vid}:{gh}:T1021.004+T1550",
                    "features_snapshot": {
                        "provenance": "declared",
                        "epss_prior": _TECHNIQUE_META["T1021.004+T1550"]["epss"],
                        "sudo_noexec": False,
                        "nosuid_mount": False,
                        "sshd_deny_users": is_blocked,
                        "is_dual_homed": any(
                            h["hostname"] == gh and h["role"] in ("app", "ci")
                            for h in facts["hosts"]
                        ),
                        "kernel_in_affected_range": False,
                    },
                    "cvss": _TECHNIQUE_META["T1021.004+T1550"]["cvss"],
                    "host_asset_value": next(
                        (h["asset_value"] for h in facts["hosts"] if h["hostname"] == gh),
                        0,
                    ),
                    "reuse_count": reuse_count,
                })

    return records

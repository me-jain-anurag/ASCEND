"""
Raw facts in, environment-graph facts out.

Every probe reports what it saw and nothing more. This module is the single
place where an observation becomes a claim — "appuser may run tar as root
without a password" becomes "app01 exposes vector T1548.003" — and it does so
only under a condition written down in scope.yaml.

Keeping the judgement here and nowhere else is what makes the collector
auditable: to see why ASCEND believes a host is exploitable, you read one rule
in scope.yaml and one function below, and the vector carries the raw evidence
that triggered it.

Output conforms to the facts schema in docs/02 section 4 — byte-compatible with
the hand-written environment_graph/facts.sample.json, so the enumerator, the
FastAPI service and the dashboard are unchanged.
"""

from __future__ import annotations

import re

# ─── Provenance ───────────────────────────────────────────────────────────────
# observed : read from the live host by a probe.
# declared : supplied by the operator (scope.yaml inventory, or the lab's
#            simulated kernel). No scan could have produced it.
OBSERVED = "observed"
DECLARED = "declared"


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def _vtuple(version: str) -> tuple[int, ...]:
    """'5.16.11-rc2' -> (5, 16, 11). Non-numeric suffixes are dropped."""
    parts = []
    for chunk in re.split(r"[.\-+~]", version or ""):
        m = re.match(r"^(\d+)", chunk)
        if not m:
            break
        parts.append(int(m.group(1)))
    return tuple(parts) or (0,)


def _kg_for(kg: dict, technique: str) -> dict:
    entry = kg.get("techniques", {}).get(technique, {})
    return {
        "cwe":   entry.get("cwe", []),
        "capec": entry.get("capec", []),
        "tactic": entry.get("tactic"),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Hosts and accounts
# ─────────────────────────────────────────────────────────────────────────────

def derive_hosts(raw: dict, scope: dict) -> list[dict]:
    inventory = scope.get("inventory", {}).get("hosts", {})
    hosts = []
    for hostname in sorted(raw):
        kern = raw[hostname]["kernel"]
        declared = inventory.get(hostname, {})
        hosts.append({
            "hostname":    hostname,
            # role and asset_value are business inputs, not scan results.
            "role":        declared.get("role", "unknown"),
            "asset_value": declared.get("asset_value", 0),
            "os":          kern.get("os", "linux"),
            "kernel":      kern.get("effective_kernel"),
            # Both kernel values travel together so they can never be conflated.
            "observed_kernel": kern.get("observed_kernel"),
            "declared_kernel": kern.get("declared_kernel"),
            "kernel_provenance": kern.get("provenance", OBSERVED),
            "distribution": kern.get("distribution"),
            "inventory_provenance": DECLARED,
        })
    return hosts


def derive_accounts(raw: dict) -> list[dict]:
    accounts = []
    for hostname in sorted(raw):
        for acct in raw[hostname]["accounts"]:
            accounts.append({
                "host":      hostname,
                "username":  acct["username"],
                "type":      acct["type"],
                "privilege": acct["privilege"],
                "uid":       acct["uid"],
                "shell":     acct["shell"],
            })
    return accounts


# ─────────────────────────────────────────────────────────────────────────────
# Credentials — the reuse detection
# ─────────────────────────────────────────────────────────────────────────────

def derive_credentials(raw: dict, scope: dict) -> tuple[list[dict], dict]:
    """Match private keys found on disk against every host's authorized_keys.

    Returns (credentials, fingerprint -> cred_id) so the vector builder can name
    the credential a readable-file vector discloses.

    The match is on the SHA256 fingerprint of the public key blob. Two files can
    have different names, different comments and different modes and still be
    the same key; only the fingerprint settles it.
    """
    # Every public key any account accepts, indexed by fingerprint.
    accepted: dict[str, list[dict]] = {}
    for hostname in sorted(raw):
        for entry in raw[hostname]["authorized_keys"]:
            accepted.setdefault(entry["fingerprint"], []).append(entry)

    # Every private key sitting on disk, indexed by fingerprint.
    private: dict[str, list[dict]] = {}
    for hostname in sorted(raw):
        for finding in raw[hostname]["cred_files"]:
            if finding.get("is_private_key") and finding.get("key_fingerprint"):
                private.setdefault(finding["key_fingerprint"], []).append(
                    {**finding, "host": hostname})

    credentials, by_fingerprint = [], {}

    for fingerprint, locations in sorted(private.items()):
        # Prefer the key's own comment as the identifier — it is what an
        # operator would call it. Fall back to a fingerprint-derived slug.
        comment = next((loc.get("key_comment") for loc in locations
                        if loc.get("key_comment")), None)
        cred_id = _slug(comment) if comment else \
            "key_" + fingerprint.split(":", 1)[-1][:10].lower().replace("/", "")

        # Where it can be picked up: the readable copies only. A key at 0600 is
        # on disk but is not *discoverable* by another account.
        readable = [loc for loc in locations
                    if loc["other_readable"] or loc["group_readable"]]
        primary = readable[0] if readable else locations[0]

        grants = []
        for entry in accepted.get(fingerprint, []):
            grants.append({
                "host":      entry["host"],
                "account":   entry["account"],
                "privilege": entry["privilege"],
            })

        credentials.append({
            "cred_id": cred_id,
            "type":    "ssh_key",
            "discoverable_at": {
                "host":      primary["host"],
                "privilege": "low" if (primary["other_readable"] or
                                       primary["group_readable"]) else "root",
            },
            "grants": sorted(grants, key=lambda g: (g["host"], g["account"])),
            "features": {
                "provenance":  OBSERVED,
                "detected_by": "probes/cred_files.py + probes/ssh_keys.py",
                "fingerprint": fingerprint,
                "key_type":    primary.get("key_type"),
                "encrypted":   primary.get("key_encrypted"),
                "found_at":    [{"host": loc["host"], "path": loc["path"],
                                 "mode": loc["mode"]} for loc in locations],
                "accepted_by": [{"host": g["host"], "account": g["account"],
                                 "path": e["path"]}
                                for g, e in zip(grants, accepted.get(fingerprint, []))],
                # The chokepoint claim, stated as a number.
                "reuse_count": len({g["host"] for g in grants}),
            },
        })
        by_fingerprint[fingerprint] = cred_id

    return credentials, by_fingerprint


# ─────────────────────────────────────────────────────────────────────────────
# Reachability
# ─────────────────────────────────────────────────────────────────────────────

def derive_reachability(raw_matrix: list[dict]) -> list[dict]:
    """Keep the edges that actually connected. Failures are kept as evidence in
    the collection report, not in the graph."""
    edges = []
    for attempt in raw_matrix:
        if not attempt["reachable"]:
            continue
        edges.append({
            "from":    attempt["from"],
            "to":      attempt["to"],
            "port":    attempt["port"],
            "service": attempt["service"],
            "features": {
                "provenance":  OBSERVED,
                "detected_by": "probes/reachability.py",
                "evidence":    attempt["evidence"],
            },
        })
    return sorted(edges, key=lambda e: (e["from"], e["to"], e["port"]))


# ─────────────────────────────────────────────────────────────────────────────
# Vectors — one builder per technique
# ─────────────────────────────────────────────────────────────────────────────

def derive_vectors(raw: dict, scope: dict, kg: dict,
                   cred_by_fingerprint: dict) -> tuple[list[dict], list[dict]]:
    """Returns (vectors, skipped) — `skipped` records conditions that were
    examined and deliberately NOT reported, which is what shows the rules are
    discriminating rather than indiscriminate."""
    vectors: list[dict] = []
    skipped: list[dict] = []
    rules = scope.get("rules", {})
    techniques = scope.get("techniques", {})

    def technique_name(tid: str) -> str:
        return techniques.get(tid, {}).get("name", tid)

    for hostname in sorted(raw):
        host_raw = raw[hostname]

        _credential_access(hostname, host_raw, rules, kg, cred_by_fingerprint,
                           technique_name, vectors, skipped)
        _sudo(hostname, host_raw, rules, kg, technique_name, vectors, skipped)
        _suid(hostname, host_raw, rules, kg, technique_name, vectors, skipped)
        _kernel(hostname, host_raw, rules, kg, technique_name, vectors, skipped)
        _container_escape(hostname, host_raw, rules, kg, technique_name,
                          vectors, skipped)

    return vectors, skipped


def _credential_access(host, raw, rules, kg, cred_by_fp, tname, out, skipped):
    """T1552.001 — a credential file readable by someone other than its owner."""
    cfg = rules.get("cred_files", {})
    require_readable = cfg.get("require_other_or_group_readable", True)

    for finding in raw["cred_files"]:
        exposed = finding["other_readable"] or finding["group_readable"]
        if require_readable and not exposed:
            skipped.append({
                "host": host, "technique": "T1552.001", "path": finding["path"],
                "reason": f"mode {finding['mode']} — readable only by its owner, "
                          f"not a disclosure",
            })
            continue
        if not finding.get("is_private_key"):
            skipped.append({
                "host": host, "technique": "T1552.001", "path": finding["path"],
                "reason": "readable, but no credential material recognised in it",
            })
            continue

        cred_id = cred_by_fp.get(finding.get("key_fingerprint"))
        if not cred_id:
            skipped.append({
                "host": host, "technique": "T1552.001", "path": finding["path"],
                "reason": "private key could not be fingerprinted (legacy PEM)",
            })
            continue

        out.append({
            "vector_id":      f"v_{host}_credfile_{_slug(finding['path'].rsplit('/', 1)[-1])}",
            "host":           host,
            "technique":      "T1552.001",
            "technique_name": tname("T1552.001"),
            "kind":           "credential_access",
            "reads_credential": cred_id,
            "requires":       {"host": host, "privilege": "low"},
            "cvss":           cfg.get("cvss", 5.5),
            "verified_exploitable": None,
            "config_exploitable":   True,
            "description": (
                f"{finding['path']} is mode {finding['mode']} "
                f"(owner {finding['owner']}) and contains an unencrypted "
                f"{finding.get('key_type')} private key, so any local account "
                f"on {host} can read it."
            ),
            "features": {
                "provenance":  OBSERVED,
                "detected_by": "probes/cred_files.py",
                "rule":        "rules.cred_files",
                "evidence": {
                    "path":  finding["path"], "mode": finding["mode"],
                    "owner": finding["owner"], "group": finding["group"],
                    "other_readable": finding["other_readable"],
                    "group_readable": finding["group_readable"],
                    "fingerprint": finding.get("key_fingerprint"),
                },
                "kg": _kg_for(kg, "T1552.001"),
            },
        })


def _sudo(host, raw, rules, kg, tname, out, skipped):
    """T1548.003 — a NOPASSWD sudo rule naming a binary with a shell escape."""
    cfg = rules.get("sudo", {})
    escapable = set(cfg.get("shell_escape_binaries", []))
    require_nopasswd = cfg.get("require_nopasswd", True)

    for rule in raw["sudo"]["rules"]:
        if require_nopasswd and not rule["nopasswd"]:
            skipped.append({
                "host": host, "technique": "T1548.003", "rule": rule["raw"],
                "reason": "sudo rule requires a password",
            })
            continue
        if rule["binary"] not in escapable:
            skipped.append({
                "host": host, "technique": "T1548.003", "rule": rule["raw"],
                "reason": f"{rule['binary']} has no documented shell escape",
            })
            continue
        if rule["runas"] not in ("root", "ALL"):
            skipped.append({
                "host": host, "technique": "T1548.003", "rule": rule["raw"],
                "reason": f"runs as {rule['runas']}, not root",
            })
            continue

        out.append({
            "vector_id":      f"v_{host}_sudo_{_slug(rule['binary'].rsplit('/', 1)[-1])}",
            "host":           host,
            "technique":      "T1548.003",
            "technique_name": tname("T1548.003"),
            "kind":           "privilege_escalation_local",
            "requires":       {"host": host, "privilege": "low"},
            "gains":          {"host": host, "privilege": "root"},
            "cvss":           cfg.get("cvss", 7.8),
            "verified_exploitable": None,
            "config_exploitable":   True,
            "description": (
                f"{rule['user']} may run {rule['command']} as {rule['runas']} "
                f"with no password; {rule['binary'].rsplit('/', 1)[-1]} has a "
                f"documented shell escape, making the rule equivalent to a root shell."
            ),
            "features": {
                "provenance":  OBSERVED,
                "detected_by": "probes/sudo.py",
                "rule":        "rules.sudo",
                "evidence": {
                    "sudo_l_output": rule["raw"],
                    "user":  rule["user"], "runas": rule["runas"],
                    "binary": rule["binary"], "nopasswd": rule["nopasswd"],
                    "policy_files": raw["sudo"]["policy_files"],
                },
                "kg": _kg_for(kg, "T1548.003"),
            },
        })


def _suid(host, raw, rules, kg, tname, out, skipped):
    """T1548.001 — a setuid-root binary outside the distribution baseline."""
    cfg = rules.get("suid", {})
    baseline = set(cfg.get("baseline", []))
    escapable = set(cfg.get("shell_escape_binaries", []))

    for entry in raw["suid"]:
        if entry["owner"] != "root":
            continue
        if entry["path"] in baseline:
            continue          # expected on any Debian host; not a finding
        if entry["path"] not in escapable:
            skipped.append({
                "host": host, "technique": "T1548.001", "path": entry["path"],
                "reason": "setuid and non-baseline, but no documented shell escape",
            })
            continue

        out.append({
            "vector_id":      f"v_{host}_suid_{_slug(entry['path'].rsplit('/', 1)[-1])}",
            "host":           host,
            "technique":      "T1548.001",
            "technique_name": tname("T1548.001"),
            "kind":           "privilege_escalation_local",
            "requires":       {"host": host, "privilege": "low"},
            "gains":          {"host": host, "privilege": "root"},
            "cvss":           cfg.get("cvss", 7.8),
            "verified_exploitable": None,
            "config_exploitable":   True,
            "description": (
                f"{entry['path']} is setuid root (mode {entry['mode']}), is not "
                f"part of the distribution baseline, and has a documented shell escape."
            ),
            "features": {
                "provenance":  OBSERVED,
                "detected_by": "probes/suid.py",
                "rule":        "rules.suid",
                "evidence":    entry,
                "kg":          _kg_for(kg, "T1548.001"),
            },
        })


def _kernel(host, raw, rules, kg, tname, out, skipped):
    """T1068 — the effective kernel falls in a known-vulnerable range.

    Linux fixes are backported per stable branch, so a single "fixed in X"
    threshold is wrong: 5.15.30 is patched for DirtyPipe even though it is
    below 5.16.11. Matching is therefore done against the fix for the host's
    OWN branch, falling back to the highest fix only when the branch is unknown.
    """
    cfg = rules.get("kernel", {})
    kern = raw["kernel"]
    version = kern.get("effective_kernel")
    if not version:
        return
    current = _vtuple(version)

    for cve in cfg.get("cves", []):
        if cve.get("package"):
            continue          # package-based, not kernel-based (e.g. PwnKit)

        fixes = cve.get("fixed_versions") or [cve.get("fixed_version")]
        fixes = [_vtuple(f) for f in fixes if f]
        branch = current[:2]
        branch_fix = next((f for f in fixes if f[:2] == branch), None)
        effective_fix = branch_fix or max(fixes)

        introduced = _vtuple(cve.get("min_version", "0"))
        vulnerable = introduced <= current < effective_fix

        fix_str = ".".join(str(n) for n in effective_fix)
        if not vulnerable:
            skipped.append({
                "host": host, "technique": "T1068", "cve": cve["cve"],
                "reason": (
                    f"kernel {version} is below the affected range"
                    if current < introduced else
                    f"kernel {version} is at or above the {'.'.join(str(n) for n in branch)} "
                    f"branch fix {fix_str}"
                ),
            })
            continue

        out.append({
            "vector_id":      f"v_{host}_kernel_{_slug(cve['cve'])}",
            "host":           host,
            "technique":      "T1068",
            "technique_name": f"{tname('T1068')} ({cve.get('name', cve['cve'])})",
            "kind":           "privilege_escalation_local",
            "cve":            cve["cve"],
            "requires":       {"host": host, "privilege": "low"},
            "gains":          {"host": host, "privilege": "root"},
            "cvss":           cve.get("cvss", 7.8),
            "verified_exploitable": None,
            "config_exploitable":   True,
            "description": (
                f"{host} reports kernel {version}, within the {cve['cve']} "
                f"({cve.get('name')}) affected range "
                f"{cve.get('min_version')} <= v < {fix_str}; a local account can "
                f"overwrite a root-owned file to gain root."
            ),
            "features": {
                # THE IMPORTANT ONE. In a container lab the kernel version is
                # supplied, not measured, and this says so on every vector.
                "provenance":     kern.get("provenance", OBSERVED),
                "detected_by":    "probes/kernel.py",
                "rule":           "rules.kernel",
                "evidence": {
                    "effective_kernel": version,
                    "observed_kernel":  kern.get("observed_kernel"),
                    "declared_kernel":  kern.get("declared_kernel"),
                    "branch_fix":       fix_str,
                    "note": (
                        "Containers share the host kernel, so this host's kernel "
                        "version is declared in the image rather than measured. "
                        "The VM fallback in docs/02 section 6 makes it observed."
                    ) if kern.get("provenance") == DECLARED else None,
                },
                "kg": {**_kg_for(kg, "T1068"),
                       "cve": kg.get("cves", {}).get(cve["cve"], {})},
            },
        })


def _container_escape(host, raw, rules, kg, tname, out, skipped):
    """T1611 — a mounted Docker socket, or docker-group membership."""
    cfg = rules.get("docker_socket", {})
    data = raw["docker_socket"]
    if not data["sockets"] and not data["docker_group_members"]:
        return

    for sock in data["sockets"]:
        out.append({
            "vector_id":      f"v_{host}_docker_socket",
            "host":           host,
            "technique":      "T1611",
            "technique_name": tname("T1611"),
            "kind":           "privilege_escalation_local",
            "requires":       {"host": host, "privilege": "low"},
            "gains":          {"host": host, "privilege": "root"},
            "cvss":           cfg.get("cvss", 8.8),
            "verified_exploitable": None,
            "config_exploitable":   True,
            "description": (
                f"{sock['path']} is mounted inside {host} (mode {sock['mode']}, "
                f"group {sock['group']}); socket access permits launching a "
                f"privileged container and is root-equivalent on the host."
            ),
            "features": {
                "provenance":  OBSERVED,
                "detected_by": "probes/docker_socket.py",
                "rule":        "rules.docker_socket",
                "evidence":    {**sock,
                                "docker_group_members": data["docker_group_members"]},
                "kg": _kg_for(kg, "T1611"),
            },
        })

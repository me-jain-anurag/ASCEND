"""Real in-container remediation commands for Lab-mode proof loop.

In Assessment mode (read-only production), applying a fix is a safe in-memory
what-if projection over ``facts.json``. In Lab mode (live demo proof loop),
this module executes the actual Linux hardening command inside the target
Docker container via ``verifier.lab.exec_as`` so the subsequent re-collection /
re-verification genuinely observes the remediated host state.
"""

from __future__ import annotations

from typing import Any


def remediation_command_for_vector(vector: dict[str, Any]) -> list[str]:
    """Return the concrete Linux root command that remediates *vector* in the lab."""
    tech = (vector.get("technique") or "").upper()
    feats = vector.get("features") or {}
    ev = feats.get("evidence") or {}

    if tech == "T1552.001":
        path = ev.get("path") or feats.get("path") or "/var/www/.ssh/id_rsa"
        return ["chmod", "0600", path]

    if tech == "T1548.001":
        path = ev.get("path") or feats.get("suid_path") or "/usr/bin/find"
        return ["chmod", "u-s", path]

    if tech == "T1548.003":
        policy_files = ev.get("policy_files") or {}
        if policy_files:
            target = next(iter(policy_files.keys()))
            return ["rm", "-f", target]
        user = ev.get("user") or "appuser"
        return ["rm", "-f", f"/etc/sudoers.d/{user}"]

    if tech == "T1611":
        return ["chmod", "0600", "/var/run/docker.sock"]

    raise ValueError(
        f"No live-container remediation command supported for technique {tech!r} "
        f"(e.g., kernel CVEs like T1068 require a VM kernel patch/reboot)."
    )


def execute_live_remediation(
    host: str,
    vector: dict[str, Any],
    *,
    container_prefix: str = "ascend-",
) -> dict[str, Any]:
    """Execute the real remediation command on *host* as root inside the lab container."""
    from verifier.lab import exec_as

    cmd = remediation_command_for_vector(vector)
    code, stdout, stderr = exec_as(host, "root", cmd, prefix=container_prefix)
    return {
        "host": host,
        "command": cmd,
        "exit_code": code,
        "stdout": stdout.strip(),
        "stderr": stderr.strip(),
        "applied_live": code == 0,
    }

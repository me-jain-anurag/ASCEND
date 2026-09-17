"""Probe: Docker socket exposure and docker-group membership (evidence for T1611).

The default lab plants no container-escape vector, so this probe is expected to
return nothing. It is here so that the ci01 host from docs/02 section 6 needs no
new collector code when it is added.
"""

from __future__ import annotations


def collect(host: str, tp, scope: dict) -> dict:
    paths = scope.get("rules", {}).get("docker_socket", {}).get(
        "paths", ["/var/run/docker.sock"])

    sockets = []
    for path in paths:
        res = tp.run(host, ["stat", "-c", "%a|%U|%G|%F", path])
        if res.ok and res.stdout.strip():
            mode, owner, group, kind = res.stdout.strip().split("|", 3)
            sockets.append({"path": path, "mode": mode, "owner": owner,
                            "group": group, "kind": kind})

    members = []
    group_line = tp.read_file(host, "/etc/group") or ""
    for line in group_line.splitlines():
        parts = line.split(":")
        if len(parts) == 4 and parts[0] == "docker":
            members = [m for m in parts[3].split(",") if m]

    return {"sockets": sockets, "docker_group_members": members}

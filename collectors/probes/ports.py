"""Probe: listening TCP sockets.

Used for two things: to know which ports the reachability probe should try, and
to name the service on each reachability edge.

Listeners bound to loopback are reported but flagged, and the reachability sweep
skips them. A socket bound to 127.0.0.0/8 or ::1 is reachable only from inside
its own network namespace, so it cannot be a lateral-movement target by
definition — probing it from another host would be a guaranteed-useless attempt.

In this lab that rule removes Docker's embedded DNS resolver on 127.0.0.11,
which otherwise shows up as an unexplained high port on every single host.
"""

from __future__ import annotations

import ipaddress
import re

PORT_SERVICE = {
    22: "ssh", 80: "http", 443: "https", 3306: "mysql",
    5432: "postgresql", 6379: "redis", 27017: "mongodb", 2375: "docker-api",
}

_PROC = re.compile(r'users:\(\("([^"]+)"')


def _is_loopback(address: str) -> bool:
    cleaned = address.strip("[]")
    if cleaned in ("*", "", "0.0.0.0", "::"):
        return False                     # wildcard binds are externally reachable
    try:
        return ipaddress.ip_address(cleaned).is_loopback
    except ValueError:
        return False


def collect(host: str, tp, scope: dict) -> list[dict]:
    res = tp.run(host, ["ss", "-ltnpH"])
    if not res.ok or not res.stdout.strip():
        res = tp.run(host, ["ss", "-ltnH"])       # without -p if not permitted

    out = []
    for line in res.stdout.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        local = fields[3]
        address, _, port = local.rpartition(":")
        if not port.isdigit():
            continue
        proc = _PROC.search(line)
        out.append({
            "proto":    "tcp",
            "address":  address,
            "port":     int(port),
            "service":  PORT_SERVICE.get(int(port), "unknown"),
            "process":  proc.group(1) if proc else None,
            "loopback": _is_loopback(address),
        })

    # Deduplicate the 0.0.0.0 / [::] pair sshd produces for the same port. Sort
    # externally-bound listeners first so that if a port is bound both ways, the
    # reachable binding is the one that survives.
    out.sort(key=lambda e: (e["port"], e["loopback"]))
    seen, unique = set(), []
    for entry in out:
        if entry["port"] in seen:
            continue
        seen.add(entry["port"])
        unique.append(entry)
    return unique

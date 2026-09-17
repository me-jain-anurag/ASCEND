"""Probe: setuid-root binaries.

-xdev keeps the walk inside the container's own filesystem so bind-mounted host
paths are never traversed.
"""

from __future__ import annotations


def collect(host: str, tp, scope: dict) -> list[dict]:
    res = tp.run(host, [
        "find", "/", "-xdev", "-type", "f", "-perm", "-4000",
        "-printf", "%m|%u|%g|%s|%p\n",
    ], timeout=60)
    # find exits non-zero when it hits an unreadable directory; its stdout is
    # still valid, so parse regardless of the exit code.
    out = []
    for line in res.stdout.splitlines():
        parts = line.split("|", 4)
        if len(parts) != 5:
            continue
        mode, owner, group, size, path = parts
        out.append({
            "path":  path,
            "mode":  mode,
            "owner": owner,
            "group": group,
            "size":  int(size) if size.isdigit() else None,
        })
    return sorted(out, key=lambda e: e["path"])

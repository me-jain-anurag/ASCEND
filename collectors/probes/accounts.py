"""Probe: local accounts, from /etc/passwd.

Only accounts with a real login shell are reported. A Debian base image carries
~20 system accounts pinned to /usr/sbin/nologin; none of them is a foothold, and
emitting them would bury the three that matter in noise.
"""

from __future__ import annotations

NON_LOGIN_SHELLS = {
    "/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false",
    "/bin/sync", "/usr/bin/sync", "",
}


def collect(host: str, tp, scope: dict) -> list[dict]:
    text = tp.read_file(host, "/etc/passwd") or ""
    accounts = []
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) != 7:
            continue
        username, _pw, uid, gid, gecos, home, shell = parts
        try:
            uid_i = int(uid)
        except ValueError:
            continue
        if shell in NON_LOGIN_SHELLS:
            continue

        # uid 0 is root by definition. Everything else is classified `service`:
        # inside a container lab there is no identity source that could tell a
        # human operator from a daemon account, and inventing the distinction
        # would be a guess. A real deployment reads it from LDAP/AD.
        is_root = uid_i == 0
        accounts.append({
            "username":  username,
            "uid":       uid_i,
            "gid":       int(gid) if gid.isdigit() else None,
            "gecos":     gecos or None,
            "home":      home,
            "shell":     shell,
            "type":      "root" if is_root else "service",
            "privilege": "root" if is_root else "low",
        })
    return sorted(accounts, key=lambda a: a["uid"])

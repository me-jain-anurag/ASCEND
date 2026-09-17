"""Probe: sudo privileges, resolved by sudo itself.

`sudo -ln -U <user>` is authoritative — it applies aliases, group membership and
Defaults exactly as a real invocation would, which naive /etc/sudoers parsing
does not. The raw sudoers.d files are captured alongside it purely as evidence
to show a reviewer.
"""

from __future__ import annotations

import re

# "    (root) NOPASSWD: /bin/tar"  /  "    (ALL : ALL) ALL"
_RULE = re.compile(r"^\s*\(([^)]*)\)\s*(NOPASSWD:\s*|PASSWD:\s*)?(.+?)\s*$")


def collect(host: str, tp, scope: dict) -> dict:
    accounts = scope.get("_accounts", [])
    rules: list[dict] = []

    for acct in accounts:
        user = acct["username"]
        if acct["privilege"] == "root":
            continue  # root already has everything; a sudo rule adds nothing
        res = tp.run(host, ["sudo", "-ln", "-U", user])
        if not res.ok:
            continue
        for line in res.stdout.splitlines():
            if not line.startswith((" ", "\t")):
                continue          # section headers, not rules
            m = _RULE.match(line)
            if not m:
                continue
            runas_raw, nopasswd, command = m.groups()
            runas = runas_raw.split(":")[0].strip() or "root"
            for binary in (c.strip() for c in command.split(",")):
                if not binary:
                    continue
                rules.append({
                    "user":      user,
                    "runas":     runas,
                    "nopasswd":  bool(nopasswd and nopasswd.strip().startswith("NOPASSWD")),
                    "binary":    binary.split()[0],
                    "command":   binary,
                    "raw":       line.strip(),
                })

    # Raw policy files, for evidence only.
    files = {}
    listing = tp.run(host, ["sh", "-c", "ls -1 /etc/sudoers.d 2>/dev/null"])
    names = [n for n in listing.stdout.split() if n and not n.startswith("README")]
    for name in names:
        content = tp.read_file(host, f"/etc/sudoers.d/{name}")
        if content:
            files[f"/etc/sudoers.d/{name}"] = content.strip()

    return {"rules": rules, "policy_files": files}

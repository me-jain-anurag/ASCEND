"""Probe: credential material sitting in readable files (evidence for T1552.001).

The finding is the *permission*, not the presence. A private key at mode 0600 is
normal operations; the same key at 0644 is a disclosure. This probe records the
mode for every candidate and lets derive.py apply the rule, so the raw fact stays
raw and the judgement stays in one place.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import sshkeys  # noqa: E402


def collect(host: str, tp, scope: dict) -> list[dict]:
    rules = scope.get("rules", {}).get("cred_files", {})
    search_paths = rules.get("search_paths", ["/home", "/root", "/var/www"])
    filenames = rules.get("filenames", ["id_rsa", ".env"])

    name_expr = []
    for fn in filenames:
        name_expr += ["-name", fn, "-o"]
    name_expr = name_expr[:-1]  # drop trailing -o

    argv = ["find", *search_paths, "-maxdepth", "4", "-type", "f",
            "(", *name_expr, ")",
            "-printf", "%m|%u|%g|%s|%p\n"]
    res = tp.run(host, argv, timeout=60)

    findings = []
    for line in res.stdout.splitlines():
        parts = line.split("|", 4)
        if len(parts) != 5:
            continue
        mode, owner, group, size, path = parts

        # Octal permission digits: owner|group|other.
        perm = mode[-3:].rjust(3, "0")
        group_readable = int(perm[1]) & 4 != 0
        other_readable = int(perm[2]) & 4 != 0

        entry = {
            "path":  path,
            "mode":  perm,
            "owner": owner,
            "group": group,
            "size":  int(size) if size.isdigit() else None,
            "group_readable": group_readable,
            "other_readable": other_readable,
            "is_private_key": False,
            "key_type": None,
            "key_fingerprint": None,
            "key_comment": None,
            "key_encrypted": None,
        }

        content = tp.read_file(host, path)
        if content and sshkeys.looks_like_private_key(content):
            entry["is_private_key"] = True
            parsed = sshkeys.parse_private_key(content)
            if parsed:
                entry.update({
                    "key_type":        parsed["type"],
                    "key_fingerprint": parsed["fingerprint"],
                    "key_comment":     parsed["comment"],
                    "key_encrypted":   parsed["encrypted"],
                })
            else:
                # Legacy PEM key: no embedded public blob, so no fingerprint.
                # Still reported — an unprotected key is a finding either way.
                entry["key_type"] = "pem-legacy"
        findings.append(entry)

    return sorted(findings, key=lambda e: e["path"])

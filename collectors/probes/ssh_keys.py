"""Probe: which public keys each account accepts.

Cross-referenced against the private keys found by cred_files.py to detect
CREDENTIAL REUSE by fingerprint. This is the fact that turns one exposed key on
web01 into a path to two other hosts, and it is discovered, never declared.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import sshkeys  # noqa: E402


def collect(host: str, tp, scope: dict) -> list[dict]:
    accounts = scope.get("_accounts", [])
    out = []
    for acct in accounts:
        home = acct.get("home")
        if not home:
            continue
        for filename in ("authorized_keys", "authorized_keys2"):
            path = f"{home}/{filename}"
            content = tp.read_file(host, f"{home}/.ssh/{filename}")
            if content is None:
                continue
            for entry in sshkeys.parse_authorized_keys(content):
                out.append({
                    "host":      host,
                    "account":   acct["username"],
                    "privilege": acct["privilege"],
                    "path":      f"{home}/.ssh/{filename}",
                    **entry,
                })
    return out

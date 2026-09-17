"""Anchor-CVE adapter — BYO-exploit kernel privesc harness (T1068).

The verifier's job here is NOT to write or ship an exploit.  It is to run an
exploit artifact that already exists in the lab image and record whether it
reached root.  The exploit is an opaque, pre-placed binary the lab owner
installed; this adapter is a harness around it.

The bring-your-own-binary rule:
  - Workstream A places a built exploit binary inside the target's lab image
    at a fixed path (``exploit_ref`` in scope.yaml).
  - The verifier references that path.  It never contains, downloads, or
    generates exploit code.
  - If the binary is absent, the adapter returns ``escalated=False`` with
    evidence ``"exploit artifact not present"`` — a missing exploit is a
    negative label, not a crash.
"""

from __future__ import annotations

import shlex

from verifier.adapters import AdapterResult, RunContext, register
from verifier.lab import file_exists
from verifier.signal import escalated


@register("anchor_cve")
def anchor_cve(ctx: RunContext) -> AdapterResult:
    """Run a pre-placed exploit artifact and read the canary as root."""
    exploit = ctx.technique.get("exploit_ref", "")
    canary = ctx.canary_path

    # Guard: the binary must exist
    if not exploit or not file_exists(ctx.host, exploit, prefix=ctx.container_prefix):
        return AdapterResult(
            escalated=False,
            evidence="exploit artifact not present",
            raw_cmd=[],
        )

    # Guard: host must be in the technique's allowed list
    allowed_hosts = ctx.technique.get("hosts", [])
    if allowed_hosts and ctx.host not in allowed_hosts:
        return AdapterResult(
            escalated=False,
            evidence=f"host {ctx.host} not in allowed hosts: {allowed_hosts}",
            raw_cmd=[],
        )

    # Run the pre-placed artifact as the low-priv user.  On success it drops
    # us to a root context, in which we immediately read the root-only canary.
    payload = (
        f"{shlex.quote(exploit)} -- sh -c {shlex.quote(f'cat {canary}')} 2>&1"
    )
    cmd = ["sh", "-c", payload]

    ok, evidence = escalated(
        ctx.host, ctx.start_user, cmd, ctx.canary_token,
        prefix=ctx.container_prefix,
    )
    return AdapterResult(escalated=ok, evidence=evidence, raw_cmd=cmd)

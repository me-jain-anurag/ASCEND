"""The ONE pass/fail decision — did privilege actually escalate?

This module is the heart of the verifier.  Every adapter calls ``escalated()``
to decide its label, never by reading its own tool's exit code.  That rule is
what keeps every label honest and comparable across techniques.

Decision logic:
  1. Run the escalation command inside the container as the low-priv user.
  2. Check if the canary token (root-only secret) appears in stdout.
  3. If the canary is present, privilege genuinely escalated.  Period.
"""

from __future__ import annotations

from verifier.lab import exec_as


def escalated(
    host: str,
    run_as: str,
    escalate_cmd: list[str],
    expected_token: str,
    prefix: str = "ascend-",
) -> tuple[bool, str]:
    """Execute *escalate_cmd* as *run_as* on *host* and decide pass/fail.

    The command should end by reading the canary (e.g. ``cat /root/.ascend_canary``)
    in the escalated context.  If *expected_token* appears in stdout, privilege
    escalated — that is the only criterion.

    Returns ``(escalated: bool, evidence: str)``.  Evidence is the tail of the
    output for human audit.
    """
    code, out, err = exec_as(host, run_as, escalate_cmd, prefix=prefix)

    ok = expected_token in out
    if ok:
        evidence = out.strip()[-400:]
    else:
        evidence = (err or out).strip()[-400:]

    return ok, evidence


def credential_accessible(
    host: str,
    run_as: str,
    file_path: str,
    prefix: str = "ascend-",
) -> tuple[bool, str]:
    """Check whether *run_as* can read a credential file on *host*.

    This is the signal for T1552.001 (credential harvest).  It is not a
    privilege escalation — it is a credential access check.  Success means
    the file is readable and contains a private key header.
    """
    code, out, err = exec_as(
        host, run_as, ["cat", file_path], prefix=prefix,
    )
    ok = code == 0 and ("PRIVATE KEY" in out or "OPENSSH PRIVATE KEY" in out)
    evidence = out.strip()[:200] if ok else (err or out).strip()[-400:]
    return ok, evidence


def session_established(
    host: str,
    run_as: str,
    ssh_cmd: list[str],
    expected_user: str,
    prefix: str = "ascend-",
) -> tuple[bool, str]:
    """Check whether *run_as* can establish an SSH session to another host as *expected_user*.

    This is the signal for T1021.004+T1550 (lateral movement via credential reuse).
    Success means SSH connected and whoami/id returned *expected_user*.
    """
    code, out, err = exec_as(host, run_as, ssh_cmd, prefix=prefix)
    ok = code == 0 and expected_user in out
    evidence = out.strip()[-400:] if ok else (err or out).strip()[-400:]
    return ok, evidence


"""Anchor-CVE adapter — BYO-exploit kernel privesc harness (T1068).

The verifier's job here is NOT to write or ship an exploit. It is to run an
exploit artifact that already exists in the lab image and record whether it
reached root.

The bring-your-own-binary rule:
  - Workstream A places a built exploit binary inside the target's lab image at
    a fixed path (``exploit_ref`` in scope.yaml).
  - The verifier references that path. It never contains, downloads, or
    generates exploit code.
  - If the binary is absent, that is ``not_executable`` — a note about the lab,
    not evidence that the technique fails.

Why this adapter checks the kernel BEFORE running anything
----------------------------------------------------------
A kernel exploit can only work if the kernel it runs against is actually
vulnerable. In a container lab every host shares the *host machine's* kernel,
so `db01` does not really run the 5.16.0 its environment graph declares — that
value is planted for the graph (provenance: "declared") and cannot make the
running kernel vulnerable.

Without the precondition check below, any binary at ``exploit_ref`` that
returns root for some other reason — a setuid bit, a sudo rule, a wrapper
script — would be recorded as "CVE-2022-0847 verified". That is the most
damaging failure mode this project has, because the whole claim of the system
is that its numbers come from execution rather than assertion. So the adapter
establishes that the technique *could* work here before it is willing to say
anything about whether it did.
"""

from __future__ import annotations

import re
import shlex

from verifier.adapters import (
    NOT_EXECUTABLE,
    AdapterResult,
    RunContext,
    register,
)
from verifier.lab import file_exists, kernel_release
from verifier.signal import escalated


def _vtuple(version: str) -> tuple[int, ...]:
    """'5.16.11-rc2' -> (5, 16, 11). Mirrors collectors/derive.py:_vtuple.

    Duplicated rather than imported so the verifier has no dependency on the
    collector package; both are ~10 lines and both are covered by tests.
    """
    parts = []
    for chunk in re.split(r"[.\-+~]", version or ""):
        m = re.match(r"^(\d+)", chunk)
        if not m:
            break
        parts.append(int(m.group(1)))
    return tuple(parts) or (0,)


def _kernel_is_vulnerable(running: str, spec: dict) -> tuple[bool, str]:
    """Is *running* inside the CVE's affected range?

    Matched per stable branch, like the collector's rule: Linux backports fixes,
    so 5.15.30 is patched even though it is below 5.16.11.

    Returns (vulnerable, human-readable explanation).
    """
    if not running:
        return False, "could not read the running kernel version"

    affected_from = spec.get("affected_from")
    fixes = spec.get("fixed_versions") or []
    if not affected_from or not fixes:
        # No range declared, so we cannot establish the precondition either way.
        return False, "no affected kernel range declared in scope.yaml"

    current = _vtuple(running)
    introduced = _vtuple(affected_from)
    fix_tuples = [_vtuple(f) for f in fixes]

    branch = current[:2]
    branch_fix = next((f for f in fix_tuples if f[:2] == branch), None)
    effective_fix = branch_fix or max(fix_tuples)
    fix_str = ".".join(str(n) for n in effective_fix)

    if current < introduced:
        return False, (
            f"running kernel {running} is below the affected range "
            f"(from {affected_from})"
        )
    if current >= effective_fix:
        if branch_fix is None:
            # The running kernel is on a branch the CVE never affected at all,
            # which is the usual case in a container lab: the host machine's
            # kernel is far newer than anything in the affected range.
            return False, (
                f"running kernel {running} is on the {'.'.join(str(n) for n in branch)} "
                f"branch, which is newer than every affected branch "
                f"({', '.join(fixes)})"
            )
        return False, (
            f"running kernel {running} is at or above the "
            f"{'.'.join(str(n) for n in branch)} branch fix {fix_str}"
        )
    return True, f"running kernel {running} is within the affected range"


@register("anchor_cve")
def anchor_cve(ctx: RunContext) -> AdapterResult:
    """Run a pre-placed exploit artifact and read the canary as root."""
    exploit = ctx.technique.get("exploit_ref", "")
    cve = ctx.technique.get("cve", ctx.technique.get("id", "this CVE"))
    canary = ctx.canary_path

    def not_executable(reason: str) -> AdapterResult:
        return AdapterResult(
            escalated=False,
            evidence=f"NOT EXECUTABLE: {reason}",
            raw_cmd=[],
            status=NOT_EXECUTABLE,
            reason=reason,
        )

    # ── Precondition 1: the host must be in the technique's allowed list ─────
    allowed_hosts = ctx.technique.get("hosts", [])
    if allowed_hosts and ctx.host not in allowed_hosts:
        return not_executable(
            f"{ctx.host} is not in this technique's allowed hosts {allowed_hosts}"
        )

    # ── Precondition 2: the RUNNING kernel must actually be vulnerable ───────
    # Checked before the artifact is even looked for, so the reason reported is
    # the fundamental one rather than an incidental missing file.
    running = kernel_release(ctx.host, prefix=ctx.container_prefix)
    spec = ctx.technique.get("requires_kernel", {})
    vulnerable, explanation = _kernel_is_vulnerable(running, spec)
    if not vulnerable:
        declared = ctx.technique.get("declared_kernel_note", "")
        return not_executable(
            f"{cve} cannot be executed on {ctx.host}: {explanation}. "
            f"Containers share the host machine's kernel, so the kernel version "
            f"in the environment graph is declared, not running."
            + (f" {declared}" if declared else "")
        )

    # ── Precondition 3: the exploit artifact must be present ────────────────
    if not exploit:
        return not_executable("no exploit_ref declared in scope.yaml")
    if not file_exists(ctx.host, exploit, prefix=ctx.container_prefix):
        return not_executable(
            f"no exploit artifact at {exploit}. The verifier never ships or "
            f"generates exploit code; Workstream A places a built binary there."
        )

    # ── Preconditions met: run it and let signal.py decide ──────────────────
    payload = (
        f"{shlex.quote(exploit)} -- sh -c {shlex.quote(f'cat {canary}')} 2>&1"
    )
    cmd = ["sh", "-c", payload]

    ok, evidence = escalated(
        ctx.host, ctx.start_user, cmd, ctx.canary_token,
        prefix=ctx.container_prefix,
    )
    return AdapterResult(escalated=ok, evidence=evidence, raw_cmd=cmd)

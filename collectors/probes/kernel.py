"""Probe: kernel and OS identity.

Reports BOTH the real `uname -r` and the declared kernel from
/etc/ascend/declared_kernel, and never collapses the two.

Why a declared value exists at all: containers share the host's kernel, so three
containers cannot genuinely run three different kernel versions. The lab needs
per-host kernel divergence to exercise the T1068 rule, so it writes a declared
value into the image and the collector marks anything derived from it
provenance: "declared". The VM fallback (docs/02 section 6) drops the declared
file and the same probe reports the fact as observed instead.
"""

from __future__ import annotations


def collect(host: str, tp, scope: dict) -> dict:
    uname = tp.run(host, ["uname", "-r"])
    observed = uname.stdout.strip() if uname.ok else None

    declared = tp.read_file(host, "/etc/ascend/declared_kernel")
    declared = declared.strip() if declared else None

    os_name = None
    osr = tp.read_file(host, "/etc/os-release") or ""
    for line in osr.splitlines():
        if line.startswith("ID="):
            os_name = line.split("=", 1)[1].strip().strip('"')
            break

    arch = tp.run(host, ["uname", "-m"])

    return {
        "observed_kernel": observed,
        "declared_kernel": declared,
        # The value downstream rules match against, and where it came from.
        "effective_kernel": declared or observed,
        "provenance": "declared" if declared else "observed",
        "os": "linux" if os_name else "linux",
        "distribution": os_name,
        "arch": arch.stdout.strip() if arch.ok else None,
    }

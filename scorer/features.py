"""Feature extraction for the ASCEND exploitability scorer.

Organized into three explicit ablation tiers (matching the IEEE paper's
feature-ablation evaluation):
  - Tier 1 (CVSS-only): ``cvss_norm``
  - Tier 2 (Scanner + Topology): technique family flags, ``host_asset_norm``,
    ``reuse_count_norm``, ``epss_prior``, ``is_dual_homed``
  - Tier 3 (Read-Only Host Config Audit): ``sudo_noexec``, ``nosuid_mount``,
    ``sshd_deny_users``

Keeping feature extraction here guarantees training (over outcomes) and
inference (over live enumerated paths) use the exact same representation.
"""

from __future__ import annotations

from typing import Any

FEATURE_NAMES: tuple[str, ...] = (
    # Tier 1: CVSS-only
    "cvss_norm",
    # Tier 2: Scanner + Topology context
    "is_config_abuse",
    "is_credential_access",
    "is_lateral_move",
    "is_kernel_cve",
    "host_asset_norm",
    "reuse_count_norm",
    "epss_prior",
    "is_dual_homed",
    # Tier 3: Read-only host configuration audit context (runtime mitigations)
    "sudo_noexec",
    "nosuid_mount",
    "sshd_deny_users",
)

FEATURE_TIERS: dict[str, tuple[str, ...]] = {
    "cvss_only": ("cvss_norm",),
    "scanner_context": FEATURE_NAMES[:9],
    "full_context": FEATURE_NAMES,
}

_DEFAULT_EPSS: dict[str, float] = {
    "T1552.001": 0.18,
    "T1548.003": 0.42,
    "T1548.001": 0.36,
    "T1068": 0.94,
    "T1550": 0.31,
    "T1021.004+T1550": 0.31,
    "T1611": 0.55,
}


def _technique_family(technique_id: str) -> tuple[float, float, float, float]:
    tid = (technique_id or "").upper()
    is_config = 1.0 if (tid.startswith("T1548") or tid.startswith("T1611")) else 0.0
    is_cred = 1.0 if tid.startswith("T1552") else 0.0
    is_lateral = 1.0 if ("T1021" in tid or "T1550" in tid) else 0.0
    is_kernel = 1.0 if tid.startswith("T1068") else 0.0
    return is_config, is_cred, is_lateral, is_kernel


def extract_features_from_record(rec: dict[str, Any]) -> list[float]:
    """Extract the fixed-order feature vector directly from an enriched outcome record."""
    tid = rec.get("technique", "")
    snap = rec.get("features_snapshot") or {}

    cvss = rec.get("cvss")
    if cvss is None:
        cvss_norm = 0.65 if ("T1021" in tid or "T1550" in tid) else 0.50
    else:
        cvss_norm = max(0.0, min(1.0, float(cvss) / 10.0))

    is_config, is_cred, is_lateral, is_kernel = _technique_family(tid)
    asset_val = float(rec.get("host_asset_value", 0) or 0.0)
    host_asset_norm = max(0.0, min(1.0, asset_val / 100.0))

    reuse_count = float(rec.get("reuse_count", 0) or 0.0)
    reuse_count_norm = max(0.0, min(1.0, reuse_count / 5.0))

    epss_prior = float(snap.get("epss_prior", _DEFAULT_EPSS.get(tid, 0.25)))
    is_dual_homed = 1.0 if snap.get("is_dual_homed") else 0.0

    sudo_noexec = 1.0 if snap.get("sudo_noexec") else 0.0
    nosuid_mount = 1.0 if snap.get("nosuid_mount") else 0.0
    sshd_deny_users = 1.0 if snap.get("sshd_deny_users") else 0.0

    return [
        cvss_norm,
        is_config,
        is_cred,
        is_lateral,
        is_kernel,
        host_asset_norm,
        reuse_count_norm,
        epss_prior,
        is_dual_homed,
        sudo_noexec,
        nosuid_mount,
        sshd_deny_users,
    ]


def extract_features(
    host: str,
    technique_id: str,
    facts: dict[str, Any],
    *,
    vector: dict[str, Any] | None = None,
    credential: dict[str, Any] | None = None,
) -> list[float]:
    """Return a fixed-order numeric feature vector matching ``FEATURE_NAMES``."""
    host_meta = next(
        (h for h in facts.get("hosts", []) if h.get("hostname") == host),
        {},
    )
    if vector is None:
        vector = next(
            (
                v for v in facts.get("vectors", [])
                if v.get("host") == host and v.get("technique") == technique_id
            ),
            {},
        )
    if credential is None:
        if "T1021" in technique_id or "T1550" in technique_id:
            creds = facts.get("credentials", [])
            credential = creds[0] if creds else {}
        else:
            credential = {}

    vfeats = vector.get("features") or {}
    cfeats = credential.get("features") or {}
    blocked_hosts = set(cfeats.get("blocked_hosts") or [])

    rec = {
        "host": host,
        "technique": technique_id,
        "cvss": vector.get("cvss"),
        "host_asset_value": host_meta.get("asset_value", 0),
        "reuse_count": cfeats.get("reuse_count", 0),
        "features_snapshot": {
            "epss_prior": vfeats.get("epss_prior", _DEFAULT_EPSS.get(technique_id, 0.25)),
            "is_dual_homed": vfeats.get("is_dual_homed", host_meta.get("role") in ("app", "ci")),
            "sudo_noexec": bool(vfeats.get("sudo_noexec", False)),
            "nosuid_mount": bool(vfeats.get("nosuid_mount", False)),
            "sshd_deny_users": bool(vfeats.get("sshd_deny_users", False) or (host in blocked_hosts)),
        },
    }
    return extract_features_from_record(rec)

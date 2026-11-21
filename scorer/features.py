"""Feature extraction for the ASCEND exploitability scorer.

Maps each (host, technique, vector/credential) observation from ``facts.json``
into a fixed-length numeric feature vector. Keeping feature extraction here
ensures training (over ``outcomes.jsonl``) and inference (over live enumerated
paths) use the exact same representation.
"""

from __future__ import annotations

from typing import Any

FEATURE_NAMES: tuple[str, ...] = (
    "cvss_norm",
    "is_config_abuse",
    "is_credential_access",
    "is_lateral_move",
    "is_kernel_cve",
    "host_asset_norm",
    "provenance_observed",
    "reuse_count_norm",
)


def _technique_family(technique_id: str) -> tuple[float, float, float, float]:
    tid = (technique_id or "").upper()
    is_config = 1.0 if (tid.startswith("T1548") or tid.startswith("T1611")) else 0.0
    is_cred = 1.0 if tid.startswith("T1552") else 0.0
    is_lateral = 1.0 if ("T1021" in tid or "T1550" in tid) else 0.0
    is_kernel = 1.0 if tid.startswith("T1068") else 0.0
    return is_config, is_cred, is_lateral, is_kernel


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

    cvss = vector.get("cvss")
    if cvss is None:
        # Lateral movement via reused key has no standalone CVE CVSS; use 0.55 prior.
        cvss_norm = 0.55 if ("T1021" in technique_id or "T1550" in technique_id) else 0.5
    else:
        cvss_norm = max(0.0, min(1.0, float(cvss) / 10.0))

    is_config, is_cred, is_lateral, is_kernel = _technique_family(technique_id)
    asset_val = float(host_meta.get("asset_value", 0) or 0.0)
    host_asset_norm = max(0.0, min(1.0, asset_val / 100.0))

    prov = (vector.get("features") or {}).get("provenance")
    if prov is None:
        prov = (credential.get("features") or {}).get("provenance", "observed")
    provenance_observed = 1.0 if prov == "observed" else 0.0

    reuse_count = float((credential.get("features") or {}).get("reuse_count", 0) or 0.0)
    reuse_count_norm = max(0.0, min(1.0, reuse_count / 5.0))

    return [
        cvss_norm,
        is_config,
        is_cred,
        is_lateral,
        is_kernel,
        host_asset_norm,
        provenance_observed,
        reuse_count_norm,
    ]

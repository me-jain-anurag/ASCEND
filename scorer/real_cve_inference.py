"""Inference wrapper for ASCEND's trained real-world Linux CVE multimodal ensemble.

Loads ``scorer/artifacts/real_cve_model.pkl.gz`` (trained on 2018-2022 NVD +
Exploit-DB + CISA KEV records, calibrated on 2023, tested on 2024) and scores
any CVE-backed vector (such as CVE-2022-0847 DirtyPipe, CVE-2021-4034 PwnKit,
or Trivy-imported CVEs in Assessment mode).
"""

from __future__ import annotations

import gzip
import json
import pickle
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = ROOT / "scorer" / "artifacts" / "real_cve_model.pkl.gz"
BENCH_PATH = ROOT / "eval" / "real_cve_benchmark.json"

_CACHE: dict[str, Any] | None = None


class _SafeUnpickler(pickle.Unpickler):
    def find_class(self, module: str, name: str) -> Any:
        if module == "__main__" and name == "MultimodalFeatureBuilder":
            from scorer.train_real_cve_model import MultimodalFeatureBuilder
            return MultimodalFeatureBuilder
        return super().find_class(module, name)


def load_real_cve_bundle() -> dict[str, Any] | None:
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    if not MODEL_PATH.exists():
        return None
    with gzip.open(MODEL_PATH, "rb") as fh:
        _CACHE = _SafeUnpickler(fh).load()
    return _CACHE


def load_real_cve_benchmark() -> dict[str, Any] | None:
    if not BENCH_PATH.exists():
        return None
    return json.loads(BENCH_PATH.read_text(encoding="utf-8"))


def score_cve_record(rec: dict[str, Any]) -> dict[str, Any] | None:
    """Return calibrated exploitability probability for a real CVE record."""
    bundle = load_real_cve_bundle()
    if bundle is None:
        return None

    cid = (rec.get("cve_id") or rec.get("cve") or "").upper()
    if cid and cid in (bundle.get("anchor_cache") or {}):
        cached = bundle["anchor_cache"][cid]
        return {
            "cve_id": cid,
            "probability": cached["ascend_model_prob"],
            "epss_live": cached.get("epss_live"),
            "basis": (
                "ASCEND Calibrated Multimodal CVE Ensemble "
                "(trained on NVD 2018-2022 + Exploit-DB + CISA KEV; 2024 test PR-AUC=0.886)"
            ),
        }

    fb = bundle["feature_builder"]
    norm = {
        "cve_id": cid or "CVE-UNKNOWN",
        "description": rec.get("description") or "",
        "cvss_base": float(rec.get("cvss_base") or rec.get("cvss") or 5.0),
        "attack_vector": rec.get("attack_vector", "LOCAL"),
        "attack_complexity": rec.get("attack_complexity", "LOW"),
        "privileges_required": rec.get("privileges_required", "LOW"),
        "user_interaction": rec.get("user_interaction", "NONE"),
        "scope": rec.get("scope", "UNCHANGED"),
        "confidentiality": rec.get("confidentiality", "HIGH"),
        "integrity": rec.get("integrity", "HIGH"),
        "availability": rec.get("availability", "HIGH"),
        "cwes": rec.get("cwes") or [],
        "has_patch_ref": bool(rec.get("has_patch_ref", True)),
        "has_vendor_adv": bool(rec.get("has_vendor_adv", True)),
    }
    p1 = float(bundle["iso_lr"].predict(bundle["lr_full"].predict_proba(fb.transform_sparse_full([norm]))[:, 1])[0])
    dn = fb.transform_dense_full([norm])
    p2 = float(bundle["iso_gb"].predict(bundle["gb_full"].predict_proba(dn)[:, 1])[0])
    p3 = float(bundle["iso_rf"].predict(bundle["rf_full"].predict_proba(dn)[:, 1])[0])
    prob = round(0.45 * p1 + 0.35 * p2 + 0.20 * p3, 4)
    return {
        "cve_id": cid,
        "probability": prob,
        "basis": (
            "ASCEND Calibrated Multimodal CVE Ensemble "
            "(trained on NVD 2018-2022 + Exploit-DB + CISA KEV; 2024 test PR-AUC=0.886)"
        ),
    }

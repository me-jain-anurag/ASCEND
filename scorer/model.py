"""Transparent ML exploitability scorer with strict honesty gates & named baselines.

Design principles (aligned with ASCEND's trustworthiness rules, docs/06 & docs/11):
1. ``not_executable`` records are NEVER treated as negative labels.
2. Known batch-matrix parameter mismatches (older outcomes.jsonl captures) are
   audited and excluded from training rather than distorting labels.
3. Strict two-class gate: ``trained`` is True ONLY when BOTH classes
   (``escalated`` and ``not_escalated``) have real support (>=2 each). On
   single-class data, the scorer refuses to report decorative accuracy/Brier
   scores or emit learned path probabilities.
4. Leakage-free evaluation: splits strictly by ``variant_id`` (or ``host``
   when no variant_id is present) and evaluates ONCE on the held-out test split
   against three named baselines: Majority-Class, CVSS >= 7.0, and Static/Scanner-Flag.
"""

from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

from scorer.features import (
    FEATURE_NAMES,
    FEATURE_TIERS,
    extract_features,
    extract_features_from_record,
)


@dataclass
class MetricBundle:
    name: str
    kind: str  # "baseline" | "model"
    feature_tier: str
    n_test: int
    accuracy: float
    precision: float
    recall: float
    macro_f1: float
    roc_auc: float | None
    brier_score: float


@dataclass
class ScorerReport:
    trained: bool
    status: str  # "trained" | "untrained_single_class" | "untrained_no_data"
    model_type: str
    label_source: str
    records_total: int
    records_trainable: int
    records_positives: int
    records_negatives: int
    records_excluded_not_executable: int
    records_flagged_param_mismatch: int
    positive_rate: float | None
    split_strategy: str
    test_metrics: dict[str, Any] | None
    baselines: list[dict[str, Any]] = field(default_factory=list)
    ablations: list[dict[str, Any]] = field(default_factory=list)
    beats_cvss_baseline: bool | None = None
    beats_majority_baseline: bool | None = None
    feature_weights: dict[str, float] = field(default_factory=dict)
    technique_priors: dict[str, dict[str, Any]] = field(default_factory=dict)
    caveats: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _sigmoid(z: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(z, -30.0, 30.0)))


class LogisticScorer:
    """L2-regularized binary logistic regression implemented in pure NumPy."""

    def __init__(self, l2: float = 0.5, lr: float = 0.4, epochs: int = 800):
        self.l2 = l2
        self.lr = lr
        self.epochs = epochs
        self.weights: np.ndarray | None = None
        self.bias: float = 0.0
        self.constant_prob: float | None = None

    def fit(self, X: np.ndarray, y: np.ndarray) -> "LogisticScorer":
        n, d = X.shape
        if n == 0 or len(np.unique(y)) < 2:
            self.weights = np.zeros(d, dtype=float)
            pos = float(np.sum(y == 1)) if n else 0.0
            self.constant_prob = (pos + 1.0) / (n + 2.0) if n else 0.5
            self.bias = math.log(self.constant_prob / (1.0 - self.constant_prob))
            return self

        self.constant_prob = None
        w = np.zeros(d, dtype=float)
        b = 0.0
        for _ in range(self.epochs):
            preds = _sigmoid(X @ w + b)
            err = preds - y
            grad_w = (X.T @ err) / n + (self.l2 / n) * w
            grad_b = float(np.mean(err))
            w -= self.lr * grad_w
            b -= self.lr * grad_b

        self.weights = w
        self.bias = b
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        if self.constant_prob is not None:
            return np.full(X.shape[0], self.constant_prob, dtype=float)
        assert self.weights is not None
        return _sigmoid(X @ self.weights + self.bias)


def _binary_metrics(
    y_true: np.ndarray,
    probs: np.ndarray,
    *,
    name: str,
    kind: str,
    feature_tier: str,
    threshold: float = 0.5,
) -> MetricBundle:
    """Compute honest classification metrics including Macro-F1 and ROC-AUC."""
    y = (y_true >= 0.5).astype(int)
    pred = (probs >= threshold).astype(int)
    n = len(y)
    acc = float(np.mean(pred == y)) if n else 0.0

    tp = int(np.sum((pred == 1) & (y == 1)))
    fp = int(np.sum((pred == 1) & (y == 0)))
    fn = int(np.sum((pred == 0) & (y == 1)))
    tn = int(np.sum((pred == 0) & (y == 0)))

    prec_pos = tp / (tp + fp) if (tp + fp) else 0.0
    rec_pos = tp / (tp + fn) if (tp + fn) else 0.0
    f1_pos = (2 * prec_pos * rec_pos / (prec_pos + rec_pos)) if (prec_pos + rec_pos) else 0.0

    prec_neg = tn / (tn + fn) if (tn + fn) else 0.0
    rec_neg = tn / (tn + fp) if (tn + fp) else 0.0
    f1_neg = (2 * prec_neg * rec_neg / (prec_neg + rec_neg)) if (prec_neg + rec_neg) else 0.0

    macro_f1 = 0.5 * (f1_pos + f1_neg)
    brier = float(np.mean((probs - y) ** 2)) if n else 0.0

    # Exact Mann-Whitney U / ROC-AUC without requiring sklearn
    pos_scores = probs[y == 1]
    neg_scores = probs[y == 0]
    if len(pos_scores) > 0 and len(neg_scores) > 0:
        wins = 0.0
        for ps in pos_scores:
            wins += float(np.sum(ps > neg_scores)) + 0.5 * float(np.sum(ps == neg_scores))
        roc_auc: float | None = round(wins / (len(pos_scores) * len(neg_scores)), 4)
    else:
        roc_auc = None

    return MetricBundle(
        name=name,
        kind=kind,
        feature_tier=feature_tier,
        n_test=n,
        accuracy=round(acc, 4),
        precision=round(prec_pos, 4),
        recall=round(rec_pos, 4),
        macro_f1=round(macro_f1, 4),
        roc_auc=roc_auc,
        brier_score=round(brier, 4),
    )


def _is_batch_param_mismatch(rec: dict[str, Any]) -> bool:
    """Detect older batch rows where web01's key path was run on another host."""
    if rec.get("technique") != "T1021.004+T1550":
        return False
    if rec.get("host") == "web01":
        return False
    cmd = " ".join(rec.get("raw_cmd") or [])
    return "/var/www/.ssh/id_rsa" in cmd and rec.get("status") == "not_escalated"


def load_outcomes(outcomes_path: str | Path) -> list[dict[str, Any]]:
    p = Path(outcomes_path)
    if not p.exists():
        return []
    rows = []
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _filter_records(
    records: list[dict[str, Any]],
    *,
    exclude_param_mismatches: bool = True,
) -> tuple[list[dict[str, Any]], int, int]:
    not_exec = 0
    mismatches = 0
    trainable: list[dict[str, Any]] = []
    for rec in records:
        status = rec.get("status") or ("escalated" if rec.get("escalated") else "not_escalated")
        if status == "not_executable":
            not_exec += 1
            continue
        if _is_batch_param_mismatch(rec):
            mismatches += 1
            if exclude_param_mismatches:
                continue
        trainable.append(rec)
    return trainable, not_exec, mismatches


def _extract_matrix(records: list[dict[str, Any]], facts: dict[str, Any] | None) -> np.ndarray:
    rows = []
    for r in records:
        if "features_snapshot" in r:
            rows.append(extract_features_from_record(r))
        else:
            rows.append(extract_features(r["host"], r["technique"], facts or {}))
    return np.array(rows, dtype=float) if rows else np.zeros((0, len(FEATURE_NAMES)), dtype=float)


def _split_train_test(records: list[dict[str, Any]]) -> tuple[list[int], list[int], str]:
    """Leakage-free split: prefer explicit variant split, else group by variant/host."""
    if any("split" in r for r in records):
        train_idx = [i for i, r in enumerate(records) if r.get("split") in ("train", "val")]
        test_idx = [i for i, r in enumerate(records) if r.get("split") == "test"]
        if train_idx and test_idx:
            return train_idx, test_idx, "grouped_by_variant (70/15 train+val, 15 held-out test)"

    groups = sorted({r.get("variant_id") or r.get("host", "unknown") for r in records})
    if len(groups) >= 2:
        cut = max(1, int(round(0.75 * len(groups))))
        train_groups = set(groups[:cut])
        train_idx = [i for i, r in enumerate(records) if (r.get("variant_id") or r.get("host")) in train_groups]
        test_idx = [i for i, r in enumerate(records) if (r.get("variant_id") or r.get("host")) not in train_groups]
        if train_idx and test_idx:
            return train_idx, test_idx, "grouped_by_host_or_variant (75/25 holdout)"

    return list(range(len(records))), [], "insufficient_groups"


def train_and_evaluate(
    facts: dict[str, Any] | None,
    outcomes_path: str | Path | None = None,
    *,
    records_override: list[dict[str, Any]] | None = None,
    exclude_param_mismatches: bool = True,
    seed: int = 1337,
) -> tuple[LogisticScorer, ScorerReport]:
    """Train and honestly evaluate the exploitability scorer against named baselines."""
    records = list(records_override) if records_override is not None else load_outcomes(outcomes_path or "")
    trainable, not_exec, mismatches = _filter_records(
        records, exclude_param_mismatches=exclude_param_mismatches
    )

    label_sources = sorted({r.get("label_source", "live_lab_outcomes") for r in trainable})
    label_source = ", ".join(label_sources) if label_sources else "none"

    # Empirical Laplace-smoothed priors per technique
    tech_counts: dict[str, list[int]] = {}
    for rec in trainable:
        tid = rec.get("technique", "unknown")
        pos, tot = tech_counts.get(tid, [0, 0])
        tech_counts[tid] = [pos + (1 if rec.get("escalated") else 0), tot + 1]
    technique_priors = {
        tid: {
            "escalated": pos,
            "attempted": tot,
            "smoothed_probability": round((pos + 1.0) / (tot + 2.0), 4),
        }
        for tid, (pos, tot) in sorted(tech_counts.items())
    }

    caveats: list[str] = []
    if not_exec:
        caveats.append(
            f"Excluded {not_exec} not_executable record(s) so lab limitations are never treated as negatives."
        )
    if mismatches:
        caveats.append(
            f"Excluded {mismatches} legacy batch lateral-SSH record(s) with cross-host key_path mismatch."
        )
    if "catalogue_ground_truth" in label_sources:
        caveats.append(
            "Variant benchmark labels come from catalogue ground truth (offline); "
            "live Docker/VM verifier runs overwrite these with canary-verified outcomes."
        )

    if not trainable:
        model = LogisticScorer().fit(np.zeros((0, len(FEATURE_NAMES))), np.zeros((0,)))
        caveats.append("No trainable outcomes available; scorer is untrained.")
        return model, ScorerReport(
            trained=False,
            status="untrained_no_data",
            model_type="L2 Logistic Regression (pure NumPy)",
            label_source=label_source,
            records_total=len(records),
            records_trainable=0,
            records_positives=0,
            records_negatives=0,
            records_excluded_not_executable=not_exec,
            records_flagged_param_mismatch=mismatches,
            positive_rate=None,
            split_strategy="none",
            test_metrics=None,
            caveats=caveats,
        )

    X = _extract_matrix(trainable, facts)
    y = np.array([1.0 if r.get("escalated") else 0.0 for r in trainable], dtype=float)
    n_pos = int(np.sum(y == 1.0))
    n_neg = int(np.sum(y == 0.0))
    pos_rate = float(np.mean(y))

    # Strict two-class honesty gate: refuse to claim a trained model on single-class data
    if n_pos < 2 or n_neg < 2:
        model = LogisticScorer().fit(X, y)
        caveats.append(
            f"Single-class training data ({n_pos} escalated, {n_neg} not_escalated). "
            "Scorer is marked UNTRAINED and suppressed from path badges until genuine "
            "failed-escalation negatives are collected."
        )
        return model, ScorerReport(
            trained=False,
            status="untrained_single_class",
            model_type="L2 Logistic Regression (pure NumPy)",
            label_source=label_source,
            records_total=len(records),
            records_trainable=len(trainable),
            records_positives=n_pos,
            records_negatives=n_neg,
            records_excluded_not_executable=not_exec,
            records_flagged_param_mismatch=mismatches,
            positive_rate=round(pos_rate, 4),
            split_strategy="single_class_blocked",
            test_metrics=None,
            feature_weights={name: 0.0 for name in FEATURE_NAMES},
            technique_priors=technique_priors,
            caveats=caveats,
        )

    train_idx, test_idx, split_strategy = _split_train_test(trainable)
    X_train, y_train = X[train_idx], y[train_idx]
    X_test, y_test = X[test_idx], y[test_idx]

    # ── Named Baselines on held-out test split ────────────────────────────────
    baselines: list[dict[str, Any]] = []
    ablations: list[dict[str, Any]] = []
    full_test_bundle: MetricBundle | None = None
    beats_cvss: bool | None = None
    beats_maj: bool | None = None

    if len(test_idx) > 0:
        # 1. Majority-class baseline
        maj_prob = float(np.mean(y_train))
        maj_probs = np.full(len(y_test), maj_prob, dtype=float)
        b_maj = _binary_metrics(
            y_test, maj_probs, name="Majority-Class Baseline", kind="baseline", feature_tier="none"
        )
        baselines.append(asdict(b_maj))

        # 2. CVSS >= 7.0 baseline (feature 0 is cvss_norm = cvss / 10.0)
        cvss_probs = (X_test[:, 0] >= 0.70).astype(float)
        b_cvss = _binary_metrics(
            y_test, cvss_probs, name="CVSS >= 7.0 Baseline", kind="baseline", feature_tier="cvss_only"
        )
        baselines.append(asdict(b_cvss))

        # 3. Static / Scanner-Flag baseline (predicts 1 for every statically derived finding)
        scanner_probs = np.ones(len(y_test), dtype=float)
        b_scan = _binary_metrics(
            y_test, scanner_probs, name="Static Scanner-Flag Baseline", kind="baseline", feature_tier="static_flag"
        )
        baselines.append(asdict(b_scan))

        # ── Feature Ablations (Logistic Regression across 3 tiers) ────────────
        for tier_name, cols in FEATURE_TIERS.items():
            col_idx = [FEATURE_NAMES.index(c) for c in cols]
            m_tier = LogisticScorer().fit(X_train[:, col_idx], y_train)
            p_tier = m_tier.predict_proba(X_test[:, col_idx])
            bundle = _binary_metrics(
                y_test,
                p_tier,
                name=f"Logistic Regression ({tier_name})",
                kind="model",
                feature_tier=tier_name,
            )
            ablations.append(asdict(bundle))
            if tier_name == "full_context":
                full_test_bundle = bundle

        # Optional GBDT comparator (scikit-learn) on full_context
        try:
            from sklearn.ensemble import GradientBoostingClassifier

            gbdt = GradientBoostingClassifier(
                n_estimators=60, max_depth=3, learning_rate=0.1, random_state=seed
            )
            gbdt.fit(X_train, y_train.astype(int))
            p_gbdt = gbdt.predict_proba(X_test)[:, 1]
            gbdt_bundle = _binary_metrics(
                y_test,
                p_gbdt,
                name="Gradient-Boosted Trees (full_context)",
                kind="model",
                feature_tier="full_context",
            )
            ablations.append(asdict(gbdt_bundle))
        except Exception:
            caveats.append("scikit-learn unavailable; GBDT comparator skipped.")

        if full_test_bundle is not None:
            beats_cvss = full_test_bundle.macro_f1 > b_cvss.macro_f1
            beats_maj = full_test_bundle.macro_f1 > b_maj.macro_f1

    # Fit final interpretable L2 Logistic Regression on train split (never touching test for fitting)
    model = LogisticScorer().fit(X_train, y_train)
    weights = {
        name: round(float(w), 4)
        for name, w in zip(FEATURE_NAMES, model.weights if model.weights is not None else [])
    }

    return model, ScorerReport(
        trained=True,
        status="trained",
        model_type="L2 Logistic Regression (pure NumPy)",
        label_source=label_source,
        records_total=len(records),
        records_trainable=len(trainable),
        records_positives=n_pos,
        records_negatives=n_neg,
        records_excluded_not_executable=not_exec,
        records_flagged_param_mismatch=mismatches,
        positive_rate=round(pos_rate, 4),
        split_strategy=split_strategy,
        test_metrics=asdict(full_test_bundle) if full_test_bundle else None,
        baselines=baselines,
        ablations=ablations,
        beats_cvss_baseline=beats_cvss,
        beats_majority_baseline=beats_maj,
        feature_weights=weights,
        technique_priors=technique_priors,
        caveats=caveats,
    )


def score_environment(
    facts: dict[str, Any],
    paths: list[dict[str, Any]],
    outcomes_path: str | Path | None = None,
    *,
    records_override: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Train scorer and score every vector and path (empty scores when untrained)."""
    model, report = train_and_evaluate(
        facts, outcomes_path, records_override=records_override
    )

    if not report.trained:
        return {
            "model": report.to_dict(),
            "vector_scores": {},
            "path_scores": {},
        }

    def _score_step(
        host: str,
        tech_id: str,
        vector: dict | None = None,
        credential: dict | None = None,
    ) -> dict[str, Any]:
        feats = extract_features(host, tech_id, facts, vector=vector, credential=credential)
        model_p = float(model.predict_proba(np.array([feats]))[0])
        cve_id = (vector or {}).get("cve")
        if cve_id:
            try:
                from scorer.real_cve_inference import score_cve_record
                cve_res = score_cve_record({"cve": cve_id, "cvss": (vector or {}).get("cvss"), "description": (vector or {}).get("description", "")})
            except Exception:
                cve_res = None
            if cve_res is not None:
                return {
                    "probability": cve_res["probability"],
                    "confidence": "unverified_in_lab" if tech_id.startswith("T1068") else "real_cve_model",
                    "basis": cve_res["basis"] + (" (container-unverified kernel step)" if tech_id.startswith("T1068") else ""),
                }
        if tech_id.startswith("T1068"):
            prob = round(min(model_p, 0.5), 4)
            basis = "unverified in container lab (prior capped at 0.50)"
            confidence = "unverified_in_lab"
        else:
            prob = round(model_p, 4)
            basis = f"L2 logistic scorer ({report.label_source})"
            confidence = "trained_model"
        return {
            "probability": prob,
            "confidence": confidence,
            "basis": basis,
        }

    vector_scores = {}
    for v in facts.get("vectors", []):
        vector_scores[v["vector_id"]] = {
            "vector_id": v["vector_id"],
            "host": v["host"],
            "technique": v["technique"],
            **_score_step(v["host"], v["technique"], vector=v),
        }

    path_scores = {}
    for p in paths:
        pid = p["path_id"]
        step_results = []
        joint_prob = 1.0
        has_unverified = False
        for step in p.get("steps", []):
            tech = step["vector"]["technique"]
            host = step["source_host"]
            res = _score_step(
                host, tech, vector=step.get("vector"), credential=step.get("credential")
            )
            joint_prob *= res["probability"]
            if res["confidence"] == "unverified_in_lab":
                has_unverified = True
            step_results.append({
                "step_number": step["step_number"],
                "technique": tech,
                "host": host,
                **res,
            })
        path_scores[pid] = {
            "path_id": pid,
            "joint_probability": round(joint_prob, 4),
            "contains_unverified_step": has_unverified,
            "steps": step_results,
        }

    real_cve_bench = None
    try:
        from scorer.real_cve_inference import load_real_cve_benchmark
        real_cve_bench = load_real_cve_benchmark()
    except Exception:
        real_cve_bench = None
    return {
        "model": report.to_dict(),
        "vector_scores": vector_scores,
        "path_scores": path_scores,
        "real_cve_benchmark": real_cve_bench,
    }

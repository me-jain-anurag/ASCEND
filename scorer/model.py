"""Transparent ML exploitability scorer trained on verified outcomes.

Design principles (aligned with ASCEND's trustworthiness rules):
1. ``not_executable`` records are NEVER treated as negative labels. They record
   a lab limitation, not evidence that a technique fails.
2. Known batch-matrix parameter mismatches (e.g., running web01's key_path on
   app01/db01 in older outcomes.jsonl captures) are audited and reported
   explicitly rather than silently distorting probabilities.
3. Dependency-light: pure NumPy L2-regularized Logistic Regression with
   stratified k-fold cross-validation and Laplace-smoothed technique priors, so
   it runs anywhere ``numpy`` is installed without requiring scikit-learn.
"""

from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import numpy as np

from scorer.features import FEATURE_NAMES, extract_features


@dataclass
class ScorerReport:
    trained: bool
    model_type: str
    records_total: int
    records_trainable: int
    records_excluded_not_executable: int
    records_flagged_param_mismatch: int
    positive_rate: float | None
    cv_folds: int
    cv_accuracy: float | None
    cv_brier_score: float | None
    feature_weights: dict[str, float]
    technique_priors: dict[str, dict[str, Any]]
    caveats: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _sigmoid(z: np.ndarray) -> np.ndarray:
    z_clipped = np.clip(z, -30.0, 30.0)
    return 1.0 / (1.0 + np.exp(-z_clipped))


class LogisticScorer:
    """L2-regularized binary logistic regression implemented in pure NumPy."""

    def __init__(self, l2: float = 1.0, lr: float = 0.2, epochs: int = 400):
        self.l2 = l2
        self.lr = lr
        self.epochs = epochs
        self.weights: np.ndarray | None = None
        self.bias: float = 0.0
        self.constant_prob: float | None = None

    def fit(self, X: np.ndarray, y: np.ndarray) -> "LogisticScorer":
        n, d = X.shape
        if n == 0:
            self.weights = np.zeros(d, dtype=float)
            self.bias = 0.0
            self.constant_prob = 0.5
            return self

        unique = np.unique(y)
        if len(unique) < 2:
            # Single-class training set: avoid degenerate diverging weights.
            # Apply Laplace smoothing (alpha=1, beta=1) so probabilities stay calibrated.
            pos = float(np.sum(y == 1))
            self.weights = np.zeros(d, dtype=float)
            self.constant_prob = (pos + 1.0) / (n + 2.0)
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


def train_and_evaluate(
    facts: dict[str, Any],
    outcomes_path: str | Path,
    *,
    exclude_param_mismatches: bool = True,
    k_folds: int = 5,
) -> tuple[LogisticScorer, ScorerReport]:
    """Train the exploitability scorer on ``outcomes.jsonl`` and audit data quality."""
    records = load_outcomes(outcomes_path)
    not_exec = 0
    mismatches = 0
    trainable: list[dict[str, Any]] = []
    missing_feature_refs = 0

    for rec in records:
        status = rec.get("status") or ("escalated" if rec.get("escalated") else "not_escalated")
        if status == "not_executable":
            not_exec += 1
            continue
        if _is_batch_param_mismatch(rec):
            mismatches += 1
            if exclude_param_mismatches:
                continue
        if not rec.get("host_facts_ref"):
            missing_feature_refs += 1
        trainable.append(rec)

    # Empirical Laplace-smoothed priors per technique (across trainable rows)
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
            f"Excluded {not_exec} not_executable record(s) from training so lab limitations "
            f"are never treated as negative exploit labels."
        )
    if mismatches:
        caveats.append(
            f"Detected {mismatches} batch lateral-SSH record(s) with cross-host key_path "
            f"mismatch (web01 path run on app01/db01); "
            + ("excluded from training." if exclude_param_mismatches else "included in audit mode.")
        )
    if missing_feature_refs:
        caveats.append(
            f"{missing_feature_refs} historical outcome(s) lack host_facts_ref; features were "
            f"reconstructed from current facts.json."
        )

    if not trainable:
        model = LogisticScorer().fit(np.zeros((0, len(FEATURE_NAMES))), np.zeros((0,)))
        caveats.append("No trainable outcomes found; model falls back to 0.50 neutral prior.")
        return model, ScorerReport(
            trained=False,
            model_type="L2 Logistic Regression (pure NumPy)",
            records_total=len(records),
            records_trainable=0,
            records_excluded_not_executable=not_exec,
            records_flagged_param_mismatch=mismatches,
            positive_rate=None,
            cv_folds=0,
            cv_accuracy=None,
            cv_brier_score=None,
            feature_weights={name: 0.0 for name in FEATURE_NAMES},
            technique_priors=technique_priors,
            caveats=caveats,
        )

    X = np.array(
        [extract_features(r["host"], r["technique"], facts) for r in trainable],
        dtype=float,
    )
    y = np.array([1.0 if r.get("escalated") else 0.0 for r in trainable], dtype=float)
    pos_rate = float(np.mean(y))

    if len(np.unique(y)) < 2:
        caveats.append(
            "After filtering not_executable and parameter-mismatch rows, remaining training "
            "outcomes are single-class. Collect genuine failed-escalation negatives in the lab "
            "to calibrate discriminative weights."
        )

    # Stratified-ish deterministic k-fold CV (interleaved after sorting by label)
    n = len(y)
    folds = min(k_folds, n) if n >= 2 else 0
    cv_acc = None
    cv_brier = None
    if folds >= 2:
        order = np.argsort(y, kind="stable")
        fold_ids = np.arange(n) % folds
        # Assign fold ids in sorted-label order so positives/negatives spread evenly
        assigned = np.empty(n, dtype=int)
        assigned[order] = fold_ids

        probs = np.zeros(n, dtype=float)
        for f in range(folds):
            test_mask = assigned == f
            train_mask = ~test_mask
            fold_model = LogisticScorer().fit(X[train_mask], y[train_mask])
            probs[test_mask] = fold_model.predict_proba(X[test_mask])

        cv_acc = round(float(np.mean((probs >= 0.5) == (y >= 0.5))), 4)
        cv_brier = round(float(np.mean((probs - y) ** 2)), 4)

    model = LogisticScorer().fit(X, y)
    weights = {
        name: round(float(w), 4)
        for name, w in zip(FEATURE_NAMES, model.weights if model.weights is not None else [])
    }

    return model, ScorerReport(
        trained=True,
        model_type="L2 Logistic Regression (pure NumPy)",
        records_total=len(records),
        records_trainable=len(trainable),
        records_excluded_not_executable=not_exec,
        records_flagged_param_mismatch=mismatches,
        positive_rate=round(pos_rate, 4),
        cv_folds=folds,
        cv_accuracy=cv_acc,
        cv_brier_score=cv_brier,
        feature_weights=weights,
        technique_priors=technique_priors,
        caveats=caveats,
    )


def score_environment(
    facts: dict[str, Any],
    paths: list[dict[str, Any]],
    outcomes_path: str | Path,
) -> dict[str, Any]:
    """Train scorer from ``outcomes_path`` and score every vector and path."""
    model, report = train_and_evaluate(facts, outcomes_path)
    priors = report.technique_priors

    def _score_step(host: str, tech_id: str, vector: dict | None = None,
                    credential: dict | None = None) -> dict[str, Any]:
        feats = extract_features(host, tech_id, facts, vector=vector, credential=credential)
        model_p = float(model.predict_proba(np.array([feats]))[0])
        prior = priors.get(tech_id)
        if prior:
            # Blend model score with Laplace-smoothed empirical prior
            prob = round(0.5 * model_p + 0.5 * prior["smoothed_probability"], 4)
            basis = f"model + empirical prior ({prior['escalated']}/{prior['attempted']} verified)"
            confidence = "empirical"
        elif tech_id.startswith("T1068"):
            # Never pretend a kernel CVE was verified in a container lab
            prob = round(min(model_p, 0.5), 4)
            basis = "unverified in container lab (prior capped at 0.50)"
            confidence = "unverified_in_lab"
        else:
            prob = round(model_p, 4)
            basis = "model feature estimate (no direct outcomes for this technique yet)"
            confidence = "low_confidence"
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
            res = _score_step(host, tech, vector=step.get("vector"), credential=step.get("credential"))
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

    return {
        "model": report.to_dict(),
        "vector_scores": vector_scores,
        "path_scores": path_scores,
    }

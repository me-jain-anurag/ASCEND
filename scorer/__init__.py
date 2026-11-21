"""ASCEND exploitability scorer package.

Trains a transparent, L2-regularized logistic model over verified execution
outcomes (``outcomes.jsonl``) and estimates per-step and per-path exploitability
probabilities for enumerated attack paths.
"""

from scorer.model import ScorerReport, score_environment, train_and_evaluate

__all__ = ["ScorerReport", "score_environment", "train_and_evaluate"]

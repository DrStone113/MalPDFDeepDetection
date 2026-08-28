"""Reusable binary evaluation and runtime helpers with malicious Label=1 positive."""

from __future__ import annotations

from time import perf_counter
from typing import Any

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
    roc_auc_score,
)

POSITIVE_LABEL = 1


def continuous_positive_scores(estimator: Any, features: Any) -> tuple[np.ndarray | None, str | None]:
    """Return probability/continuous scores for Label=1, never hard predictions.

    ``predict_proba`` is preferred. If unavailable, a continuous decision score is
    used. Estimators exposing neither return ``(None, None)`` and ROC/PR metrics
    are reported as unavailable rather than calculated from class predictions.
    """
    if hasattr(estimator, "predict_proba"):
        probabilities = np.asarray(estimator.predict_proba(features))
        classes = np.asarray(getattr(estimator, "classes_", []))
        positive_positions = np.flatnonzero(classes == POSITIVE_LABEL)
        if probabilities.ndim == 2 and len(positive_positions) == 1:
            return probabilities[:, int(positive_positions[0])], "predict_proba"
    if hasattr(estimator, "decision_function"):
        scores = np.asarray(estimator.decision_function(features))
        if scores.ndim == 1:
            return scores, "decision_function"
        classes = np.asarray(getattr(estimator, "classes_", []))
        positive_positions = np.flatnonzero(classes == POSITIVE_LABEL)
        if scores.ndim == 2 and len(positive_positions) == 1:
            return scores[:, int(positive_positions[0])], "decision_function"
    return None, None


def evaluate_binary_predictions(
    y_true: Any, y_predicted: Any, positive_scores: Any | None = None
) -> dict[str, Any]:
    """Compute paper metrics plus ROC-AUC, PR-AUC, MCC, and a fixed-label matrix."""
    truth = np.asarray(y_true)
    predicted = np.asarray(y_predicted)
    result: dict[str, Any] = {
        "positive_label": POSITIVE_LABEL,
        "accuracy": float(accuracy_score(truth, predicted)),
        "precision": float(precision_score(truth, predicted, pos_label=POSITIVE_LABEL, zero_division=0)),
        "recall": float(recall_score(truth, predicted, pos_label=POSITIVE_LABEL, zero_division=0)),
        "f1": float(f1_score(truth, predicted, pos_label=POSITIVE_LABEL, zero_division=0)),
        "mcc": float(matthews_corrcoef(truth, predicted)),
        "confusion_matrix": confusion_matrix(truth, predicted, labels=[0, POSITIVE_LABEL]).tolist(),
        "confusion_matrix_labels": [0, POSITIVE_LABEL],
        "roc_auc": None,
        "pr_auc": None,
        "score_source": None,
    }
    if positive_scores is None:
        return result
    scores = np.asarray(positive_scores)
    if len(np.unique(truth)) == 2:
        result["roc_auc"] = float(roc_auc_score(truth, scores))
        result["pr_auc"] = float(average_precision_score(truth, scores, pos_label=POSITIVE_LABEL))
    return result


def evaluate_estimator(estimator: Any, features: Any, labels: Any) -> dict[str, Any]:
    """Evaluate a fitted estimator using Label=1 scores where available."""
    predictions = estimator.predict(features)
    scores, source = continuous_positive_scores(estimator, features)
    result = evaluate_binary_predictions(labels, predictions, scores)
    result["score_source"] = source
    return result


def fit_and_measure_runtime(
    estimator: Any, train_features: Any, train_labels: Any, test_features: Any
) -> dict[str, float]:
    """Fit once and measure fit/inference separately with a high-resolution timer.

    This utility is intentionally not invoked by infrastructure setup. Any future
    benchmark should use it only after selecting a frozen configuration.
    """
    train_start = perf_counter()
    estimator.fit(train_features, train_labels)
    training_seconds = perf_counter() - train_start
    inference_start = perf_counter()
    estimator.predict(test_features)
    inference_seconds = perf_counter() - inference_start
    test_count = len(test_features)
    return {
        "training_seconds": training_seconds,
        "test_inference_total_seconds": inference_seconds,
        "test_inference_milliseconds_per_sample": 0.0 if test_count == 0 else inference_seconds * 1000 / test_count,
    }

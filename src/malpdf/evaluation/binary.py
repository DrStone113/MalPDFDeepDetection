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


def classification_metrics_from_confusion_counts(
    *, tn: int, fp: int, fn: int, tp: int
) -> dict[str, float]:
    """Derive binary class and macro metrics from ``[[TN, FP], [FN, TP]]``.

    ``*_malicious`` treats Label=1 as the operational positive class. Macro
    values average the benign (Label=0) and malicious (Label=1) class metrics.
    Zero denominators follow the project's ``zero_division=0`` convention.
    """
    if min(tn, fp, fn, tp) < 0:
        raise ValueError("Confusion-matrix counts must be non-negative")

    def divide(numerator: int, denominator: int) -> float:
        return 0.0 if denominator == 0 else numerator / denominator

    total = tn + fp + fn + tp
    if total == 0:
        raise ValueError("Confusion-matrix counts must contain at least one sample")
    precision_malicious = divide(tp, tp + fp)
    recall_malicious = divide(tp, tp + fn)
    precision_benign = divide(tn, tn + fn)
    recall_benign = divide(tn, tn + fp)

    def f1(precision: float, recall: float) -> float:
        return 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)

    f1_malicious = f1(precision_malicious, recall_malicious)
    f1_benign = f1(precision_benign, recall_benign)
    return {
        "accuracy": (tn + tp) / total,
        "precision_benign": precision_benign,
        "recall_benign": recall_benign,
        "f1_benign": f1_benign,
        "precision_malicious": precision_malicious,
        "recall_malicious": recall_malicious,
        "f1_malicious": f1_malicious,
        "precision_macro": (precision_benign + precision_malicious) / 2,
        "recall_macro": (recall_benign + recall_malicious) / 2,
        "f1_macro": (f1_benign + f1_malicious) / 2,
    }


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
    """Compute malicious-positive and macro metrics plus score-based metrics.

    Historical ``precision``, ``recall``, and ``f1`` fields remain aliases for
    Label=1 malicious-positive metrics. New code should use the explicit named
    fields instead. ROC-AUC and PR-AUC retain Label=1 score semantics.
    """
    truth = np.asarray(y_true)
    predicted = np.asarray(y_predicted)
    malicious_precision = float(
        precision_score(truth, predicted, pos_label=POSITIVE_LABEL, zero_division=0)
    )
    malicious_recall = float(
        recall_score(truth, predicted, pos_label=POSITIVE_LABEL, zero_division=0)
    )
    malicious_f1 = float(f1_score(truth, predicted, pos_label=POSITIVE_LABEL, zero_division=0))
    result: dict[str, Any] = {
        "positive_label": POSITIVE_LABEL,
        "accuracy": float(accuracy_score(truth, predicted)),
        "precision_malicious": malicious_precision,
        "recall_malicious": malicious_recall,
        "f1_malicious": malicious_f1,
        "precision_macro": float(
            precision_score(truth, predicted, labels=[0, POSITIVE_LABEL], average="macro", zero_division=0)
        ),
        "recall_macro": float(
            recall_score(truth, predicted, labels=[0, POSITIVE_LABEL], average="macro", zero_division=0)
        ),
        "f1_macro": float(
            f1_score(truth, predicted, labels=[0, POSITIVE_LABEL], average="macro", zero_division=0)
        ),
        # Backward-compatible aliases used by completed historical reports.
        "precision": malicious_precision,
        "recall": malicious_recall,
        "f1": malicious_f1,
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


def fit_predict_and_measure(
    estimator: Any, train_features: Any, train_labels: Any, test_features: Any
) -> tuple[np.ndarray, np.ndarray | None, str | None, dict[str, float]]:
    """Fit on training data and time one complete held-out inference pass.

    The inference interval includes class prediction and, when available,
    probability or decision-score generation needed for ROC-AUC and PR-AUC.
    """
    train_start = perf_counter()
    estimator.fit(train_features, train_labels)
    training_seconds = perf_counter() - train_start
    predictions, positive_scores, score_source, runtime = predict_and_measure(
        estimator, test_features
    )
    return (
        predictions,
        positive_scores,
        score_source,
        {
            "training_seconds": training_seconds,
            "test_inference_total_seconds": runtime["inference_total_seconds"],
            "test_inference_milliseconds_per_sample": runtime[
                "inference_milliseconds_per_sample"
            ],
        },
    )


def predict_and_measure(
    estimator: Any, features: Any
) -> tuple[np.ndarray, np.ndarray | None, str | None, dict[str, float]]:
    """Time one complete inference pass without fitting the estimator."""
    inference_start = perf_counter()
    predictions = np.asarray(estimator.predict(features))
    positive_scores, score_source = continuous_positive_scores(estimator, features)
    inference_seconds = perf_counter() - inference_start
    sample_count = len(features)
    runtime = {
        "inference_total_seconds": inference_seconds,
        "inference_milliseconds_per_sample": (
            0.0 if sample_count == 0 else inference_seconds * 1000 / sample_count
        ),
    }
    return predictions, positive_scores, score_source, runtime


def fit_and_measure_runtime(
    estimator: Any, train_features: Any, train_labels: Any, test_features: Any
) -> dict[str, float]:
    """Fit once and measure fit/inference separately with a high-resolution timer.

    This utility is intentionally not invoked by infrastructure setup. Any future
    benchmark should use it only after selecting a frozen configuration.
    """
    _, _, _, runtime = fit_predict_and_measure(
        estimator, train_features, train_labels, test_features
    )
    return runtime

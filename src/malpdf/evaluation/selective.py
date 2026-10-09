"""Small, explicit utilities for validation-locked static fusion and referral.

These functions are deliberately model-agnostic: they receive only labels and
malicious-class probabilities.  They never construct a dynamic value, submit a
sample, or use a test partition to choose a candidate.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

import numpy as np
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss, log_loss

from malpdf.evaluation.binary import evaluate_binary_predictions


CALIBRATION_METHODS = ("none", "platt", "isotonic")


def _probabilities(values: Any) -> np.ndarray:
    probabilities = np.asarray(values, dtype=float).reshape(-1)
    if not len(probabilities) or not np.isfinite(probabilities).all() or (probabilities < 0).any() or (probabilities > 1).any():
        raise ValueError("Probabilities must be a non-empty finite vector within [0, 1]")
    return probabilities


def _labels(values: Any, length: int, *, require_both_classes: bool = True) -> np.ndarray:
    labels = np.asarray(values, dtype=int).reshape(-1)
    if len(labels) != length or not np.isin(labels, (0, 1)).all() or (require_both_classes and len(np.unique(labels)) != 2):
        raise ValueError("Labels must be binary 0/1 and contain both classes when score metrics are requested")
    return labels


def binary_entropy(probabilities: Any) -> np.ndarray:
    """Return natural-log binary entropy, with exact finite endpoint handling."""
    values = _probabilities(probabilities)
    safe = np.clip(values, np.finfo(float).eps, 1.0 - np.finfo(float).eps)
    return -(safe * np.log(safe) + (1.0 - safe) * np.log(1.0 - safe))


def expected_calibration_error(labels: Any, probabilities: Any, *, n_bins: int = 10) -> float:
    """Fixed-width ECE for malicious-class probabilities."""
    values = _probabilities(probabilities)
    truth = _labels(labels, len(values), require_both_classes=False)
    if n_bins < 2:
        raise ValueError("ECE requires at least two bins")
    bin_ids = np.minimum((values * n_bins).astype(int), n_bins - 1)
    error = 0.0
    for index in range(n_bins):
        mask = bin_ids == index
        if mask.any():
            error += float(mask.mean()) * abs(float(values[mask].mean()) - float(truth[mask].mean()))
    return float(error)


def calibration_metrics(labels: Any, probabilities: Any, *, n_bins: int = 10, threshold: float = 0.5) -> dict[str, Any]:
    """Combine calibration and score-based metrics without hard-score shortcuts."""
    values = _probabilities(probabilities)
    truth = _labels(labels, len(values), require_both_classes=False)
    if type(threshold) not in (int, float) or not np.isfinite(threshold) or not 0 <= threshold <= 1:
        raise ValueError("Decision threshold must be finite and within [0,1]")
    predictions = (values >= threshold).astype(int)
    result = evaluate_binary_predictions(truth, predictions, values)
    result.update(
        {
            "brier": float(brier_score_loss(truth, values, pos_label=1)),
            "log_loss": float(log_loss(truth, values, labels=[0, 1])),
            "ece": expected_calibration_error(truth, values, n_bins=n_bins),
            "ece_bins": n_bins,
            "threshold": float(threshold),
        }
    )
    return result


class _IdentityCalibrator:
    def predict(self, probabilities: Any) -> np.ndarray:
        return _probabilities(probabilities)


def fit_probability_calibrator(method: str, probabilities: Any, labels: Any, *, seed: int = 42) -> Any:
    """Fit exactly one predeclared calibrator from validation-only predictions."""
    values = _probabilities(probabilities)
    truth = _labels(labels, len(values), require_both_classes=False)
    if method == "none":
        return _IdentityCalibrator()
    if method == "platt":
        model = LogisticRegression(C=1.0, solver="lbfgs", max_iter=1000, random_state=seed)
        return model.fit(values.reshape(-1, 1), truth)
    if method == "isotonic":
        return IsotonicRegression(y_min=0.0, y_max=1.0, out_of_bounds="clip").fit(values, truth)
    raise ValueError(f"Unknown calibration method {method!r}; expected {CALIBRATION_METHODS}")


def apply_probability_calibrator(method: str, calibrator: Any, probabilities: Any) -> np.ndarray:
    values = _probabilities(probabilities)
    if method == "none":
        calibrated = calibrator.predict(values)
    elif method == "platt":
        calibrated = calibrator.predict_proba(values.reshape(-1, 1))[:, 1]
    elif method == "isotonic":
        calibrated = calibrator.predict(values)
    else:
        raise ValueError(f"Unknown calibration method {method!r}")
    return _probabilities(calibrated)


def fuse_probabilities(xgb_probabilities: Any, ft_probabilities: Any, *, xgb_weight: float) -> np.ndarray:
    """Use a fixed convex probability average; `xgb_weight=1` is XGBoost only."""
    xgb = _probabilities(xgb_probabilities)
    ft = _probabilities(ft_probabilities)
    if len(xgb) != len(ft) or not 0.0 <= xgb_weight <= 1.0:
        raise ValueError("Fusion requires equal-length probabilities and 0 <= xgb_weight <= 1")
    return xgb_weight * xgb + (1.0 - xgb_weight) * ft


def continuous_disagreement(xgb_probabilities: Any, ft_probabilities: Any) -> np.ndarray:
    xgb = _probabilities(xgb_probabilities)
    ft = _probabilities(ft_probabilities)
    if len(xgb) != len(ft):
        raise ValueError("Disagreement requires equal-length probabilities")
    return np.abs(xgb - ft)


def binary_disagreement(xgb_probabilities: Any, ft_probabilities: Any) -> np.ndarray:
    xgb = _probabilities(xgb_probabilities)
    ft = _probabilities(ft_probabilities)
    if len(xgb) != len(ft):
        raise ValueError("Disagreement requires equal-length probabilities")
    return (xgb >= 0.5) != (ft >= 0.5)


@dataclass(frozen=True)
class ReferralResult:
    requested_referral_rate: float
    referral_rate: float
    coverage: float
    referred: np.ndarray


def referral_by_uncertainty(uncertainty: Any, *, referral_rate: float, always_refer: Any | None = None) -> ReferralResult:
    """Refer the most uncertain rows with stable deterministic tie handling.

    `always_refer` supports the disagreement-first policy. It may make the
    achieved referral rate exceed the requested budget; both values are kept.
    """
    scores = np.asarray(uncertainty, dtype=float).reshape(-1)
    if not len(scores) or not np.isfinite(scores).all() or not 0.0 <= referral_rate <= 1.0:
        raise ValueError("Uncertainty and referral rate are invalid")
    forced = np.zeros(len(scores), dtype=bool) if always_refer is None else np.asarray(always_refer, dtype=bool).reshape(-1)
    if len(forced) != len(scores):
        raise ValueError("always_refer must match uncertainty length")
    requested_count = int(round(referral_rate * len(scores)))
    referred = forced.copy()
    additional = max(0, requested_count - int(referred.sum()))
    if additional:
        candidates = np.flatnonzero(~referred)
        # lexsort keeps lower original position first for equal scores.
        order = candidates[np.lexsort((candidates, -scores[candidates]))]
        referred[order[:additional]] = True
    actual_rate = float(referred.mean())
    return ReferralResult(referral_rate, actual_rate, 1.0 - actual_rate, referred)


def selective_metrics(labels: Any, probabilities: Any, referred: Any, *, threshold: float = 0.5) -> dict[str, Any]:
    """Evaluate only static-retained samples; referrals are never corrected."""
    values = _probabilities(probabilities)
    truth = _labels(labels, len(values), require_both_classes=False)
    routed = np.asarray(referred, dtype=bool).reshape(-1)
    if len(routed) != len(values) or routed.all():
        raise ValueError("Selective metrics require at least one retained row")
    if type(threshold) not in (int, float) or not np.isfinite(threshold) or not 0 <= threshold <= 1:
        raise ValueError("Decision threshold must be finite and within [0,1]")
    predictions = (values >= threshold).astype(int)
    retained = ~routed
    metrics = evaluate_binary_predictions(truth[retained], predictions[retained], values[retained])
    errors = predictions != truth
    fp = (predictions == 1) & (truth == 0)
    fn = (predictions == 0) & (truth == 1)
    total_errors = int(errors.sum())
    return {
        "coverage": float(retained.mean()),
        "referral_rate": float(routed.mean()),
        "retained_metrics": metrics,
        "fp_retained": int((fp & retained).sum()),
        "fn_retained": int((fn & retained).sum()),
        "fp_referred": int((fp & routed).sum()),
        "fn_referred": int((fn & routed).sum()),
        "errors_referred": int((errors & routed).sum()),
        "error_capture_rate": 0.0 if total_errors == 0 else float((errors & routed).sum() / total_errors),
        "fn_capture_rate": 0.0 if not fn.any() else float((fn & routed).sum() / fn.sum()),
        "fp_capture_rate": 0.0 if not fp.any() else float((fp & routed).sum() / fp.sum()),
        "referred_error_rate": 0.0 if not routed.any() else float(errors[routed].mean()),
        "retained_error_rate": float(errors[retained].mean()),
    }


def validate_candidate_grid(weights: Iterable[float]) -> tuple[float, ...]:
    selected = tuple(float(weight) for weight in weights)
    if not selected or any(not 0.0 <= weight <= 1.0 for weight in selected) or len(set(selected)) != len(selected):
        raise ValueError("Fusion weights must be unique values within [0, 1]")
    return selected


def fail_closed_routing(labels, probabilities, identifiers, parser_failed, *, threshold):
    """Forced parser referrals first; entropy fills the remaining 10% budget."""
    order = np.argsort(np.asarray(identifiers), kind="stable")
    forced = np.asarray(parser_failed, bool)
    entropy = binary_entropy(probabilities) / np.log(2.0)
    decision = referral_by_uncertainty(entropy[order], referral_rate=0.1, always_refer=forced[order])
    mask = np.empty(len(order), bool)
    mask[order] = decision.referred
    measured = selective_metrics(labels, probabilities, mask, threshold=threshold)
    fn_total = measured["fn_referred"] + measured["fn_retained"]
    summary = {"policy": "parser_referral_then_entropy_10_percent", "coverage": decision.coverage,
               "referral_rate": decision.referral_rate, "requested_referral_rate": 0.1,
               "forced_parser_referrals": int(forced.sum()), "referred_count": int(mask.sum()),
               "fn_total": fn_total, "fn_referred": measured["fn_referred"], "fn_retained": measured["fn_retained"],
               "fn_catch_rate": measured["fn_referred"] / fn_total if fn_total else None,
               "retained_metrics": calibration_metrics(np.asarray(labels)[~mask], np.asarray(probabilities)[~mask], threshold=threshold),
               "entropy_unit": "bits", "dynamic_samples_executed": 0, "referrals_counted_as_corrected": False}
    return summary, mask

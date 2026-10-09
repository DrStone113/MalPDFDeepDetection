"""Validation-only Platt-calibrated stacking and fixed-budget static referral."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

from malpdf.evaluation.selective import (
    apply_probability_calibrator, binary_entropy, calibration_metrics,
    fit_probability_calibrator, fuse_probabilities, referral_by_uncertainty,
    selective_metrics,
)
from malpdf.reproducibility import set_random_seed

BASE_BRANCHES = ("xgboost", "ft_transformer")
VISION_BRANCHES = (*BASE_BRANCHES, "vision_resnet18")
SELECTION_POLICY = "maximize validation-selection MCC; malicious F1 secondary; exact ties keep declared candidate order"


@dataclass(frozen=True)
class FusionPartition:
    partition: str
    sample_ids: tuple[str, ...]
    group_ids: tuple[str, ...]
    labels: np.ndarray
    probabilities: np.ndarray
    branches: tuple[str, ...] = BASE_BRANCHES

    def __post_init__(self):
        if self.partition not in {"validation", "test"} or self.branches not in (BASE_BRANCHES, VISION_BRANCHES):
            raise ValueError("Fusion needs a validation/test partition and the declared branch order")
        size = len(self.sample_ids)
        if not 1 <= size <= 100_000 or len(set(self.sample_ids)) != size or len(self.group_ids) != size:
            raise ValueError("Fusion sample IDs must be unique and groups must cover every row")
        if any(not isinstance(value, str) or not value for value in (*self.sample_ids, *self.group_ids)):
            raise ValueError("Fusion sample/group IDs must be nonempty strings")
        labels = np.asarray(self.labels)
        scores = np.asarray(self.probabilities, dtype=float)
        if labels.shape != (size,) or not np.isin(labels, (0, 1)).all() or set(labels.tolist()) != {0, 1}:
            raise ValueError("Official fusion labels must be binary and contain both classes")
        if scores.shape != (size, len(self.branches)) or not np.isfinite(scores).all() or (scores < 0).any() or (scores > 1).any():
            raise ValueError("Fusion probabilities must be finite, aligned and within [0,1]")
        group_labels = {}
        for group, label in zip(self.group_ids, labels):
            if group in group_labels and group_labels[group] != label:
                raise ValueError("Fusion groups cannot contain conflicting labels")
            group_labels[group] = label
        labels, scores = labels.astype(int, copy=True), scores.copy()
        labels.setflags(write=False)
        scores.setflags(write=False)
        object.__setattr__(self, "labels", labels)
        object.__setattr__(self, "probabilities", scores)


def validation_roles(validation: FusionPartition, *, seed: int = 42) -> dict[str, np.ndarray]:
    """Split validation groups into meta-fit/calibration-fit/selection (~25/25/50)."""
    if validation.partition != "validation" or type(seed) is not int or seed != 42:
        raise ValueError("Fitting/selection must use validation only with seed 42")
    groups = sorted(set(validation.group_ids))
    label_by_group = dict(zip(validation.group_ids, validation.labels))
    if min(sum(label_by_group[group] == label for group in groups) for label in (0, 1)) < 4:
        raise ValueError("Validation needs at least four independent groups per class")
    fit_groups, selection_groups = train_test_split(groups, train_size=0.5, random_state=seed, stratify=[label_by_group[group] for group in groups])
    fit_groups = sorted(fit_groups)
    meta_groups, calibration_groups = train_test_split(fit_groups, train_size=0.5, random_state=seed, stratify=[label_by_group[group] for group in fit_groups])
    roles = {name: np.flatnonzero(np.isin(validation.group_ids, values)) for name, values in
             (("meta_fit", meta_groups), ("calibration_fit", calibration_groups), ("selection", selection_groups))}
    for positions in roles.values():
        if set(validation.labels[positions].tolist()) != {0, 1}:
            raise ValueError("Every validation role must contain both classes")
    return roles


@dataclass(frozen=True)
class FusionCandidate:
    family: str
    regularization_c: float = 1.0
    xgb_weight: float = 0.5
    vision_weight: float = 0.0

    def __post_init__(self):
        if self.family not in {"stacking", "weighted_average"}:
            raise ValueError("Unknown fusion family")
        for name in ("regularization_c", "xgb_weight", "vision_weight"):
            value = getattr(self, name)
            if type(value) not in (int, float) or not np.isfinite(value):
                raise ValueError("Candidate parameters must be finite numbers")
        if self.regularization_c <= 0 or not 0 <= self.xgb_weight <= 1 or not 0 <= self.vision_weight < 1:
            raise ValueError("Invalid regularization or convex fusion weight")
        if self.family == "stacking" and self.vision_weight != 0:
            raise ValueError("Stacking learns coefficients; explicit vision weights apply to averages")


def candidate_grid(*, vision_available: bool, regularization_cs=(0.1, 1.0, 10.0),
                   xgb_weights=(0.0, 0.25, 0.5, 0.75, 1.0), vision_weights=(0.0, 0.1, 0.25)) -> tuple[FusionCandidate, ...]:
    if type(vision_available) is not bool:
        raise ValueError("Vision availability must be an explicit boolean")
    candidates = [FusionCandidate("stacking", regularization_c=value) for value in regularization_cs]
    candidates += [FusionCandidate("weighted_average", xgb_weight=xgb, vision_weight=vision)
                   for vision in vision_weights if vision_available or vision == 0
                   for xgb in xgb_weights]
    if not candidates or len(candidates) > 64 or len(set(candidates)) != len(candidates):
        raise ValueError("Require 1–64 unique declared fusion candidates")
    return tuple(candidates)


def _raw_probability(candidate: FusionCandidate, probabilities: np.ndarray, meta: LogisticRegression | None) -> np.ndarray:
    if candidate.family == "stacking":
        return meta.predict_proba(probabilities)[:, 1]
    tabular = fuse_probabilities(probabilities[:, 0], probabilities[:, 1], xgb_weight=candidate.xgb_weight)
    if candidate.vision_weight:
        if probabilities.shape[1] != 3:
            raise ValueError("Nonzero Vision weight requires genuine aligned Vision probabilities")
        return (1 - candidate.vision_weight) * tabular + candidate.vision_weight * probabilities[:, 2]
    return tabular


def _logistic_state(model: LogisticRegression | None) -> dict | None:
    return None if model is None else {"coefficients": model.coef_.tolist(), "intercept": model.intercept_.tolist(), "classes": model.classes_.tolist(), "C": model.C}


def _check_fitted_logistic(model: LogisticRegression) -> None:
    if not np.isfinite(model.coef_).all() or not np.isfinite(model.intercept_).all() or np.max(model.n_iter_) >= model.max_iter:
        raise RuntimeError("Fusion logistic fitting is non-finite or did not converge")


@dataclass(frozen=True)
class FittedLateFusion:
    candidate: FusionCandidate
    branches: tuple[str, ...]
    meta_learner: LogisticRegression | None
    platt_calibrator: LogisticRegression
    selection: dict
    role_summary: dict

    def predict_proba(self, partition: FusionPartition) -> np.ndarray:
        if partition.branches != self.branches:
            raise ValueError("Prediction branch order differs from the fitted stack")
        raw = _raw_probability(self.candidate, partition.probabilities, self.meta_learner)
        return apply_probability_calibrator("platt", self.platt_calibrator, raw)

    def lock_metadata(self) -> dict:
        return {"candidate": asdict(self.candidate), "branches": list(self.branches),
                "meta_learner": _logistic_state(self.meta_learner), "platt_calibrator": _logistic_state(self.platt_calibrator),
                "platt_input": "uncalibrated fused malicious-class probability", "validation_roles": self.role_summary,
                "selection": self.selection, "selection_policy": SELECTION_POLICY, "seed": 42,
                "threshold": 0.5, "ece_bins": 10, "test_used_for_fitting_or_selection": False,
                "refit_after_selection": False}


def fit_validation_stack(validation: FusionPartition, candidates: tuple[FusionCandidate, ...], *, seed: int = 42) -> tuple[FittedLateFusion, list[dict], dict[str, np.ndarray]]:
    """Fit only validation; test labels/scores are absent from this API."""
    roles = validation_roles(validation, seed=seed)
    if not candidates or any(not isinstance(candidate, FusionCandidate) for candidate in candidates) or len(candidates) > 64 or len(set(candidates)) != len(candidates):
        raise ValueError("Require 1–64 unique fusion candidates")
    if validation.branches == BASE_BRANCHES and any(candidate.vision_weight for candidate in candidates):
        raise ValueError("Nonzero Vision weights require the Vision branch")
    set_random_seed(seed)
    role_summary = {}
    for name, positions in roles.items():
        ids = sorted(validation.sample_ids[index] for index in positions)
        role_summary[name] = {"rows": len(ids), "groups": len({validation.group_ids[index] for index in positions}),
                              "sample_ids_sha256": hashlib.sha256(json.dumps(ids, separators=(",", ":")).encode()).hexdigest()}
    meta_pos, cal_pos, selection_pos = (roles[name] for name in ("meta_fit", "calibration_fit", "selection"))
    rows, fitted = [], []
    for order, candidate in enumerate(candidates):
        meta = None
        if candidate.family == "stacking":
            meta = LogisticRegression(C=candidate.regularization_c, solver="lbfgs", max_iter=1000, random_state=seed)
            meta.fit(validation.probabilities[meta_pos], validation.labels[meta_pos])
            _check_fitted_logistic(meta)
        raw_calibration = _raw_probability(candidate, validation.probabilities[cal_pos], meta)
        platt = fit_probability_calibrator("platt", raw_calibration, validation.labels[cal_pos], seed=seed)
        _check_fitted_logistic(platt)
        selection_scores = apply_probability_calibrator("platt", platt, _raw_probability(candidate, validation.probabilities[selection_pos], meta))
        metrics = calibration_metrics(validation.labels[selection_pos], selection_scores, n_bins=10)
        row = {"candidate_order": order, **asdict(candidate), "partition": "validation_selection",
               "mcc": metrics["mcc"], "f1_malicious": metrics["f1_malicious"], "brier": metrics["brier"],
               "log_loss": metrics["log_loss"], "ece": metrics["ece"]}
        rows.append(row)
        fitted.append(FittedLateFusion(candidate, validation.branches, meta, platt, row, role_summary))
    best = max(range(len(rows)), key=lambda index: (rows[index]["mcc"], rows[index]["f1_malicious"], -index))
    return fitted[best], rows, roles


def entropy_routing(labels, probabilities, sample_ids, *, threshold: float = 0.5) -> tuple[dict, np.ndarray]:
    """Refer the fixed top 10% entropy without labels influencing routing."""
    ids = tuple(sample_ids)
    values = np.asarray(probabilities, dtype=float)
    truth = np.asarray(labels)
    if values.shape != (len(ids),) or truth.shape != values.shape or len(set(ids)) != len(ids):
        raise ValueError("Routing requires unique aligned IDs, labels and probabilities")
    order = np.argsort(np.asarray(ids), kind="stable")
    entropy = binary_entropy(values) / np.log(2.0)
    decision = referral_by_uncertainty(entropy[order], referral_rate=0.10)
    referred = np.empty(len(ids), dtype=bool)
    referred[order] = decision.referred
    measured = selective_metrics(truth, values, referred, threshold=threshold)
    retained = calibration_metrics(truth[~referred], values[~referred], n_bins=10, threshold=threshold)
    fn_count = int(((truth == 1) & (values < threshold)).sum())
    summary = {"policy": "top_entropy_10_percent", "entropy_unit": "bits", "requested_referral_rate": 0.10,
               "referral_rate": decision.referral_rate, "coverage": decision.coverage,
               "referred_count": int(referred.sum()), "retained_count": int((~referred).sum()),
               "fn_total": fn_count, "fn_referred": measured["fn_referred"], "fn_retained": measured["fn_retained"],
               "fn_catch_rate": measured["fn_referred"] / fn_count if fn_count else None,
               "fn_catch_rate_unavailable_reason": None if fn_count else "No false negatives in the evaluated partition",
               "errors_referred": measured["errors_referred"], "error_capture_rate": measured["error_capture_rate"],
               "retained_metrics": retained, "threshold": float(threshold), "dynamic_samples_executed": 0,
               "referrals_counted_as_corrected": False}
    return summary, referred

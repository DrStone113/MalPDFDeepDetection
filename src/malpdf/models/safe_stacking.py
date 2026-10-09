"""Safety-preserving features, group-aware train CV, and validation-only v3 stacking."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from types import SimpleNamespace

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_curve
from sklearn.model_selection import StratifiedGroupKFold, train_test_split

from malpdf.evaluation.selective import apply_probability_calibrator, calibration_metrics, fit_probability_calibrator
from malpdf.models.late_fusion import _check_fitted_logistic, _logistic_state, validation_roles
from malpdf.reproducibility import set_random_seed
from malpdf.static.schema import PROTOCOL_G_DROPPED_CONSTANT_FEATURES, PROTOCOL_G_REQUIRED_FEATURES, RIT_FEATURES

V3_BRANCHES = ("xgboost", "lightgbm", "catboost", "random_forest", "ft_transformer")
INTERACTIONS = {
    "script_ratio": "(JS + JavaScript) / (1 + obj)",
    "ObfuscationCount": "Number of raw PDF name tokens containing a valid #HH hexadecimal escape; checksum-verified PDF bytes only",
}
V3_FEATURES = (*PROTOCOL_G_REQUIRED_FEATURES, *INTERACTIONS)


def safe_feature_view(frame: pd.DataFrame, *, check_training_constants: bool = False) -> pd.DataFrame:
    """Preserve all 38 source features exactly, with two unfitted interactions.

    Check permitted exclusions only on the training/fold-fitting partition;
    validation/test values never choose a feature or alter preprocessing.
    """
    if not frame.columns.is_unique or not set(RIT_FEATURES).issubset(frame.columns) or frame.empty:
        raise ValueError("Safety-first v3 requires the complete 41-feature source schema")
    if "ObfuscationCount" not in frame:
        raise ValueError("ObfuscationCount must be measured from real checksum-verified PDF bytes, never a proxy or missing-value fill")
    values = frame.loc[:, RIT_FEATURES].to_numpy(dtype=np.float64)
    if not np.isfinite(values).all():
        raise ValueError("Source features must be finite; no imputation or clipping")
    if check_training_constants and any(frame[name].nunique(dropna=False) != 1 for name in PROTOCOL_G_DROPPED_CONSTANT_FEATURES):
        raise ValueError("Only the three verified zero-variance training features may be excluded")
    counts = frame.loc[:, ["JS", "JavaScript", "obj", "Encoding", "ObjStm"]].to_numpy(dtype=float)
    if (counts < 0).any():
        raise ValueError("Interaction counts must be nonnegative; semantic source values are never clipped")
    result = frame.loc[:, PROTOCOL_G_REQUIRED_FEATURES].copy()
    result["script_ratio"] = (frame.JS.astype(float) + frame.JavaScript.astype(float)) / (1 + frame.obj.astype(float))
    obfuscation = frame.ObfuscationCount.to_numpy(dtype=float)
    if not np.isfinite(obfuscation).all() or (obfuscation < 0).any() or not np.equal(obfuscation, np.floor(obfuscation)).all():
        raise ValueError("Measured ObfuscationCount must contain nonnegative integer counts")
    result["ObfuscationCount"] = frame.ObfuscationCount.copy()
    if tuple(result.columns) != V3_FEATURES or not np.isfinite(result.to_numpy(dtype=float)).all():
        raise ValueError("V3 feature contract or finite interaction validation failed")
    return result


def v3_validation_roles(manifest: pd.DataFrame, *, seed: int = 42) -> dict[str, np.ndarray]:
    """Four disjoint deterministic validation-group roles (~25% each)."""
    if seed != 42 or not manifest.split.eq("validation").all():
        raise ValueError("V3 role assignment accepts only seed-42 validation")
    if not manifest.sample_id.is_unique or manifest.duplicate_group_id.isna().any() or manifest.groupby("duplicate_group_id").Label.nunique().max() != 1:
        raise ValueError("Validation requires unique IDs and label-pure nonempty groups")
    # Reuse v2's group logic; it depends only on cohort IDs/groups/labels.
    cohort = SimpleNamespace(partition="validation", sample_ids=tuple(manifest.sample_id),
                             group_ids=tuple(manifest.duplicate_group_id), labels=manifest.Label.to_numpy())
    roles = validation_roles(cohort, seed=seed)
    selected = manifest.iloc[roles.pop("selection")]
    groups = sorted(set(selected.duplicate_group_id))
    labels = selected.set_index("duplicate_group_id").Label.to_dict()
    if min(sum(labels[group] == label for group in groups) for label in (0, 1)) < 2:
        raise ValueError("Validation needs enough independent groups for four binary roles")
    base, threshold = train_test_split(groups, train_size=0.5, stratify=[labels[group] for group in groups], random_state=seed)
    roles.update(base_selection=np.flatnonzero(manifest.duplicate_group_id.isin(base)),
                 threshold_selection=np.flatnonzero(manifest.duplicate_group_id.isin(threshold)))
    if sum(map(len, roles.values())) != len(manifest) or any(set(manifest.iloc[pos].Label) != {0, 1} for pos in roles.values()):
        raise ValueError("Validation roles must cover every row and both classes")
    return roles


def train_cv_folds(manifest: pd.DataFrame, *, seed: int = 42) -> tuple[tuple[np.ndarray, np.ndarray], ...]:
    if seed != 42 or not manifest.split.eq("train").all() or not manifest.sample_id.is_unique:
        raise ValueError("Five-fold CV accepts only unique seed-42 train IDs")
    if manifest.duplicate_group_id.isna().any() or manifest.groupby("duplicate_group_id").Label.nunique().max() != 1:
        raise ValueError("Training groups must be nonempty and label-pure")
    labels, groups = manifest.Label.to_numpy(), manifest.duplicate_group_id.to_numpy()
    if set(labels) != {0, 1} or min(manifest.loc[manifest.Label.eq(label)].duplicate_group_id.nunique() for label in (0, 1)) < 5:
        raise ValueError("Five-fold CV needs at least five independent groups per class")
    result = tuple(StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed).split(np.zeros((len(manifest), 1)), labels, groups))
    seen = np.zeros(len(manifest), dtype=int)
    for fit, held in result:
        if set(groups[fit]) & set(groups[held]) or set(labels[fit]) != {0, 1} or set(labels[held]) != {0, 1}:
            raise ValueError("Training CV must preserve groups and binary classes")
        seen[held] += 1
    if not np.all(seen == 1):
        raise ValueError("Every train sample must have exactly one out-of-fold prediction")
    return result


def youden_threshold(labels, scores) -> tuple[float, dict]:
    truth, probabilities = np.asarray(labels), np.asarray(scores, dtype=float)
    if truth.shape != probabilities.shape or truth.ndim != 1 or set(truth) != {0, 1} or not np.isfinite(probabilities).all() or (probabilities < 0).any() or (probabilities > 1).any():
        raise ValueError("Youden selection requires aligned binary validation labels and probabilities")
    fpr, tpr, thresholds = roc_curve(truth, probabilities, drop_intermediate=False)
    # Exclude sklearn's infinite all-negative sentinel. Literal probability 1
    # remains a legal threshold; decisions consistently use p >= threshold.
    candidates = [(float(t), float(j)) for t, j in zip(thresholds, tpr - fpr) if np.isfinite(t) and 0 <= t <= 1]
    best_j = max(j for _, j in candidates)
    tied = [(t, calibration_metrics(truth, probabilities, threshold=t)) for t, j in candidates if abs(j - best_j) <= 1e-12]
    threshold, metrics = max(tied, key=lambda item: (item[1]["mcc"], item[1]["f1_malicious"], -abs(item[0] - 0.5), item[0]))
    return threshold, {"youden_j": best_j, "threshold": threshold, "metrics": metrics,
                       "tie_breaker": "MCC, malicious F1, closest to 0.5, larger threshold"}


@dataclass(frozen=True)
class V3Stack:
    meta: LogisticRegression
    platt: LogisticRegression
    threshold: float
    selection: dict
    role_summary: dict
    branches: tuple[str, ...] = V3_BRANCHES

    def predict_proba(self, probabilities: np.ndarray) -> np.ndarray:
        scores = _branch_probabilities(probabilities, self.branches)
        return apply_probability_calibrator("platt", self.platt, self.meta.predict_proba(scores)[:, 1])

    def lock_metadata(self) -> dict:
        return {"seed": 42, "branches": list(self.branches), "meta_learner": _logistic_state(self.meta),
                "platt_calibrator": _logistic_state(self.platt), "threshold": self.threshold,
                "selection": self.selection, "validation_roles": self.role_summary,
                "selection_policy": "Maximize threshold-selection MCC; malicious F1; declared C order",
                "threshold_policy": "Youden J on threshold-selection only; deterministic tie-breaker",
                "test_used_for_fitting_or_selection": False, "refit_after_selection": False,
                "ece_bins": 10, "referral_rate": 0.1}


def _five_probabilities(values) -> np.ndarray:
    return _branch_probabilities(values, V3_BRANCHES)


def _branch_probabilities(values, branches) -> np.ndarray:
    if branches not in (V3_BRANCHES, (*V3_BRANCHES, "vision_resnet18")):
        raise ValueError("Stacking requires the five tabular branches, optionally plus Vision")
    result = np.asarray(values, dtype=float)
    if result.ndim != 2 or result.shape[1] != len(branches) or not len(result) or not np.isfinite(result).all() or (result < 0).any() or (result > 1).any():
        raise ValueError("V3 requires finite aligned declared probability columns within [0,1]")
    return result


def fit_validation_v3(manifest: pd.DataFrame, probabilities, regularization_cs: list[float], *,
                      branches=V3_BRANCHES, roles=None) -> tuple[V3Stack, list[dict]]:
    scores = _branch_probabilities(probabilities, branches)
    if not manifest.split.eq("validation").all() or not manifest.sample_id.is_unique or set(manifest.Label) != {0, 1}:
        raise ValueError("Stacking accepts validation-only binary identities")
    roles = v3_validation_roles(manifest) if roles is None else roles
    if set(roles) != {"meta_fit", "calibration_fit", "base_selection", "threshold_selection"}:
        raise ValueError("Stacking requires four disjoint validation roles")
    covered, seen_groups = [], set()
    for positions in roles.values():
        indices = np.asarray(positions)
        if indices.ndim != 1 or indices.dtype.kind not in "iu" or not len(indices) or (indices < 0).any() or (indices >= len(manifest)).any():
            raise ValueError("Invalid validation role indices")
        groups = set(manifest.iloc[indices].duplicate_group_id)
        if seen_groups & groups or set(manifest.iloc[indices].Label) != {0, 1}:
            raise ValueError("Validation roles must preserve components and both classes")
        seen_groups |= groups
        covered.extend(indices.tolist())
    if sorted(covered) != list(range(len(manifest))):
        raise ValueError("Validation roles must cover each row exactly once")
    if len(scores) != len(manifest) or not regularization_cs or len(regularization_cs) > 16 or len(set(regularization_cs)) != len(regularization_cs) or any(type(c) not in (int, float) or not np.isfinite(c) or c <= 0 for c in regularization_cs):
        raise ValueError("V3 needs aligned validation scores and a bounded positive C grid")
    set_random_seed(42)
    labels = manifest.Label.to_numpy()
    summaries = {}
    for name, positions in roles.items():
        ids = sorted(manifest.iloc[positions].sample_id.tolist())
        summaries[name] = {"rows": len(ids), "groups": manifest.iloc[positions].duplicate_group_id.nunique(),
                           "sample_ids_sha256": hashlib.sha256(json.dumps(ids, separators=(",", ":")).encode()).hexdigest()}
    rows, fitted = [], []
    for order, c in enumerate(regularization_cs):
        meta = LogisticRegression(C=c, solver="lbfgs", max_iter=1000, random_state=42)
        meta.fit(scores[roles["meta_fit"]], labels[roles["meta_fit"]])
        _check_fitted_logistic(meta)
        platt = fit_probability_calibrator("platt", meta.predict_proba(scores[roles["calibration_fit"]])[:, 1], labels[roles["calibration_fit"]], seed=42)
        _check_fitted_logistic(platt)
        selected = roles["threshold_selection"]
        calibrated = apply_probability_calibrator("platt", platt, meta.predict_proba(scores[selected])[:, 1])
        threshold, decision = youden_threshold(labels[selected], calibrated)
        row = {"candidate_order": order, "regularization_c": c, "threshold": threshold, "youden_j": decision["youden_j"],
               **{name: decision["metrics"][name] for name in ("accuracy", "f1_malicious", "mcc", "brier", "log_loss", "ece")},
               "partition": "validation_threshold_selection"}
        rows.append(row)
        fitted.append(V3Stack(meta, platt, threshold, row, summaries, branches))
    best = max(range(len(rows)), key=lambda index: (rows[index]["mcc"], rows[index]["f1_malicious"], -index))
    return fitted[best], rows

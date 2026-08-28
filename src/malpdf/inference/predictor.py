"""Strict gate, frozen-model prediction, and local native TreeSHAP utilities."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any, Callable

import numpy as np
import pandas as pd

from malpdf.inference.deployment import DeploymentError, load_verified_deployment_model
from malpdf.inference.result import InferenceResult, LocalContribution
from malpdf.inference.schema import DEPLOYMENT_FEATURE_ORDER, DEPLOYMENT_MODEL_ID, DEPLOYMENT_THRESHOLD
from malpdf.static import StaticInspectionLimits, inspect_pdf

MARGIN_TOLERANCE = 2e-5
PROBABILITY_TOLERANCE = 2e-6


def _base_result(static_result: Any, gate: Any) -> dict[str, Any]:
    return {
        "input": {
            "sha256": static_result.input.get("sha256"),
            "size_bytes": static_result.input.get("size_bytes"),
        },
        "extraction": {
            "success": bool(static_result.parser.get("success")) and not any(issue.fatal for issue in static_result.errors),
            "warnings": [issue.message for issue in static_result.warnings],
            "errors": [issue.message for issue in static_result.errors],
        },
        "compatibility": {
            "passed": gate.passed,
            "expected_features": gate.expected_feature_count,
            "compatible_features": gate.compatible_feature_count,
            "blockers": list(gate.blocking_features),
        },
        "model": {
            "name": DEPLOYMENT_MODEL_ID,
            "artifact_sha256": None,
            "training_dataset_sha256": None,
            "feature_schema": None,
            "threshold": DEPLOYMENT_THRESHOLD,
        },
        "prediction": {
            "available": False,
            "malicious_probability": None,
            "predicted_label": None,
            "verdict": None,
            "error": None,
        },
        "explanation": {
            "available": False,
            "base_value": None,
            "top_positive_contributions": [],
            "top_negative_contributions": [],
            "error": None,
        },
        "safety": {
            "active_content_executed": False,
            "external_resources_followed": False,
            "embedded_payload_executed": False,
        },
    }


def _feature_frame(features: dict[str, int | float | None]) -> pd.DataFrame:
    """Explicitly construct the exact saved order, rejecting every invalid value."""
    row: dict[str, int | float] = {}
    for feature in DEPLOYMENT_FEATURE_ORDER:
        value = features.get(feature)
        if not isinstance(value, (int, float, np.number)) or isinstance(value, bool) or not math.isfinite(float(value)):
            raise DeploymentError(f"Required model feature {feature!r} is not finite numeric data")
        row[feature] = value
    return pd.DataFrame([row], columns=list(DEPLOYMENT_FEATURE_ORDER))


def _sigmoid(value: float) -> float:
    if value >= 0:
        return 1.0 / (1.0 + math.exp(-value))
    exponent = math.exp(value)
    return exponent / (1.0 + exponent)


def verdict_from_probability(probability: float, threshold: float = DEPLOYMENT_THRESHOLD) -> tuple[int, str]:
    """Apply the documented fixed binary deployment rule without threshold tuning."""
    if not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
        raise DeploymentError("Malicious probability must be finite and within [0, 1]")
    if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
        raise DeploymentError("Deployment threshold must be finite and within [0, 1]")
    label = int(probability >= threshold)
    return label, "MALICIOUS" if label else "BENIGN"


def local_treeshap_explanation(model: Any, features: pd.DataFrame, probability: float) -> dict[str, Any]:
    """Return validated native XGBoost TreeSHAP contributions for one row."""
    try:
        import xgboost as xgb

        booster = model.get_booster()
        matrix = xgb.DMatrix(features, feature_names=list(DEPLOYMENT_FEATURE_ORDER))
        raw = np.asarray(booster.predict(matrix, pred_contribs=True), dtype=float)
        margins = np.asarray(booster.predict(matrix, output_margin=True), dtype=float)
        if raw.shape != (1, len(DEPLOYMENT_FEATURE_ORDER) + 1) or margins.shape != (1,):
            raise DeploymentError("Native TreeSHAP returned an unexpected contribution or margin shape")
        contributions, bias, margin = raw[0, :-1], float(raw[0, -1]), float(margins[0])
        reconstruction_error = abs(float(contributions.sum()) + bias - margin)
        probability_error = abs(_sigmoid(margin) - probability)
        if reconstruction_error > MARGIN_TOLERANCE or probability_error > PROBABILITY_TOLERANCE:
            raise DeploymentError(
                "Native TreeSHAP mathematical identity failed "
                f"(margin error={reconstruction_error:.3g}, probability error={probability_error:.3g})"
            )
        values = features.iloc[0]
        entries = [
            LocalContribution(feature, float(values[feature]), float(contribution))
            for feature, contribution in zip(DEPLOYMENT_FEATURE_ORDER, contributions, strict=True)
        ]
        positive = sorted((item for item in entries if item.contribution > 0), key=lambda item: item.contribution, reverse=True)[:5]
        negative = sorted((item for item in entries if item.contribution < 0), key=lambda item: item.contribution)[:5]
        return {
            "available": True,
            "base_value": bias,
            "top_positive_contributions": [item.to_dict() for item in positive],
            "top_negative_contributions": [item.to_dict() for item in negative],
            "margin": margin,
            "margin_reconstruction_error": reconstruction_error,
            "probability_reconstruction_error": probability_error,
            "error": None,
        }
    except Exception as error:
        return {
            "available": False,
            "base_value": None,
            "top_positive_contributions": [],
            "top_negative_contributions": [],
            "error": str(error),
        }


def scan_pdf(
    path: str | Path,
    *,
    repository_root: str | Path,
    limits: StaticInspectionLimits | None = None,
    inspector: Callable[..., Any] = inspect_pdf,
    model_loader: Callable[[str | Path], tuple[Any, dict[str, Any]]] = load_verified_deployment_model,
) -> InferenceResult:
    """Statically inspect one local PDF and score it only after the strict gate passes."""
    static_result = inspector(path, limits=limits)
    gate = static_result.protocol_g_drop3constant_gate()
    payload = _base_result(static_result, gate)
    if not gate.passed:
        payload["prediction"]["error"] = "Inference refused because the 38-feature compatibility gate did not pass."
        return InferenceResult(**payload)
    try:
        features = _feature_frame(static_result.features)
        model, manifest = model_loader(repository_root)
        payload["model"].update({
            "name": manifest["model_id"],
            "artifact_sha256": manifest["artifact_sha256"],
            "training_dataset_sha256": manifest["training_dataset"]["sha256"],
            "feature_schema": manifest["feature_schema"],
            "threshold": manifest["threshold"],
        })
        probability = float(np.asarray(model.predict_proba(features), dtype=float)[0, 1])
        if not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
            raise DeploymentError("Deployment model returned a non-finite or out-of-range malicious probability")
        label, verdict = verdict_from_probability(probability, float(manifest["threshold"]))
        payload["prediction"].update({
            "available": True,
            "malicious_probability": probability,
            "predicted_label": label,
            "verdict": verdict,
        })
        payload["explanation"] = local_treeshap_explanation(model, features, probability)
    except Exception as error:
        payload["prediction"]["error"] = str(error)
    return InferenceResult(**payload)

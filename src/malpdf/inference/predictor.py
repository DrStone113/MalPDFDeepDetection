"""Strict gate, frozen-model prediction, and local native TreeSHAP utilities."""

from __future__ import annotations

import math
from copy import deepcopy
from itertools import islice
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
            "success": (bool(static_result.parser.get("success"))
                        and static_result.parser.get("structural_complete", True)
                        and not static_result.parser.get("resource_limit_reached", False)
                        and not any(issue.fatal for issue in static_result.errors)),
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


class StaticScanSession:
    """Reuse one verified frozen model, with strict gates and bounded batches.

    The artifact/manifest snapshot is verified when first needed. Create a new
    session to adopt another artifact. Sessions are not shared between threads.
    This serves the existing deployment XGBoost, not a retrained v3/v4 stack.
    """

    def __init__(self, *, repository_root, limits=None, inspector=inspect_pdf,
                 model_loader=load_verified_deployment_model, batch_size=128):
        if type(batch_size) is not int or not 1 <= batch_size <= 1024:
            raise ValueError("batch_size must be an integer between 1 and 1024")
        self.repository_root, self.limits = repository_root, limits
        self.inspector, self.model_loader, self.batch_size = inspector, model_loader, batch_size
        self._loaded = None
        self._load_error = None

    def _model(self):
        if self._load_error is not None:
            raise DeploymentError(self._load_error)
        if self._loaded is None:
            try:
                model, manifest = self.model_loader(self.repository_root)
                self._loaded = model, deepcopy(manifest)
            except Exception as error:
                self._load_error = str(error)
                raise
        return self._loaded

    def _batch(self, paths, explain):
        payloads, frames, positions = [], [], []
        for path in paths:
            static = self.inspector(path, limits=self.limits)
            gate = static.protocol_g_drop3constant_gate()
            payload = _base_result(static, gate)
            payloads.append(payload)
            if not payload["extraction"]["success"]:
                payload["prediction"]["error"] = "Inference refused because PDF parsing was incomplete or a fatal extraction error occurred."
                continue
            if not gate.passed:
                payload["prediction"]["error"] = "Inference refused because the 38-feature compatibility gate did not pass."
                continue
            try:
                frames.append(_feature_frame(static.features))
                positions.append(len(payloads) - 1)
            except Exception as error:
                payload["prediction"]["error"] = str(error)
        if frames:
            try:
                model, manifest = self._model()
                features = pd.concat(frames, ignore_index=True)
                raw = np.asarray(model.predict_proba(features), dtype=float)
                if (raw.shape != (len(frames), 2) or not np.isfinite(raw).all()
                        or np.any((raw < 0) | (raw > 1))
                        or not np.allclose(raw.sum(axis=1), 1, rtol=0, atol=1e-5)):
                    raise DeploymentError("Deployment model returned invalid binary probabilities or shape")
                for row, position in enumerate(positions):
                    payload = payloads[position]
                    probability = float(raw[row, 1])
                    label, verdict = verdict_from_probability(probability, float(manifest["threshold"]))
                    payload["model"].update({
                        "name": manifest["model_id"], "artifact_sha256": manifest["artifact_sha256"],
                        "training_dataset_sha256": manifest["training_dataset"]["sha256"],
                        "feature_schema": manifest["feature_schema"], "threshold": manifest["threshold"],
                    })
                    payload["prediction"].update({"available": True, "malicious_probability": probability,
                                                  "predicted_label": label, "verdict": verdict})
                    if explain:
                        payload["explanation"] = local_treeshap_explanation(model, features.iloc[[row]], probability)
                    else:
                        payload["explanation"]["reason"] = "not_requested"
            except Exception as error:
                for position in positions:
                    payloads[position]["prediction"].update({"available": False,
                        "malicious_probability": None, "predicted_label": None, "verdict": None,
                        "error": str(error)})
        return [InferenceResult(**payload) for payload in payloads]

    def iter_scan(self, paths, *, explain=False):
        """Stream results in input order; only compatible rows enter the model."""
        iterator = iter(paths)
        while batch := list(islice(iterator, self.batch_size)):
            yield from self._batch(batch, explain)

    def scan_many(self, paths, *, explain=False):
        """Collect streamed results for a caller-owned finite list of paths."""
        return list(self.iter_scan(paths, explain=explain))


def scan_pdf(
    path: str | Path,
    *,
    repository_root: str | Path,
    limits: StaticInspectionLimits | None = None,
    inspector: Callable[..., Any] = inspect_pdf,
    model_loader: Callable[[str | Path], tuple[Any, dict[str, Any]]] = load_verified_deployment_model,
    explain: bool = True,
) -> InferenceResult:
    """Inspect one PDF; explanations remain enabled for backward compatibility."""
    session = StaticScanSession(repository_root=repository_root, limits=limits,
                                inspector=inspector, model_loader=model_loader)
    return session.scan_many([path], explain=explain)[0]

from __future__ import annotations

from dataclasses import dataclass, field
import json
import logging
from pathlib import Path
from typing import Any

import numpy as np


@dataclass(frozen=True)
class MondrianConformalEvaluator:
    ncm_benign: tuple[float, ...]
    ncm_malicious: tuple[float, ...]
    alpha_benign: float = 0.01
    alpha_malicious: float = 0.01
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name, field_name, scores, alpha in (
            ("ben", "ncm_benign", self.ncm_benign, self.alpha_benign),
            ("mal", "ncm_malicious", self.ncm_malicious, self.alpha_malicious),
        ):
            values = np.asarray(scores, dtype=np.float64)
            if values.ndim != 1 or not np.all((0 <= values) & (values <= 1)):
                raise ValueError("invalid_conformal_calibration_scores")
            if not 0 < alpha < 1:
                raise ValueError("invalid_conformal_alpha")
            ordered = np.sort(values)
            ordered.setflags(write=False)
            object.__setattr__(self, f"_{name}_sorted", ordered)
            object.__setattr__(self, field_name, tuple(ordered.tolist()))

    @classmethod
    def fit_from_calibration(
        cls,
        probs: np.ndarray,
        labels: np.ndarray,
        *,
        alpha_benign: float = 0.01,
        alpha_malicious: float = 0.01,
        metadata: dict[str, Any] | None = None,
    ) -> MondrianConformalEvaluator:
        probs = np.asarray(probs, dtype=np.float64)
        labels = np.asarray(labels)
        if probs.ndim != 1 or probs.shape != labels.shape or not np.isin(labels, (0, 1)).all():
            raise ValueError("invalid_conformal_calibration_labels")
        benign, malicious = probs[labels == 0], probs[labels == 1]
        if not benign.size or not malicious.size:
            raise ValueError("conformal_calibration_requires_both_classes")
        return cls(tuple(benign), tuple(1.0 - malicious), alpha_benign, alpha_malicious, dict(metadata or {}))

    def p_values(self, prob_malicious: float) -> tuple[float, float]:
        p = float(np.clip(prob_malicious, 0.0, 1.0))
        if not np.isfinite(p):
            raise ValueError("invalid_conformal_probability")
        b, m = self._ben_sorted, self._mal_sorted
        c0 = len(b) - np.searchsorted(b, p, side="left")
        c1 = len(m) - np.searchsorted(m, 1.0 - p, side="left")
        return float((c0 + 1) / (len(b) + 1)), float((c1 + 1) / (len(m) + 1))

    def evaluate(
        self,
        prob_malicious: float,
        *,
        has_observed_threat: bool = False,
        graph_tab_disagreement: float | None = None,
    ) -> dict[str, Any]:
        p_benign, p_malicious = self.p_values(prob_malicious)
        prediction_set = []
        if p_benign > self.alpha_benign and not has_observed_threat:
            prediction_set.append("BENIGN")
        if p_malicious > self.alpha_malicious or has_observed_threat:
            prediction_set.append("MALICIOUS")
        state = {
            ("BENIGN",): "CERTIFIED_BENIGN",
            ("MALICIOUS",): "CERTIFIED_MALICIOUS",
            ("BENIGN", "MALICIOUS"): "AMBIGUOUS_BOTH",
            (): "DRIFT_OOD_EMPTY",
        }[tuple(prediction_set)]
        result = {
            "alpha_benign": round(float(self.alpha_benign), 6),
            "alpha_malicious": round(float(self.alpha_malicious), 6),
            "p_benign": round(p_benign, 6),
            "p_malicious": round(p_malicious, 6),
            "credibility": round(max(p_benign, p_malicious), 6),
            "confidence": round(1.0 - min(p_benign, p_malicious), 6),
            "prediction_set": prediction_set,
            "conformal_state": state,
            "reject_for_cdr": len(prediction_set) != 1,
            "calibration_n_benign": len(self._ben_sorted),
            "calibration_n_malicious": len(self._mal_sorted),
        }
        if graph_tab_disagreement is not None:
            result["graph_tab_disagreement"] = round(float(graph_tab_disagreement), 6)
        return result

    def to_json_file(self, path: Path | str) -> None:
        payload = {
            "ncm_benign": self._ben_sorted.tolist(),
            "ncm_malicious": self._mal_sorted.tolist(),
            "alpha_benign": self.alpha_benign,
            "alpha_malicious": self.alpha_malicious,
            "metadata": self.metadata,
        }
        Path(path).write_text(
            json.dumps(payload, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8"
        )

    @classmethod
    def from_json_file(cls, path: Path | str) -> MondrianConformalEvaluator:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        payload["ncm_benign"] = tuple(payload["ncm_benign"])
        payload["ncm_malicious"] = tuple(payload["ncm_malicious"])
        evaluator = cls(**payload)
        if not evaluator.ncm_benign or not evaluator.ncm_malicious or not isinstance(evaluator.metadata, dict):
            raise ValueError("invalid_conformal_calibration_file")
        return evaluator


def load_conformal_calibration(
    *config_dirs: Path, weights_sha256: str | None, temperature: float
) -> MondrianConformalEvaluator | None:
    if not weights_sha256:
        return None
    for directory in config_dirs:
        path = directory / "conformal_calibration_v3.json"
        try:
            if not path.is_file():
                continue
            evaluator = MondrianConformalEvaluator.from_json_file(path)
            if evaluator.metadata.get("weights_npz_sha256") == weights_sha256 and np.isclose(
                float(evaluator.metadata["temperature"]), temperature, rtol=0, atol=1e-9
            ):
                return evaluator
        except (AttributeError, KeyError, OSError, TypeError, ValueError) as exc:
            logging.getLogger(__name__).warning("Ignoring invalid conformal calibration %s: %s", path, exc)
    return None

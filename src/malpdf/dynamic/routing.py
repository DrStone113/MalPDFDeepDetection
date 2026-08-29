"""Configurable static-to-dynamic routing recommendations, never sandbox execution."""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


class RoutingPolicy(str, Enum):
    STATIC_ONLY = "STATIC_ONLY"
    ALWAYS_SANDBOX = "ALWAYS_SANDBOX"
    UNCERTAINTY_BAND = "UNCERTAINTY_BAND"
    STATIC_SUSPICIOUS = "STATIC_SUSPICIOUS"


@dataclass(frozen=True)
class RoutingPolicyConfig:
    """Project-controlled policy settings; no default interval is claimed optimal."""

    policy: RoutingPolicy = RoutingPolicy.STATIC_ONLY
    uncertainty_lower: float | None = None
    uncertainty_upper: float | None = None
    dynamic_on_prediction_unavailable: bool = True
    suspicious_verdicts: tuple[str, ...] = ("MALICIOUS",)

    def validate(self) -> None:
        if self.policy != RoutingPolicy.UNCERTAINTY_BAND:
            return
        if self.uncertainty_lower is None or self.uncertainty_upper is None:
            raise ValueError("UNCERTAINTY_BAND requires explicit lower and upper policy parameters")
        if not (0.0 <= self.uncertainty_lower <= self.uncertainty_upper <= 1.0):
            raise ValueError("Uncertainty-band bounds must satisfy 0 <= lower <= upper <= 1")

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "policy": self.policy.value, "suspicious_verdicts": list(self.suspicious_verdicts)}


@dataclass(frozen=True)
class RoutingResult:
    policy: RoutingPolicy
    static_probability: float | None
    static_verdict: str | None
    dynamic_required: bool
    reason: str
    policy_parameters: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy": self.policy.value,
            "static_probability": self.static_probability,
            "static_verdict": self.static_verdict,
            "dynamic_required": self.dynamic_required,
            "reason": self.reason,
            "policy_parameters": self.policy_parameters,
        }


@dataclass(frozen=True)
class EnsembleRoutingContext:
    """Safe metadata for a future sandbox handoff, never sample content.

    The fields are scalar model/routing facts only.  This object deliberately
    excludes PDF bytes, JavaScript, attachments, URLs, and dynamic values.
    """

    static_model_version: str
    xgb_probability: float | None
    ft_probability: float | None
    ensemble_probability: float | None
    model_disagreement: bool | None
    uncertainty_score: float | None
    routing_reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def route_static_result(
    *,
    prediction_available: bool,
    malicious_probability: float | None,
    static_verdict: str | None,
    extraction_warnings: tuple[str, ...] | list[str] = (),
    config: RoutingPolicyConfig = RoutingPolicyConfig(),
) -> RoutingResult:
    """Return a recommendation only; calling it cannot perform dynamic analysis."""
    config.validate()
    params = config.to_dict()
    if not prediction_available or malicious_probability is None:
        # Extraction/schema failure is outside probabilistic policy selection:
        # no static verdict is emitted, so a future dynamic stage is recommended
        # whenever the explicit safety flag remains enabled.
        required = config.dynamic_on_prediction_unavailable
        return RoutingResult(config.policy, None, static_verdict, required, "STATIC_EXTRACTION_INCOMPLETE", params)
    if not isinstance(malicious_probability, (int, float)) or isinstance(malicious_probability, bool) or not math.isfinite(float(malicious_probability)) or not 0.0 <= float(malicious_probability) <= 1.0:
        return RoutingResult(config.policy, None, static_verdict, False, "STATIC_EXTRACTION_INCOMPLETE", params)
    probability = float(malicious_probability)
    if config.policy == RoutingPolicy.STATIC_ONLY:
        return RoutingResult(config.policy, probability, static_verdict, False, "POLICY_STATIC_ONLY", params)
    if config.policy == RoutingPolicy.ALWAYS_SANDBOX:
        return RoutingResult(config.policy, probability, static_verdict, True, "POLICY_ALWAYS_DYNAMIC", params)
    if config.policy == RoutingPolicy.UNCERTAINTY_BAND:
        required = config.uncertainty_lower <= probability <= config.uncertainty_upper  # validated above
        return RoutingResult(config.policy, probability, static_verdict, required, "STATIC_UNCERTAIN" if required else "STATIC_CONFIDENT", params)
    suspicious = static_verdict in config.suspicious_verdicts or bool(extraction_warnings)
    return RoutingResult(config.policy, probability, static_verdict, suspicious, "STATIC_SUSPICIOUS" if suspicious else "STATIC_CONFIDENT", params)

"""Structured, JSON-safe results and model-compatibility gates."""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from numbers import Real
from typing import Any

STATIC_DIAGNOSTIC_SCHEMA_VERSION = "static-diagnostics-v2"


class FeatureStatus(StrEnum):
    """Evidence level for the mapping from an extracted value to a RIT feature."""

    IMPLEMENTED_VERIFIED_SEMANTICS = "IMPLEMENTED_VERIFIED_SEMANTICS"
    IMPLEMENTED_PROVISIONAL = "IMPLEMENTED_PROVISIONAL"
    UNSUPPORTED = "UNSUPPORTED"
    AMBIGUOUS = "AMBIGUOUS"


@dataclass(frozen=True)
class StructuredExtractionIssue:
    """A bounded, machine-readable parser warning or extraction error."""

    code: str
    message: str
    fatal: bool = False


@dataclass(frozen=True)
class FeatureCompatibilityGate:
    """Decision on whether a result can safely be passed to a model schema."""

    model_schema: str
    expected_feature_count: int
    compatible_feature_count: int
    passed: bool
    blocking_features: tuple[dict[str, str], ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class StaticInspectionResult:
    """Result of a read-only static inspection; no prediction is included."""

    input: dict[str, Any]
    parser: dict[str, Any]
    features: dict[str, int | float | None]
    compatibility: dict[str, FeatureStatus]
    diagnostics: dict[str, Any]
    errors: list[StructuredExtractionIssue] = field(default_factory=list)
    warnings: list[StructuredExtractionIssue] = field(default_factory=list)
    safety: dict[str, bool] = field(
        default_factory=lambda: {
            "active_content_executed": False,
            "embedded_payload_executed": False,
            "external_uri_followed": False,
            "external_application_invoked": False,
        }
    )

    def feature_coverage(self) -> dict[str, int]:
        """Count statuses across the complete fixed RIT schema."""
        return {
            status.value: sum(value == status for value in self.compatibility.values())
            for status in FeatureStatus
        }

    def protocol_g_drop3constant_gate(self) -> FeatureCompatibilityGate:
        """Require all 38 exact-semantics numeric features; never impute values."""
        # Local import avoids a schema/result import cycle.
        from malpdf.static.schema import PROTOCOL_G_REQUIRED_FEATURES

        blockers: list[dict[str, str]] = []
        compatible = 0
        for feature in PROTOCOL_G_REQUIRED_FEATURES:
            value = self.features.get(feature)
            status = self.compatibility.get(feature)
            if feature not in self.features:
                blockers.append({"feature": feature, "reason": "missing feature"})
                continue
            if status != FeatureStatus.IMPLEMENTED_VERIFIED_SEMANTICS:
                status_text = "missing status" if status is None else status.value
                blockers.append({"feature": feature, "reason": f"status is {status_text}"})
                continue
            if not isinstance(value, Real) or isinstance(value, bool):
                blockers.append({"feature": feature, "reason": "value is missing or non-numeric"})
                continue
            if not math.isfinite(float(value)):
                blockers.append({"feature": feature, "reason": "value is non-finite"})
                continue
            compatible += 1
        return FeatureCompatibilityGate(
            model_schema="Protocol G G-drop3constant",
            expected_feature_count=len(PROTOCOL_G_REQUIRED_FEATURES),
            compatible_feature_count=compatible,
            passed=not blockers,
            blocking_features=tuple(blockers),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return deterministic JSON-ready content without PDF payloads or URLs."""
        return {
            "diagnostic_schema_version": STATIC_DIAGNOSTIC_SCHEMA_VERSION,
            "input": self.input,
            "parser": self.parser,
            "features": self.features,
            "compatibility": {name: status.value for name, status in self.compatibility.items()},
            "diagnostics": self.diagnostics,
            "errors": [asdict(issue) for issue in self.errors],
            "warnings": [asdict(issue) for issue in self.warnings],
            "safety": self.safety,
            "feature_coverage": self.feature_coverage(),
            "model_compatibility": {
                "protocol_g_drop3constant": self.protocol_g_drop3constant_gate().to_dict()
            },
        }

"""JSON-safe results for offline dynamic-report normalization and routing."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any

from malpdf.dynamic.schema import DYNAMIC_SCHEMA_VERSION


@dataclass(frozen=True)
class DynamicWarning:
    """A non-fatal normalization warning without embedding raw report content."""

    code: str
    message: str
    source: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class NormalizedBehavioralReport:
    """Compact normalized report; raw payloads, commands, and host data are omitted."""

    provider: str
    analysis_id: str | None
    status: str
    duration_seconds: float | None
    section_availability: dict[str, bool]
    observations: dict[str, Any]
    warnings: tuple[DynamicWarning, ...] = ()
    schema_version: str = DYNAMIC_SCHEMA_VERSION
    adapter_version: str = "unknown"
    raw_report_type: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "adapter_version": self.adapter_version,
            "raw_report_type": self.raw_report_type,
            "analysis": {
                "provider": self.provider,
                "analysis_id": self.analysis_id,
                "status": self.status,
                "duration_seconds": self.duration_seconds,
            },
            "section_availability": dict(sorted(self.section_availability.items())),
            "observations": self.observations,
            "warnings": [warning.to_dict() for warning in self.warnings],
        }

    def to_json(self) -> str:
        """Serialize deterministically for auditable offline parser output."""
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


@dataclass(frozen=True)
class BehavioralFeatureSet:
    """Feature values and their report-path traceability; values may be unavailable."""

    values: dict[str, int | bool | None]
    sources: dict[str, str]
    warnings: tuple[DynamicWarning, ...] = ()
    schema_version: str = DYNAMIC_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "values": self.values,
            "sources": self.sources,
            "warnings": [warning.to_dict() for warning in self.warnings],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


@dataclass(frozen=True)
class HybridAnalysisResult:
    """Future-compatible two-stage result with no unvalidated hybrid decision."""

    static: dict[str, Any]
    routing: dict[str, Any]
    dynamic_available: bool
    behavioral_features: BehavioralFeatureSet | None = None
    dynamic_warnings: tuple[DynamicWarning, ...] = ()
    hybrid_available: bool = False
    hybrid_verdict: str | None = None
    hybrid_method: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "static": self.static,
            "routing": self.routing,
            "dynamic": {
                "available": self.dynamic_available,
                "behavioral_features": self.behavioral_features.to_dict() if self.behavioral_features else None,
                "warnings": [warning.to_dict() for warning in self.dynamic_warnings],
            },
            "hybrid": {
                "available": self.hybrid_available,
                "verdict": self.hybrid_verdict,
                "method": self.hybrid_method,
            },
        }


def unavailable_hybrid_result(*, static: dict[str, Any], routing: dict[str, Any]) -> HybridAnalysisResult:
    """Make the intentionally unavailable hybrid state explicit."""
    return HybridAnalysisResult(static=static, routing=routing, dynamic_available=False)

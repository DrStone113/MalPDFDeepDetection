"""Structured, JSON-safe results for static deployment inference."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class LocalContribution:
    """One feature's signed contribution to the malicious raw model margin."""

    feature: str
    extracted_value: int | float
    contribution: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class InferenceResult:
    """No-payload result emitted by ``malpdf scan`` for one untrusted file."""

    input: dict[str, Any]
    extraction: dict[str, Any]
    compatibility: dict[str, Any]
    model: dict[str, Any]
    prediction: dict[str, Any]
    explanation: dict[str, Any]
    safety: dict[str, bool]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

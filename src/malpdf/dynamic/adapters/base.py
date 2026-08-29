"""Offline-only sandbox adapter and future client interfaces."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any

from malpdf.dynamic.result import NormalizedBehavioralReport


class SandboxReportAdapter(ABC):
    """Normalize an already-produced sandbox report without network access."""

    provider: str
    adapter_version: str

    @abstractmethod
    def normalize(self, report: Mapping[str, Any]) -> NormalizedBehavioralReport:
        """Treat ``report`` solely as inert JSON data."""


class SandboxClient(ABC):
    """Explicitly non-operational placeholder for a future isolated environment."""

    def submit(self, *_: Any, **__: Any) -> None:
        raise NotImplementedError("Live sandbox submission is intentionally not implemented.")

    def status(self, *_: Any, **__: Any) -> None:
        raise NotImplementedError("Live sandbox status queries are intentionally not implemented.")

    def fetch_report(self, *_: Any, **__: Any) -> None:
        raise NotImplementedError("Live sandbox report retrieval is intentionally not implemented.")

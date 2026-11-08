from __future__ import annotations

from typing import Any

from malpdf.scanner.forensic import ForensicAttributionEngine
from malpdf.scanner.ingestion import InstantPDFIngestion

__all__ = [
    "MalPDFScannerEngine",
    "ScanResult",
    "ForensicAttributionEngine",
    "InstantPDFIngestion",
]


def __getattr__(name: str) -> Any:
    if name in ("MalPDFScannerEngine", "ScanResult"):
        from malpdf.scanner import engine

        return getattr(engine, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

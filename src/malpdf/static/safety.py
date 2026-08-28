"""Resource limits for inert static PDF inspection."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class StaticInspectionLimits:
    """Bound parsing work before an untrusted PDF is inspected.

    Limits apply to this local, read-only extractor.  A limit produces a
    structured result; it never causes an attempt to bypass the limit.
    """

    max_file_size_bytes: int = 50 * 1024 * 1024
    max_pages: int = 1_000
    max_objects: int = 10_000
    max_recursion_depth: int = 100
    max_warning_length: int = 500

    def __post_init__(self) -> None:
        for name, value in self.__dict__.items():
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")

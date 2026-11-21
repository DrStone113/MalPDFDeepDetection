"""Bounded escaped-name counting on real PDF bytes; no parsing or rendering."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re

from malpdf.data.manifest_validator import validate_sha256
from malpdf.static.safety import read_bounded_bytes

PDF_NAME = re.compile(rb"/[^\x00\x09\x0a\x0c\x0d ()<>\[\]{}/%]+")
HEX_ESCAPE = re.compile(rb"#[0-9a-fA-F]{2}")
ESCAPED_PDF_NAME = re.compile(
    rb"/[^\x00\x09\x0a\x0c\x0d ()<>\[\]{}/%]*(?:#[0-9a-fA-F]{2})[^\x00\x09\x0a\x0c\x0d ()<>\[\]{}/%]*"
)
MAX_PDF_BYTES = 10 * 1024 * 1024


def count_escaped_pdf_names(data: bytes, *, max_bytes: int = MAX_PDF_BYTES) -> int:
    """Count each raw name-shaped token with a #HH escape once.

    This is a lexical byte measurement, including token-shaped occurrences in
    strings/comments/stream bytes. It neither inflates streams nor claims that
    tokens are active PDF objects or that legal name escapes prove maliciousness.
    """
    if max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    if not isinstance(data, bytes) or not 5 <= len(data) <= max_bytes:
        limit_mb = max_bytes // (1024 * 1024)
        raise ValueError(f"PDF bytes must be nonempty and within the {limit_mb} MiB cap")
    if not data[:1024].lstrip().startswith(b"%PDF-"):
        raise ValueError("Measured source must have a static PDF header")
    if b"#" not in data:
        return 0
    return sum(1 for _ in ESCAPED_PDF_NAME.finditer(data))


def measure_pdf_obfuscation(path: Path, *, boundary: Path, expected_sha256: str) -> dict:
    expected = validate_sha256(expected_sha256)
    data = read_bounded_bytes(path, boundary=boundary, max_bytes=MAX_PDF_BYTES)
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("PDF bytes differ from the locked source SHA-256")
    return {"ObfuscationCount": count_escaped_pdf_names(data), "pdf_bytes": len(data),
            "measurement": "raw_escaped_pdf_name_token_count_v1", "raw_pdf_sha256_verified": True}

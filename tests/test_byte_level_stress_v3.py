"""Unit tests for real byte-level stress scoring and incremental PDF construction."""

from __future__ import annotations

import numpy as np

from scripts.lab.run_byte_level_stress_v3 import append_incremental_pdf_bytes


def test_append_incremental_pdf_bytes_builds_valid_prev_xref() -> None:
    sample = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \n"
        b"trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n58\n%%EOF\n"
    )
    updated = append_incremental_pdf_bytes(sample, "Test Producer")
    assert updated.startswith(sample)
    assert b"/Prev 58" in updated
    assert b"/Size 3" in updated
    assert b"2 0 obj" in updated
    assert updated.count(b"startxref") == 2
    assert updated.count(b"%%EOF") == 2

"""Top-level safe static PDF analyzer.

This module has no model dependency.  It reads a local path as bytes, performs
bounded lexical and structural inspection, and reports a RIT-schema-oriented
feature vector plus compatibility evidence.  It never executes PDF content.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from malpdf.static.pdf_parser import inspect_pdf_structure, parse_pdf_header, parser_library_metadata
from malpdf.static.raw_scan import scan_raw_pdf_tokens
from malpdf.static.rit_reference import inspect_rit_reference_features, reference_parser_metadata
from malpdf.static.result import StaticInspectionResult, StructuredExtractionIssue
from malpdf.static.safety import StaticInspectionLimits, read_bounded_bytes
from malpdf.static.schema import RIT_FEATURES, implementation_statuses
from malpdf.static.profiling import stage


class StaticPDFAnalysisError(ValueError):
    """Raised only for invalid analyzer configuration, never for input PDFs."""


class StaticPDFAnalyzer:
    """Perform bounded static inspection of a local, untrusted PDF path."""

    def __init__(self, limits: StaticInspectionLimits | None = None) -> None:
        self.limits = StaticInspectionLimits() if limits is None else limits

    def _empty_result(self, input_path=None):
        statuses = dict(implementation_statuses())
        features: dict[str, int | float | None] = {feature: None for feature in RIT_FEATURES}
        input_info = {
            "path": None if input_path is None else str(input_path),
            "extension": None if input_path is None else input_path.suffix.lower(),
            "size_bytes": None,
            "sha256": None,
        }
        parser = {
            **parser_library_metadata(),
            "success": False,
            "encrypted": None,
            "rit_reference_extractor": reference_parser_metadata(),
        }
        diagnostics: dict[str, object] = {"raw_token_counts": {}, "parsed_structural_indicators": {}}
        errors: list[StructuredExtractionIssue] = []
        result = StaticInspectionResult(
            input=input_info,
            parser=parser,
            features=features,
            compatibility=statuses,
            diagnostics=diagnostics,
            errors=errors,
        )
        return result

    def inspect(self, path: str | Path, *, snapshot: bytes | None = None,
                snapshot_sha256: str | None = None, timings=None) -> StaticInspectionResult:
        """Return partial structured data even for malformed or non-PDF files."""
        input_path = Path(path)
        result = self._empty_result(input_path)
        errors, input_info = result.errors, result.input
        if not input_path.is_file():
            errors.append(StructuredExtractionIssue("file_not_found", "Input path is not a regular file.", fatal=True))
            return result

        try:
            size = input_path.stat().st_size
            input_info["size_bytes"] = int(size)
        except OSError as error:
            errors.append(StructuredExtractionIssue("file_read_error", str(error)[: self.limits.max_warning_length], fatal=True))
            return result

        if size > self.limits.max_file_size_bytes:
            errors.append(
                StructuredExtractionIssue(
                    "file_size_limit",
                    f"File has {size} bytes; configured maximum is {self.limits.max_file_size_bytes} bytes.",
                    fatal=True,
                )
            )
            return result

        try:
            with stage(timings, "read_hash"):
                data = (read_bounded_bytes(input_path, boundary=input_path.absolute().parent,
                                          max_bytes=self.limits.max_file_size_bytes)
                        if snapshot is None else snapshot)
                if not isinstance(data, bytes) or len(data) > self.limits.max_file_size_bytes:
                    raise ValueError("Invalid bounded snapshot")
                digest = hashlib.sha256(data).hexdigest()
                if snapshot_sha256 is not None and digest != snapshot_sha256:
                    raise ValueError("Snapshot checksum mismatch")
        except (OSError, ValueError) as error:
            errors.append(StructuredExtractionIssue("file_read_error", str(error)[: self.limits.max_warning_length], fatal=True))
            return result

        size = len(data)
        input_info["size_bytes"] = size
        input_info["sha256"] = digest
        return self._inspect_verified_bytes(data, result, timings)

    def inspect_snapshot(self, data: bytes, *, expected_sha256=None, timings=None) -> StaticInspectionResult:
        """Inspect an in-memory child artifact without creating a temporary PDF.

        Production callers must use a disposable resource-limited worker. This
        entry point verifies its own input; path entry-point checks stay intact.
        """
        result = self._empty_result()
        if not isinstance(data, bytes):
            result.errors.append(StructuredExtractionIssue('invalid_snapshot', 'Snapshot must be bytes.', fatal=True))
            return result
        if len(data) > self.limits.max_file_size_bytes:
            result.errors.append(StructuredExtractionIssue('file_size_limit', 'Snapshot exceeds the byte cap.', fatal=True))
            return result
        digest = hashlib.sha256(data).hexdigest()
        result.input.update(size_bytes=len(data), sha256=digest)
        if expected_sha256 is not None and digest != expected_sha256:
            result.errors.append(StructuredExtractionIssue('snapshot_checksum_mismatch', 'Snapshot checksum mismatch.', fatal=True))
            return result
        return self._inspect_verified_bytes(data, result, timings)

    def _inspect_verified_bytes(self, data, result, timings):
        size = len(data)
        input_info, features, parser = result.input, result.features, result.parser
        diagnostics, errors = result.diagnostics, result.errors

        header = parse_pdf_header(data)
        diagnostics["file_header"] = header
        with stage(timings, "raw_scan"):
            raw_counts = scan_raw_pdf_tokens(data)
        diagnostics["raw_token_counts"] = raw_counts
        features.update(raw_counts)
        diagnostics["pdfsize"] = {"size_bytes": int(size), "canonical_conversion": "int(size_bytes / 1000)"}

        if not header["pdf_header_present"]:
            errors.append(StructuredExtractionIssue("not_pdf", "A valid %PDF- header was not found in the first 32 bytes.", fatal=True))
            return result

        with stage(timings, "parse_pdf"):
            parsed = inspect_pdf_structure(data, self.limits)
            reference = inspect_rit_reference_features(data, int(size), self.limits)
        parser.update(
            {
                "success": parsed.success,
                "structural_complete": parsed.structural_complete,
                "encrypted": parsed.encrypted,
                "resource_limit_reached": parsed.resource_limit_reached,
                "diagnostics": parsed.diagnostics,
                "header_version_string": header["header_version_string"],
                "header_version_numeric": header["header_version_numeric"],
            }
        )
        diagnostics["parsed_structural_indicators"] = parsed.structural_indicator_counts
        diagnostics["structural_coverage"] = {
            "complete": parsed.structural_complete,
            "observed_indicators": parsed.observed_structural_indicator_counts,
            "scope": "pypdf trailer-reachable objects; observed counts are lower bounds when incomplete",
        }
        diagnostics["pypdf_metadata_diagnostics"] = {"entry_count": parsed.metadata_entry_count, "content_redacted": True}
        diagnostics["pypdf_images_diagnostics"] = {"measurement": "unique parser-derived /Image XObjects; image bytes were not exported"}
        diagnostics["rit_reference_diagnostics"] = reference.diagnostics
        errors.extend(parsed.errors)
        result.warnings.extend(parsed.warnings)
        errors.extend(reference.errors)
        result.warnings.extend(reference.warnings)

        features.update(reference.features)
        # pypdf values remain separate diagnostics. Canonical values above use
        # the published PDFMalExtract/PyMuPDF methods and their explicit
        # sentinels; absent values are never imputed.
        return result


def inspect_pdf(path: str | Path, *, limits: StaticInspectionLimits | None = None) -> StaticInspectionResult:
    """Convenience wrapper for one safe static inspection."""
    return StaticPDFAnalyzer(limits=limits).inspect(path)

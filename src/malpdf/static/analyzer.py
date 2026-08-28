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
from malpdf.static.safety import StaticInspectionLimits
from malpdf.static.schema import RIT_FEATURES, implementation_statuses


class StaticPDFAnalysisError(ValueError):
    """Raised only for invalid analyzer configuration, never for input PDFs."""


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class StaticPDFAnalyzer:
    """Perform bounded static inspection of a local, untrusted PDF path."""

    def __init__(self, limits: StaticInspectionLimits | None = None) -> None:
        self.limits = StaticInspectionLimits() if limits is None else limits

    def inspect(self, path: str | Path) -> StaticInspectionResult:
        """Return partial structured data even for malformed or non-PDF files."""
        input_path = Path(path)
        statuses = dict(implementation_statuses())
        features: dict[str, int | float | None] = {feature: None for feature in RIT_FEATURES}
        input_info = {
            "path": str(input_path),
            "extension": input_path.suffix.lower(),
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
        if not input_path.is_file():
            errors.append(StructuredExtractionIssue("file_not_found", "Input path is not a regular file.", fatal=True))
            return result

        try:
            size = input_path.stat().st_size
            input_info["size_bytes"] = int(size)
            input_info["sha256"] = _sha256_path(input_path)
            with input_path.open("rb") as handle:
                initial = handle.read(16)
        except OSError as error:
            errors.append(StructuredExtractionIssue("file_read_error", str(error)[: self.limits.max_warning_length], fatal=True))
            return result

        diagnostics["file_header"] = parse_pdf_header(initial)
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
            data = input_path.read_bytes()
        except OSError as error:
            errors.append(StructuredExtractionIssue("file_read_error", str(error)[: self.limits.max_warning_length], fatal=True))
            return result

        header = parse_pdf_header(data)
        diagnostics["file_header"] = header
        raw_counts = scan_raw_pdf_tokens(data)
        diagnostics["raw_token_counts"] = raw_counts
        features.update(raw_counts)
        diagnostics["pdfsize"] = {"size_bytes": int(size), "canonical_conversion": "int(size_bytes / 1000)"}

        if not header["pdf_header_present"]:
            errors.append(StructuredExtractionIssue("not_pdf", "A valid %PDF- header was not found in the first 32 bytes.", fatal=True))
            return result

        parsed = inspect_pdf_structure(data, self.limits)
        reference = inspect_rit_reference_features(data, int(size), self.limits)
        parser.update(
            {
                "success": parsed.success,
                "encrypted": parsed.encrypted,
                "resource_limit_reached": parsed.resource_limit_reached,
                "header_version_string": header["header_version_string"],
                "header_version_numeric": header["header_version_numeric"],
            }
        )
        diagnostics["parsed_structural_indicators"] = parsed.structural_indicator_counts
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

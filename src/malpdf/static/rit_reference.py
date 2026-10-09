"""Safe reimplementation of the published PDFMalExtract metadata contract.

The canonical methods in this module follow the publicly released
PDFMalExtract v0.1 implementation at the immutable Git revision below.  It
uses PyMuPDF 1.26.7, the version pinned by that upstream repository.  All
operations are in-memory, read-only inspection: no JavaScript, URI, attachment,
or external program is invoked.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pymupdf

from malpdf.static.result import StructuredExtractionIssue
from malpdf.static.safety import StaticInspectionLimits

PDFMALEXTRACT_SOURCE_URL = "https://github.com/Mo-Alani/PDFMalExtract"
PDFMALEXTRACT_SOURCE_COMMIT = "1aaba0896ae395ddadbf1010ab9e887eedc38ea1"
PDFMALEXTRACT_SOURCE_PATH = "PDFMalExtract.py"
PDFMALEXTRACT_PYMUPDF_VERSION = "1.26.7"
TEXT_THRESHOLD_CHARACTERS = 50


@dataclass
class RITReferenceInspection:
    """Canonical metadata values and bounded diagnostics from PyMuPDF."""

    features: dict[str, int | float | None] = field(default_factory=dict)
    success: bool = False
    warnings: list[StructuredExtractionIssue] = field(default_factory=list)
    errors: list[StructuredExtractionIssue] = field(default_factory=list)
    diagnostics: dict[str, Any] = field(default_factory=dict)


def _bounded(message: object, limits: StaticInspectionLimits) -> str:
    return " ".join(str(message).split())[: limits.max_warning_length]


def reference_parser_metadata() -> dict[str, str]:
    """Expose source and library provenance without processing a PDF."""
    return {
        "library": "PyMuPDF",
        "version": str(pymupdf.__version__),
        "required_version": PDFMALEXTRACT_PYMUPDF_VERSION,
        "source_url": PDFMALEXTRACT_SOURCE_URL,
        "source_commit": PDFMALEXTRACT_SOURCE_COMMIT,
        "source_path": PDFMALEXTRACT_SOURCE_PATH,
        "mode": "in-memory read-only static extraction",
    }


def _reference_version_matches() -> bool:
    return str(pymupdf.__version__) == PDFMALEXTRACT_PYMUPDF_VERSION


def inspect_rit_reference_features(data: bytes, size_bytes: int, limits: StaticInspectionLimits) -> RITReferenceInspection:
    """Extract the ten RIT metadata features with the released tool's methods.

    A value remains unavailable if the released method cannot produce it.  The
    only negative sentinels are the exact PDFMalExtract contracts: ``images=-1``
    for image-loop failure and ``contains_text=-1`` for outer text/attachment
    loop failure.  Parser failure is always represented separately as an error.
    """
    result = RITReferenceInspection(
        features={
            "pdfsize": None,
            "metadata size": None,
            "pages": None,
            "xref length": None,
            "title length": None,
            "isEncrypted": None,
            "embedded files": None,
            "images": None,
            "contains_text": None,
            "pdf_ver": None,
        },
        diagnostics={
            "pdfmalextract_text_threshold_characters": TEXT_THRESHOLD_CHARACTERS,
            "pdfmalextract_text_threshold_comparison": "strictly greater than",
            "page_text_extraction_error_count": 0,
            "metadata_content_redacted": True,
        },
    )
    if not _reference_version_matches():
        result.errors.append(
            StructuredExtractionIssue(
                "reference_parser_version_mismatch",
                f"PyMuPDF {pymupdf.__version__} does not match the pinned PDFMalExtract version {PDFMALEXTRACT_PYMUPDF_VERSION}.",
                fatal=True,
            )
        )
        return result

    # PDFMalExtract uses int(os.path.getsize(file) / 1000): decimal kilobytes
    # truncated toward zero.  File length is non-negative, so // is equivalent.
    result.features["pdfsize"] = int(size_bytes // 1000)
    document = None
    try:
        document = pymupdf.open(stream=data, filetype="pdf")
    except Exception as error:
        result.errors.append(StructuredExtractionIssue("reference_parser_failure", _bounded(error, limits)))
        return result

    try:
        repair_state = getattr(document, "is_repaired", None)
        result.diagnostics["parser_repaired"] = None if repair_state is None else bool(repair_state)
        try:
            metadata = document.metadata
        except Exception as error:
            result.errors.append(StructuredExtractionIssue("reference_metadata_unavailable", _bounded(error, limits)))
            return result
        if not metadata:
            result.errors.append(
                StructuredExtractionIssue("reference_metadata_unavailable", "PDFMalExtract requires non-empty PyMuPDF metadata; no canonical metadata features were produced.")
            )
            return result

        # This intentionally measures the UTF-8 byte length of Python's metadata
        # dictionary representation, exactly as the published implementation.
        result.features["metadata size"] = len(str(metadata).encode("utf-8"))
        result.diagnostics["metadata_entry_count"] = len(metadata)
        result.diagnostics["metadata_representation"] = "utf-8 bytes of str(PyMuPDF Document.metadata)"

        try:
            result.features["pdf_ver"] = float(metadata["format"][4:7])
        except Exception as error:
            result.warnings.append(StructuredExtractionIssue("reference_pdf_version_unavailable", _bounded(error, limits)))

        try:
            result.features["isEncrypted"] = int(bool(metadata["encryption"]))
        except Exception as error:
            result.warnings.append(StructuredExtractionIssue("reference_encryption_unavailable", _bounded(error, limits)))

        title = metadata.get("title")
        result.features["title length"] = len(title) if title else 0

        try:
            result.features["xref length"] = int(document.xref_length())
            if result.features["xref length"] > limits.max_objects:
                result.errors.append(StructuredExtractionIssue("reference_object_limit", "PDF xref exceeds the static object cap", fatal=True))
                return result
        except Exception as error:
            result.warnings.append(StructuredExtractionIssue("reference_xref_length_unavailable", _bounded(error, limits)))

        try:
            page_count = int(document.page_count)
            if page_count > limits.max_pages:
                result.warnings.append(
                    StructuredExtractionIssue("reference_page_limit", f"PDF has {page_count} pages; configured maximum is {limits.max_pages}.")
                )
            else:
                result.features["pages"] = page_count
        except Exception as error:
            result.warnings.append(StructuredExtractionIssue("reference_page_count_unavailable", _bounded(error, limits)))

        found = 0
        text = ""
        embedded_count: int | None = None
        try:
            page_total = len(document)
            if page_total > limits.max_pages:
                raise RuntimeError(f"PDF has {page_total} pages; configured maximum is {limits.max_pages}")
            for page_index in range(page_total):
                try:
                    text += document[page_index].get_text()
                    if len(text) > TEXT_THRESHOLD_CHARACTERS:
                        found = 1
                        break
                except Exception:
                    result.diagnostics["page_text_extraction_error_count"] += 1
            embedded_count = int(document.embfile_count())
        except Exception as error:
            # These are source-defined feature values, not generic replacements:
            # PDFMalExtract assigns -1 / 0 in this same outer failure path.
            found = -1
            embedded_count = 0
            result.warnings.append(StructuredExtractionIssue("reference_text_or_attachment_failure", _bounded(error, limits)))
        result.features["contains_text"] = found
        result.features["embedded files"] = embedded_count

        image_count = 0
        try:
            page_total = len(document)
            if page_total > limits.max_pages:
                raise RuntimeError(f"PDF has {page_total} pages; configured maximum is {limits.max_pages}")
            for page_index in range(page_total):
                image_count += len(document[page_index].get_images())
        except Exception as error:
            # PDFMalExtract explicitly uses -1 for this image-extraction state.
            image_count = -1
            result.warnings.append(StructuredExtractionIssue("reference_image_count_failure", _bounded(error, limits)))
        result.features["images"] = image_count
        result.success = True
        return result
    finally:
        if document is not None:
            document.close()

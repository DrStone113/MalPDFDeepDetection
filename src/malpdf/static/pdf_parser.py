"""Read-only structural PDF parsing using pypdf.

No parser callback is registered and no content is evaluated.  The parser is
used solely for dictionaries, page trees, metadata lengths, and text/image
diagnostics.  Parser-derived values are deliberately not substituted for raw
RIT string-occurrence features.
"""

from __future__ import annotations

import io
import re
import warnings
from dataclasses import dataclass, field
from typing import Any

import pypdf
from pypdf import PdfReader
from pypdf.errors import PdfReadError
from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject

from malpdf.static.result import StructuredExtractionIssue
from malpdf.static.safety import StaticInspectionLimits

_STRUCTURAL_NAMES = frozenset(
    {
        "/JavaScript", "/JS", "/URI", "/AA", "/OpenAction", "/Launch",
        "/EmbeddedFile", "/Acroform", "/AcroForm", "/XFA", "/JBIG2Decode", "/RichMedia",
    }
)


def _indicator_name(name: str) -> str:
    # Keep the old diagnostic key while recognizing the standard PDF spelling.
    return "Acroform" if name == "/AcroForm" else name.removeprefix("/")


@dataclass
class ParserInspection:
    """Parser-only values; every unavailable value remains explicit ``None``."""

    success: bool = False
    encrypted: bool | None = None
    page_count: int | None = None
    title_length: int | None = None
    metadata_entry_count: int | None = None
    image_count: int | None = None
    contains_text: int | None = None
    embedded_file_count: int | None = None
    structural_indicator_counts: dict[str, int | None] = field(default_factory=dict)
    observed_structural_indicator_counts: dict[str, int] = field(default_factory=dict)
    structural_complete: bool = False
    warnings: list[StructuredExtractionIssue] = field(default_factory=list)
    errors: list[StructuredExtractionIssue] = field(default_factory=list)
    resource_limit_reached: bool = False


def _bounded_message(message: str, limits: StaticInspectionLimits) -> str:
    cleaned = " ".join(str(message).split())
    return cleaned[: limits.max_warning_length]


class _StructureWalker:
    """Cycle-safe, bounded dictionary traversal without stream decoding."""

    def __init__(self, limits: StaticInspectionLimits) -> None:
        self.limits = limits
        self.visited_indirect: set[tuple[int, int]] = set()
        self.object_count = 0
        self.limit_reached = False
        self.failed_references = 0
        self.indicators = {_indicator_name(name): 0 for name in _STRUCTURAL_NAMES}
        self.embedded_file_count = 0

    def walk(self, value: Any, depth: int = 0) -> None:
        if self.limit_reached:
            return
        if depth > self.limits.max_recursion_depth:
            self.limit_reached = True
            return
        resolving: set[tuple[int, int]] = set()
        while isinstance(value, IndirectObject):
            identifier = (int(value.idnum), int(value.generation))
            if identifier in resolving:
                self.failed_references += 1
                return
            if identifier in self.visited_indirect:
                return
            if len(resolving) >= self.limits.max_recursion_depth:
                self.limit_reached = True
                return
            resolving.add(identifier)
            self.visited_indirect.add(identifier)
            try:
                value = value.get_object()
                if value is None:
                    self.failed_references += 1
                    return
            except Exception:
                self.failed_references += 1
                return
        if isinstance(value, DictionaryObject):
            self.object_count += 1
            if self.object_count > self.limits.max_objects:
                self.limit_reached = True
                return
            keys = {str(key) for key in value.keys()}
            for key in keys.intersection(_STRUCTURAL_NAMES):
                self.indicators[_indicator_name(key)] += 1
            # Action and type names are values in ordinary PDF dictionaries
            # (for example << /S /Launch >>), not only dictionary keys.
            for key, child in value.items():
                if str(key) in {"/S", "/Type"} and str(child) in _STRUCTURAL_NAMES:
                    self.indicators[_indicator_name(str(child))] += 1
            if "/EF" in keys:
                self.embedded_file_count += 1
            for child in value.values():
                self.walk(child, depth + 1)
        elif isinstance(value, ArrayObject):
            self.object_count += 1
            if self.object_count > self.limits.max_objects:
                self.limit_reached = True
                return
            for child in value:
                self.walk(child, depth + 1)


def _resolve(value: Any) -> Any:
    return value.get_object() if isinstance(value, IndirectObject) else value


def _count_page_images(pages: list[Any]) -> int:
    """Count unique image XObjects through dictionaries only; export nothing."""
    images: set[tuple[int, int] | int] = set()
    for page in pages:
        resources = _resolve(page.get("/Resources"))
        if not isinstance(resources, DictionaryObject):
            continue
        xobjects = _resolve(resources.get("/XObject"))
        if not isinstance(xobjects, DictionaryObject):
            continue
        for reference in xobjects.values():
            object_key: tuple[int, int] | int
            if isinstance(reference, IndirectObject):
                object_key = (int(reference.idnum), int(reference.generation))
            else:
                object_key = id(reference)
            target = _resolve(reference)
            if isinstance(target, DictionaryObject) and str(target.get("/Subtype")) == "/Image":
                images.add(object_key)
    return len(images)


def inspect_pdf_structure(data: bytes, limits: StaticInspectionLimits) -> ParserInspection:
    """Inspect an in-memory PDF with pypdf, returning partial structured data."""
    result = ParserInspection(
        structural_indicator_counts={_indicator_name(name): None for name in _STRUCTURAL_NAMES}
    )
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            reader = PdfReader(io.BytesIO(data), strict=False)
        result.warnings.extend(
            StructuredExtractionIssue("parser_warning", _bounded_message(item.message, limits))
            for item in caught
        )
    except (PdfReadError, ValueError, OSError, EOFError) as error:
        result.errors.append(StructuredExtractionIssue("parser_failure", _bounded_message(error, limits)))
        return result
    except Exception as error:  # pypdf can expose malformed-object implementation errors.
        result.errors.append(StructuredExtractionIssue("parser_failure", _bounded_message(error, limits)))
        return result

    result.success = True
    try:
        result.encrypted = bool(reader.is_encrypted)
    except Exception as error:
        result.warnings.append(StructuredExtractionIssue("encryption_state_unavailable", _bounded_message(error, limits)))
    if result.encrypted:
        result.warnings.append(
            StructuredExtractionIssue(
                "encrypted_pdf_partial_extraction",
                "PDF is encrypted; no password is requested or attempted, so parser-derived page/text/image values are unavailable.",
            )
        )
        return result

    walker = _StructureWalker(limits)
    try:
        walker.walk(reader.trailer)
        result.structural_complete = not (walker.limit_reached or walker.failed_references)
        if result.structural_complete:
            result.structural_indicator_counts = dict(walker.indicators)
            result.embedded_file_count = walker.embedded_file_count
        if walker.failed_references:
            result.warnings.append(StructuredExtractionIssue(
                "structural_reference_unavailable", "One or more PDF references could not be resolved; structural totals are unavailable."))
        if walker.limit_reached:
            result.resource_limit_reached = True
            result.warnings.append(
                StructuredExtractionIssue("structural_object_limit", "Structural traversal reached a configured object or recursion limit.")
            )
    except Exception as error:
        result.warnings.append(StructuredExtractionIssue("structural_traversal_failure", _bounded_message(error, limits)))
    result.observed_structural_indicator_counts = dict(walker.indicators)

    try:
        metadata = reader.metadata
        if metadata is not None:
            result.metadata_entry_count = len(metadata)
            title = metadata.get("/Title")
            if title is not None:
                result.title_length = len(str(title))
            else:
                result.title_length = 0
    except Exception as error:
        result.warnings.append(StructuredExtractionIssue("metadata_unavailable", _bounded_message(error, limits)))

    try:
        page_count = len(reader.pages)
        if page_count > limits.max_pages:
            result.resource_limit_reached = True
            result.warnings.append(
                StructuredExtractionIssue("page_limit", f"PDF has {page_count} pages; configured maximum is {limits.max_pages}.")
            )
            return result
        result.page_count = page_count
        pages = [reader.pages[index] for index in range(page_count)]
    except Exception as error:
        result.warnings.append(StructuredExtractionIssue("page_tree_unavailable", _bounded_message(error, limits)))
        return result

    try:
        result.image_count = _count_page_images(pages)
    except Exception as error:
        result.warnings.append(StructuredExtractionIssue("image_count_unavailable", _bounded_message(error, limits)))

    text_length = 0
    try:
        for page in pages:
            # pypdf parses content streams only. It does not execute JavaScript,
            # Launch actions, URLs, embedded files, macros, or external programs.
            text_length += len(page.extract_text() or "")
        result.contains_text = int(text_length >= 50)
    except Exception as error:
        result.warnings.append(StructuredExtractionIssue("text_extraction_unavailable", _bounded_message(error, limits)))
    return result


def parser_library_metadata() -> dict[str, str]:
    """Return parser provenance without inspecting any input file."""
    return {"library": "pypdf", "version": str(pypdf.__version__), "mode": "read-only structural parsing"}


def parse_pdf_header(data: bytes) -> dict[str, Any]:
    """Return header diagnostics independently from parser success."""
    prefix = data[:16]
    match = re.match(rb"%PDF-([0-9]+(?:\.[0-9]+)?)", data[:32])
    version_string = None if match is None else match.group(1).decode("ascii", errors="replace")
    normalized = None
    if version_string is not None:
        try:
            normalized = float(version_string)
        except ValueError:
            normalized = None
    return {
        "pdf_header_present": match is not None,
        "header_version_string": version_string,
        "header_version_numeric": normalized,
        "first_bytes_hex": prefix.hex(),
    }

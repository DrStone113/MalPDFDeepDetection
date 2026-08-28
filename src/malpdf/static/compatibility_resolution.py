"""Formal provenance report for closing the ten static-extractor blockers."""

from __future__ import annotations

import csv
import platform
from pathlib import Path
from typing import Any

import pymupdf

from malpdf.static.result import StaticInspectionResult
from malpdf.static.rit_reference import (
    PDFMALEXTRACT_PYMUPDF_VERSION,
    PDFMALEXTRACT_SOURCE_COMMIT,
    PDFMALEXTRACT_SOURCE_PATH,
    PDFMALEXTRACT_SOURCE_URL,
)
from malpdf.static.schema import RIT_FEATURE_DETAILS, RIT_FEATURES, implementation_statuses

BASELINE_STATUS = {
    "pdfsize": "AMBIGUOUS", "metadata size": "AMBIGUOUS", "pages": "IMPLEMENTED_PROVISIONAL",
    "xref length": "AMBIGUOUS", "title length": "IMPLEMENTED_PROVISIONAL",
    "embedded files": "IMPLEMENTED_PROVISIONAL", "images": "IMPLEMENTED_PROVISIONAL",
    "contains_text": "IMPLEMENTED_PROVISIONAL", "pdf_ver": "IMPLEMENTED_PROVISIONAL",
    "ObjStm": "IMPLEMENTED_PROVISIONAL",
}
BLOCKERS = tuple(BASELINE_STATUS)

_CURRENT_METHODS = {
    "pdfsize": "exact file bytes plus unassigned KiB diagnostic",
    "metadata size": "metadata presence/entry count only", "pages": "pypdf page-tree count",
    "xref length": "raw xref token diagnostic only", "title length": "pypdf /Title character length",
    "embedded files": "bounded /EF dictionary traversal", "images": "unique /Image XObject count",
    "contains_text": "pypdf aggregate text threshold", "pdf_ver": "literal numeric %PDF header",
    "ObjStm": "token-aware raw /ObjStm count",
}
_FINAL_METHODS = {
    "pdfsize": "int(file_size_bytes / 1000)",
    "metadata size": "len(str(PyMuPDF Document.metadata).encode('utf-8'))",
    "pages": "PyMuPDF Document.page_count", "xref length": "PyMuPDF Document.xref_length()",
    "title length": "len(metadata['title']) if metadata['title'] else 0",
    "embedded files": "PyMuPDF Document.embfile_count()", "images": "sum(len(page.get_images()) for every page)",
    "contains_text": "aggregate page.get_text(); 1 iff accumulated length > 50, 0 otherwise, -1 only on released outer-loop failure",
    "pdf_ver": "float(metadata['format'][4:7])", "ObjStm": "raw bytes.count(b'/ObjStm')",
}
_UNITS = {
    "pdfsize": "decimal kilobytes, truncated integer", "metadata size": "UTF-8 bytes",
    "pages": "count", "xref length": "PyMuPDF xref length count", "title length": "Python string characters",
    "embedded files": "attachment count", "images": "per-page image-reference count",
    "contains_text": "-1 / 0 / 1", "pdf_ver": "float", "ObjStm": "raw byte-substring count",
}
_SYNTHETIC_TESTS = {
    "pdfsize": "test_pdfsize_is_decimal_and_truncated_not_binary_kibibytes",
    "metadata size": "test_metadata_and_title_contracts_cover_absent_ascii_unicode_and_xmp",
    "pages": "test_pages_xref_images_and_attachments_use_reference_counts",
    "xref length": "test_pages_xref_images_and_attachments_use_reference_counts",
    "title length": "test_metadata_and_title_contracts_cover_absent_ascii_unicode_and_xmp",
    "embedded files": "test_pages_xref_images_and_attachments_use_reference_counts",
    "images": "test_pages_xref_images_and_attachments_use_reference_counts",
    "contains_text": "test_contains_text_distinguishes_threshold_and_failure_sentinel",
    "pdf_ver": "test_pdf_version_preserves_normal_unusual_and_malformed_states",
    "ObjStm": "test_objstm_and_raw_counting_reproduce_pdfmalextract_overlap_rules",
}


def _schema_gate() -> dict[str, Any]:
    statuses = dict(implementation_statuses())
    result = StaticInspectionResult(
        input={}, parser={}, features={feature: 0 for feature in RIT_FEATURES}, compatibility=statuses, diagnostics={}
    )
    return result.protocol_g_drop3constant_gate().to_dict()


def build_resolution_rows() -> list[dict[str, str]]:
    """Build one evidence-qualified row for each original Protocol G blocker."""
    statuses = implementation_statuses()
    source_evidence = (
        f"Released PDFMalExtract v0.1 {PDFMALEXTRACT_SOURCE_PATH} at {PDFMALEXTRACT_SOURCE_COMMIT}; "
        f"uses PyMuPDF {PDFMALEXTRACT_PYMUPDF_VERSION}."
    )
    rows: list[dict[str, str]] = []
    for feature in BLOCKERS:
        detail = RIT_FEATURE_DETAILS[feature]
        rows.append(
            {
                "rit_feature": feature,
                "current_status": BASELINE_STATUS[feature],
                "documented_RIT_meaning": str(detail["paper_meaning"]),
                "current_measurement_method": _CURRENT_METHODS[feature],
                "candidate_correct_measurement": _FINAL_METHODS[feature],
                "unit": _UNITS[feature],
                "special_values": str(detail["special_values"]),
                "semantic_evidence": source_evidence,
                "synthetic_validation": _SYNTHETIC_TESTS[feature],
                "final_status": statuses[feature].value,
                "blocking_reason_if_any": "",
            }
        )
    return rows


def render_resolution_markdown(rows: list[dict[str, str]]) -> str:
    """Render a self-contained compatibility-closure report without PDF contents."""
    after_counts: dict[str, int] = {}
    for status in implementation_statuses().values():
        after_counts[status.value] = after_counts.get(status.value, 0) + 1
    gate = _schema_gate()
    lines = [
        "# Static extractor RIT compatibility resolution",
        "",
        "## Scope",
        "",
        "This v2 report preserves the prior v1 coverage result and resolves only its ten Protocol G blockers using the released PDFMalExtract v0.1 implementation, not model performance or dataset-distribution matching. The source uses PyMuPDF, so this project pins the same upstream-tested PyMuPDF version for canonical RIT metadata extraction. pypdf remains a separate, read-only structural-diagnostics parser.",
        "",
        f"- PDFMalExtract source: [{PDFMALEXTRACT_SOURCE_URL}]({PDFMALEXTRACT_SOURCE_URL}), revision `{PDFMALEXTRACT_SOURCE_COMMIT}`, `{PDFMALEXTRACT_SOURCE_PATH}`.",
        f"- Runtime provenance: Python `{platform.python_version()}`, PyMuPDF `{pymupdf.__version__}` (required `{PDFMALEXTRACT_PYMUPDF_VERSION}`).",
        "- Safety: the implementation opens bytes in memory, never evaluates JavaScript, follows URIs, extracts attachment payloads, opens a viewer, invokes an external application, or runs ML inference.",
        "",
        "## Before and after",
        "",
        "| State | Verified | Provisional | Ambiguous | Unsupported | Protocol G schema gate |",
        "| --- | ---: | ---: | ---: | ---: | --- |",
        "| v1 baseline | 31 | 7 | 3 | 0 | 28 / 38 FAIL |",
        f"| v2 implementation | {after_counts.get('IMPLEMENTED_VERIFIED_SEMANTICS', 0)} | {after_counts.get('IMPLEMENTED_PROVISIONAL', 0)} | {after_counts.get('AMBIGUOUS', 0)} | {after_counts.get('UNSUPPORTED', 0)} | {gate['compatible_feature_count']} / {gate['expected_feature_count']} {'PASS' if gate['passed'] else 'FAIL'} |",
        "",
        "The PASS is a **schema-level** result: all 38 required feature definitions now have verified deterministic representations. Every actual input still passes the per-file gate only if all values are present, numeric, finite, and extracted without an incompatible failure state.",
        "",
        "## Resolution table",
        "",
        "| Feature | Previous status | Canonical measurement | Unit / representation | Evidence | Synthetic validation | Final status | Remaining limitation |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        cells = (
            row["rit_feature"], row["current_status"], row["candidate_correct_measurement"], row["unit"],
            row["semantic_evidence"], row["synthetic_validation"], row["final_status"],
            row["blocking_reason_if_any"] or "None for source-defined normal representation.",
        )
        lines.append("| " + " | ".join(value.replace("|", r"\|") for value in cells) + " |")
    lines.extend(
        [
            "",
            "## Special-value contract",
            "",
            "- `contains_text`: PDFMalExtract aggregates text and sets `1` only once length is strictly greater than 50; it sets `-1` only in its outer text/attachment exception path. A page-level text failure is recorded separately and does not automatically become `-1`.",
            "- `images`: `-1` is used only for the released image-loop exception path. A generic pypdf failure is not converted to this sentinel.",
            "- `pages`: a returned `0` from `Document.page_count` is a valid source value. Current extractor failures are `null` plus a structured issue, never silently `0`.",
            "- `pdf_ver`: the exact source slice is parsed as a float. Out-of-spec values such as `5.0` are preserved; malformed/missing headers remain unavailable rather than normalized.",
            "",
            "## Additional raw-counter correction",
            "",
            "During source comparison, v1's token-boundary counters were corrected to the released raw `bytes.count` contract, including its overlap subtractions for `obj`, `stream`, `xref`, and `/Page`, and its literal `j/BaseEncoding` quirk. This affects an existing non-model-required constant feature but is documented and regression-tested rather than silently changed.",
            "",
            "## Limitations and next step",
            "",
            "The original RIT PDFs are still unavailable, so record-level equality cannot be demonstrated. The public source revision is the strongest available methodology evidence, but cannot prove it was the exact checkout used to build the local CSV. PyMuPDF behavior is version-sensitive, hence the exact pin and recorded runtime version. The source implementation's error-path sentinels are reproduced only where explicitly defined; no missing value is imputed. Feature compatibility is now satisfied, but this task performed no model loading, training, scoring, or prediction. A separately authorized next task may assess inference enablement.",
            "",
        ]
    )
    return "\n".join(lines)


def write_compatibility_resolution_outputs(project_root: str | Path) -> tuple[Path, Path]:
    """Write immutable v2 reports without replacing the historical v1 evidence."""
    root = Path(project_root)
    markdown_path = root / "reports" / "analysis" / "static_extractor_compatibility_resolution.md"
    csv_path = root / "reports" / "tables" / "static_extractor" / "rit_feature_compatibility_resolution.csv"
    for path in (markdown_path, csv_path):
        if path.exists():
            raise FileExistsError(f"Refusing to overwrite prior static-extractor result: {path}")
        path.parent.mkdir(parents=True, exist_ok=True)
    rows = build_resolution_rows()
    markdown_path.write_text(render_resolution_markdown(rows), encoding="utf-8")
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return markdown_path, csv_path

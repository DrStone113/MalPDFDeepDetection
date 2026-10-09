"""Feature-coverage documentation for the RIT-schema-oriented extractor."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from malpdf.static.result import StaticInspectionResult
from malpdf.static.schema import (
    PROTOCOL_G_DROPPED_CONSTANT_FEATURES,
    RIT_FEATURE_DETAILS,
    RIT_FEATURES,
    implementation_statuses,
)


def _shap_ranks(project_root: Path) -> dict[str, int]:
    path = project_root / "reports" / "experiments" / "explainability" / "xgb_protocol_g_seed42" / "shap_global_importance.csv"
    if not path.is_file():
        return {}
    with path.open("r", encoding="utf-8", newline="") as handle:
        return {str(row["feature"]): int(row["rank"]) for row in csv.DictReader(handle)}


def _method_for(feature: str) -> tuple[str, str, str]:
    if feature == "pdfsize":
        return ("PDFMalExtract int(file_size_bytes / 1000)", "decimal kilobytes, truncated integer", "Released source contract; original file bytes are also retained as diagnostics.")
    if feature == "metadata size":
        return ("UTF-8 byte length of str(PyMuPDF Document.metadata)", "bytes", "Released source contract; metadata content is not serialized.")
    if feature == "xref length":
        return ("PyMuPDF Document.xref_length()", "count", "Released source contract; distinct from raw xref token count.")
    if feature == "pages":
        return ("PyMuPDF Document.page_count", "count", "A source-returned 0 remains distinct from extractor failure.")
    if feature == "title length":
        return ("len(PyMuPDF metadata['title']) or 0", "Python string characters", "Released source contract; metadata text is not retained.")
    if feature == "isEncrypted":
        return ("int(bool(PyMuPDF metadata['encryption']))", "0/1", "Released source contract; the separate pypdf encryption flag is diagnostic only. Passwords are never attempted.")
    if feature == "embedded files":
        return ("PyMuPDF Document.embfile_count()", "count", "Counts logical attachments; payload bytes are never read.")
    if feature == "images":
        return ("sum(len(page.get_images()) for every page)", "per-page image-reference count", "No rendering/export; repeated references on separate pages count separately.")
    if feature == "contains_text":
        return ("PyMuPDF aggregate get_text(), threshold strictly >50", "-1/0/1", "Source-defined -1 is used only for the released outer-loop exception path.")
    if feature == "pdf_ver":
        return ("float(PyMuPDF metadata['format'][4:7])", "float", "Unusual source values are retained; malformed values remain unavailable.")
    if feature == "ObjStm":
        return ("raw bytes.count(b'/ObjStm')", "count", "Released code establishes standard /ObjStm spelling.")
    if feature == "BaseEncoding":
        return ("raw bytes.count(b'j/BaseEncoding')", "count", "Released source has a leading-j quirk; retained for dataset fidelity.")
    return ("PDFMalExtract raw bytes.count with documented overlap subtractions where applicable", "count", "Raw byte occurrences remain distinct from parser-confirmed active actions.")


def build_feature_compatibility_rows(project_root: str | Path) -> list[dict[str, str | int]]:
    """Build deterministic table rows for all 41 authoritative RIT features."""
    root = Path(project_root)
    ranks = _shap_ranks(root)
    statuses = implementation_statuses()
    rows: list[dict[str, str | int]] = []
    for feature in RIT_FEATURES:
        method, unit, notes = _method_for(feature)
        detail = RIT_FEATURE_DETAILS[feature]
        rows.append(
            {
                "rit_feature": feature,
                "documented_meaning": str(detail["paper_meaning"]),
                "model_used": "no" if feature in PROTOCOL_G_DROPPED_CONSTANT_FEATURES else "yes",
                "implementation_status": statuses[feature].value,
                "measurement_method": method,
                "unit": unit,
                "special_value_handling": str(detail["special_values"]),
                "shap_rank": ranks.get(feature, "unavailable"),
                "tests": "synthetic fixture and unit coverage",
                "notes": notes,
            }
        )
    return rows


def _coverage_gate() -> dict[str, Any]:
    statuses = dict(implementation_statuses())
    placeholder = StaticInspectionResult(
        input={}, parser={}, features={feature: 0 for feature in RIT_FEATURES}, compatibility=statuses, diagnostics={}
    )
    return placeholder.protocol_g_drop3constant_gate().to_dict()


def render_feature_coverage_markdown(rows: list[dict[str, str | int]]) -> str:
    """Render the thesis-facing coverage report without PDF sample information."""
    counts: dict[str, int] = {}
    for row in rows:
        status = str(row["implementation_status"])
        counts[status] = counts.get(status, 0) + 1
    gate = _coverage_gate()
    lines = [
        "# Static PDF extractor feature coverage",
        "",
        "## Scope and safety",
        "",
        "This is a **RIT-schema-oriented static extractor**, not a proven RIT-compatible feature generator and not an ML predictor. It reads local PDF bytes and parser dictionaries only. It never executes JavaScript or embedded files, follows URIs, opens a viewer, launches applications, extracts payloads, or invokes model inference.",
        "",
        "The public local RIT CSV has no corresponding PDFs or per-PDF hashes. Therefore record-by-record equivalence with the original feature-generation pipeline cannot be measured. Raw lexical counts and parser-derived structural diagnostics are deliberately reported as different concepts.",
        "",
        "## Coverage summary",
        "",
        f"- IMPLEMENTED_VERIFIED_SEMANTICS: {counts.get('IMPLEMENTED_VERIFIED_SEMANTICS', 0)} / 41",
        f"- IMPLEMENTED_PROVISIONAL: {counts.get('IMPLEMENTED_PROVISIONAL', 0)} / 41",
        f"- AMBIGUOUS: {counts.get('AMBIGUOUS', 0)} / 41",
        f"- UNSUPPORTED: {counts.get('UNSUPPORTED', 0)} / 41",
        "",
        "## Protocol G G-drop3constant compatibility gate",
        "",
        f"- Expected model features: {gate['expected_feature_count']}",
        f"- Exact-semantics numeric features currently compatible by implementation status: {gate['compatible_feature_count']}",
        f"- Gate result: **{'PASS' if gate['passed'] else 'FAIL'}**",
        "- This failure is intentional safety behavior: provisional or ambiguous mappings, missing values, non-numeric values, NaN, and infinity are never filled or coerced.",
        "- Blocking required features: " + ", ".join(f"`{item['feature']}` ({item['reason']})" for item in gate["blocking_features"]),
        "",
        "## Feature-by-feature coverage",
        "",
        "| RIT feature | Meaning | Implementation | Status | Unit | Special-value handling | Protocol G used | Local SHAP rank | Limitations |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        value = lambda key: str(row[key]).replace("|", r"\|")
        lines.append("| " + " | ".join(value(key) for key in ("rit_feature", "documented_meaning", "measurement_method", "implementation_status", "unit", "special_value_handling", "model_used", "shap_rank", "notes")) + " |")
    lines.extend(
        [
            "",
            "## Threats to validity",
            "",
            "- The original RIT raw PDFs and feature-extraction implementation are unavailable locally.",
            "- pypdf behavior can differ from the original parser, especially for malformed/encrypted PDFs.",
            "- Static inspection cannot observe runtime behavior and does not validate live malware samples.",
            "- Parser failure is represented separately from RIT sentinels such as `contains_text=-1`, `images=-1`, and `pages=0`; no value is cleaned, clipped, replaced, or imputed.",
            "",
        ]
    )
    return "\n".join(lines)


def write_feature_coverage_outputs(project_root: str | Path) -> tuple[Path, Path]:
    """Create non-overwriting Markdown/CSV coverage outputs from committed code."""
    root = Path(project_root)
    markdown_path = root / "reports" / "analysis" / "static_extractor_feature_coverage.md"
    csv_path = root / "reports" / "tables" / "static_extractor" / "rit_feature_compatibility.csv"
    for path in (markdown_path, csv_path):
        if path.exists():
            raise FileExistsError(f"Refusing to overwrite existing static-extractor result: {path}")
        path.parent.mkdir(parents=True, exist_ok=True)
    rows = build_feature_compatibility_rows(root)
    markdown_path.write_text(render_feature_coverage_markdown(rows), encoding="utf-8")
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return markdown_path, csv_path

"""Read-only source-fidelity comparison for local CIC tabular mirrors.

The module never changes source CSV/Parquet files and deliberately keeps
identifier values in memory only. Derived reports use aggregate counts and
redacted profile data rather than per-file identifiers.
"""

from __future__ import annotations

import hashlib
import json
import re
from decimal import Decimal, InvalidOperation
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

import pandas as pd

from malpdf.data.cic_pdfmal import (
    OFFICIAL_CIC_URL,
    OFFICIAL_COUNTS,
    discover_cic_sources,
    load_cic_pdfmal,
    validate_cic_pdfmal,
)
from malpdf.data.rit_pdfmal import sha256_file

_VALID_LABELS = {"benign", "malicious"}
_NUMERIC_LEXICAL = re.compile(r"[+-]?\d+(?:\.\d+)?")


class FidelityClassification(str, Enum):
    """Evidence-qualified status for one third-party CIC table."""

    FULL_COUNT_MATCH = "FULL_COUNT_MATCH"
    SUBSET_OR_TRUNCATED = "SUBSET_OR_TRUNCATED"
    TRANSFORMED = "TRANSFORMED"
    UNRESOLVED = "UNRESOLVED"


def _normalise_name(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).casefold())


def _canonical_value(value: Any) -> str:
    """Compare numerical lexical representations without changing source data."""
    text = str(value)
    if _NUMERIC_LEXICAL.fullmatch(text):
        try:
            return "numeric:" + str(Decimal(text).normalize())
        except InvalidOperation:  # pragma: no cover - guarded by the regex
            pass
    return "text:" + text


def _stable_distribution_fingerprint(series: pd.Series) -> str:
    """Return a safe fingerprint of the complete value distribution.

    This is used for identifiers too, but raw values never leave process memory.
    """
    counts: dict[str, int] = {}
    for value in series.astype(object).tolist():
        token = _canonical_value(value)
        counts[token] = counts.get(token, 0) + 1
    payload = json.dumps(sorted(counts.items()), ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _valid_label_mask(frame: pd.DataFrame, target: str) -> pd.Series:
    return frame[target].astype("string").str.strip().str.casefold().isin(_VALID_LABELS)


def _class_counts(frame: pd.DataFrame, target: str, mask: pd.Series | None = None) -> dict[str, int]:
    values = frame[target] if mask is None else frame.loc[mask, target]
    return {str(label): int(count) for label, count in values.value_counts(dropna=False, sort=False).items()}


def _source_provenance(path: Path) -> dict[str, str]:
    if path.name.casefold() == "pdfmalware2022.parquet":
        return {
            "source_type": "third-party mirror",
            "source_platform": "Kaggle",
            "source_filename": path.name,
            "retrieval_note": "Existing project mirror; no publisher byte-level provenance was supplied.",
        }
    return {
        "source_type": "third-party mirror",
        "source_platform": "unavailable",
        "source_filename": path.name,
        "retrieval_note": "Local mirror discovered during the fidelity audit; platform/repository metadata was not supplied.",
    }


def _target_summary(frame: pd.DataFrame, audit: dict[str, Any]) -> dict[str, Any]:
    target = audit["target"]["candidate_column"]
    if target is None:
        return {"target_column": None, "recognized_label_rows": 0, "recognized_class_counts": {}, "unexpected_raw_label_counts": {}}
    mask = _valid_label_mask(frame, target)
    raw = _class_counts(frame, target)
    unexpected = {
        label: count for label, count in raw.items()
        if str(label).strip().casefold() not in _VALID_LABELS
    }
    recognized = _class_counts(frame, target, mask)
    normalized = {str(label).casefold(): count for label, count in recognized.items()}
    return {
        "target_column": target,
        "recognized_label_rows": int(mask.sum()),
        "recognized_class_counts": normalized,
        "unexpected_raw_label_counts": unexpected,
        "physical_raw_label_counts": raw,
    }


def _unexpected_row_diagnostics(frame: pd.DataFrame, target: str | None) -> dict[str, Any]:
    """Describe malformed target rows without reporting identifiers or dropping rows."""
    if target is None:
        return {"unexpected_target_rows": 0, "all_fields_textual_nan_rows": 0, "actual_nan_cells_in_unexpected_rows": 0}
    unexpected = frame.loc[~_valid_label_mask(frame, target)]
    all_textual_nan = 0
    for _, row in unexpected.iterrows():
        if all(str(value).strip().casefold() == "nan" for value in row.tolist()):
            all_textual_nan += 1
    return {
        "unexpected_target_rows": int(len(unexpected)),
        "all_fields_textual_nan_rows": all_textual_nan,
        "actual_nan_cells_in_unexpected_rows": int(unexpected.isna().sum().sum()),
    }


def classify_source_fidelity(summary: dict[str, Any]) -> FidelityClassification:
    """Classify using physical rows first; never hide malformed source rows."""
    classes = summary["target_summary"]
    rows = summary["dimensions"]["rows"]
    expected = OFFICIAL_COUNTS
    known = classes["recognized_class_counts"]
    no_unexpected = not classes["unexpected_raw_label_counts"]
    exact_known = known == {"benign": expected["benign"], "malicious": expected["malicious"]}
    if rows == expected["total_records"] and no_unexpected and exact_known:
        return FidelityClassification.FULL_COUNT_MATCH
    if rows < expected["total_records"] and no_unexpected and all(known.get(label, 0) <= expected[label] for label in _VALID_LABELS):
        return FidelityClassification.SUBSET_OR_TRUNCATED
    if rows != expected["total_records"] or not no_unexpected or not exact_known:
        return FidelityClassification.TRANSFORMED
    return FidelityClassification.UNRESOLVED


def inspect_cic_sources(directory: str | Path) -> list[dict[str, Any]]:
    """Load every local tabular copy and prove the audit did not change its bytes."""
    sources: list[dict[str, Any]] = []
    for path in discover_cic_sources(directory):
        before = sha256_file(path)
        frame = load_cic_pdfmal(path)
        audit = validate_cic_pdfmal(frame, path)
        after = sha256_file(path)
        if before != after:
            raise RuntimeError(f"Source file changed during read-only inspection: {path}")
        summary = {
            "filename": path.name,
            "relative_path": audit["dataset"]["relative_path"],
            "format": path.suffix.casefold().lstrip("."),
            "file_size_bytes": audit["dataset"]["byte_size"],
            "sha256": before,
            "dimensions": audit["dimensions"],
            "columns_in_original_order": audit["columns_in_original_order"],
            "data_types": audit["data_types"],
            "target_summary": _target_summary(frame, audit),
            "unexpected_row_diagnostics": _unexpected_row_diagnostics(frame, audit["target"]["candidate_column"]),
            "provenance": _source_provenance(path),
            "candidate_predictive_feature_count": len(audit["candidate_predictive_columns"]),
            "identifier_column": next((name for name, role in audit["column_roles"].items() if role["classification"] == "identifier"), None),
            "column_profiles": audit["column_profiles"],
        }
        summary["population_fidelity_classification"] = classify_source_fidelity(summary).value
        summary["fidelity_classification"] = summary["population_fidelity_classification"]
        sources.append({"path": path, "frame": frame, "audit": audit, "summary": summary})
    return sources


def _column_map(frame: pd.DataFrame) -> dict[str, str]:
    mapping = {_normalise_name(column): str(column) for column in frame.columns}
    if len(mapping) != len(frame.columns):
        raise ValueError("Source schema has normalized-name collisions; comparison is unsafe")
    return mapping


def compare_schema(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """Compare schema/value distributions without exposing identifier values."""
    left_map = _column_map(left["frame"])
    right_map = _column_map(right["frame"])
    normalized_order_equal = list(left_map) == list(right_map)
    rows: list[dict[str, Any]] = []
    for name in sorted(set(left_map).union(right_map)):
        left_column = left_map.get(name)
        right_column = right_map.get(name)
        left_profile = None if left_column is None else left["summary"]["column_profiles"][left_column]
        right_profile = None if right_column is None else right["summary"]["column_profiles"][right_column]
        identifier = (left_column == left["summary"]["identifier_column"]) or (right_column == right["summary"]["identifier_column"])
        left_distribution = None if left_column is None else _stable_distribution_fingerprint(left["frame"][left_column])
        right_distribution = None if right_column is None else _stable_distribution_fingerprint(right["frame"][right_column])
        rows.append({
            "left_filename": left["summary"]["filename"], "right_filename": right["summary"]["filename"],
            "normalized_column": name, "left_column": left_column, "right_column": right_column,
            "present_in_both": left_column is not None and right_column is not None,
            "left_dtype": None if left_profile is None else left_profile["dtype"],
            "right_dtype": None if right_profile is None else right_profile["dtype"],
            "dtype_equal": None if left_profile is None or right_profile is None else left_profile["dtype"] == right_profile["dtype"],
            "left_unique_values": None if left_profile is None else left_profile["unique_value_count_including_nan"],
            "right_unique_values": None if right_profile is None else right_profile["unique_value_count_including_nan"],
            "left_missing_count": None if left_profile is None else left_profile["actual_nan_count"],
            "right_missing_count": None if right_profile is None else right_profile["actual_nan_count"],
            "identifier_values_redacted": identifier,
            "value_distribution_equal": None if left_distribution is None or right_distribution is None else left_distribution == right_distribution,
        })
    return {
        "raw_column_order_equal": left["summary"]["columns_in_original_order"] == right["summary"]["columns_in_original_order"],
        "normalized_column_order_equal": normalized_order_equal,
        "normalized_column_set_equal": set(left_map) == set(right_map),
        "per_column": rows,
    }


def _safe_transition_counts(left: pd.Series, right: pd.Series) -> list[dict[str, Any]]:
    pairs = pd.DataFrame({"left": left.astype(str), "right": right.astype(str)}).value_counts().head(12)
    return [{"left_value": values[0], "right_value": values[1], "count": int(count)} for values, count in pairs.items()]


def compare_rows_safely(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """Compare labeled records by identifier and semantic value representation only."""
    left_frame, right_frame = left["frame"], right["frame"]
    left_target = left["summary"]["target_summary"]["target_column"]
    right_target = right["summary"]["target_summary"]["target_column"]
    left_id, right_id = left["summary"]["identifier_column"], right["summary"]["identifier_column"]
    if None in {left_target, right_target, left_id, right_id}:
        return {"comparison_possible": False, "reason": "A target or identifier column was not safely identified."}
    left_map, right_map = _column_map(left_frame), _column_map(right_frame)
    if "filename" not in left_map or "filename" not in right_map:
        return {"comparison_possible": False, "reason": "Normalized FileName identifiers are unavailable."}
    left_valid = left_frame.loc[_valid_label_mask(left_frame, left_target)].set_index(left_id, drop=False)
    right_valid = right_frame.loc[_valid_label_mask(right_frame, right_target)].set_index(right_id, drop=False)
    if not left_valid.index.is_unique or not right_valid.index.is_unique:
        return {"comparison_possible": False, "reason": "Identifier values are not unique; row matching would be unsafe."}
    common = left_valid.index.intersection(right_valid.index)
    left_only, right_only = left_valid.index.difference(right_valid.index), right_valid.index.difference(left_valid.index)
    left_label, right_label = left_valid.loc[common, left_target].astype(str), right_valid.loc[common, right_target].astype(str)
    mismatch_columns: list[dict[str, Any]] = []
    mismatch_rows = pd.Series(False, index=common)
    for normalized in sorted(set(left_map).intersection(right_map).difference({"filename", "class"})):
        left_values = left_valid.loc[common, left_map[normalized]].astype(object).map(_canonical_value)
        right_values = right_valid.loc[common, right_map[normalized]].astype(object).map(_canonical_value)
        different = left_values.ne(right_values)
        mismatch_rows |= different
        if bool(different.any()):
            mismatch_columns.append({
                "normalized_column": normalized, "left_column": left_map[normalized], "right_column": right_map[normalized],
                "shared_rows_with_semantic_difference": int(different.sum()),
                "top_raw_value_transitions": _safe_transition_counts(
                    left_valid.loc[common, left_map[normalized]][different], right_valid.loc[common, right_map[normalized]][different]
                ),
            })
    larger, smaller = (left, right) if len(left_valid) >= len(right_valid) else (right, left)
    larger_only = left_only if larger is left else right_only
    larger_target = left_target if larger is left else right_target
    larger_valid = left_valid if larger is left else right_valid
    return {
        "comparison_possible": True,
        "left_filename": left["summary"]["filename"], "right_filename": right["summary"]["filename"],
        "identifier_matching": "Raw identifier values were used only in memory; reports contain aggregate counts and no identifiers.",
        "left_labeled_records": int(len(left_valid)), "right_labeled_records": int(len(right_valid)),
        "common_identifier_records": int(len(common)), "left_only_identifier_records": int(len(left_only)), "right_only_identifier_records": int(len(right_only)),
        "larger_filename": larger["summary"]["filename"], "larger_only_identifier_records": int(len(larger_only)),
        "larger_only_label_counts": _class_counts(larger_valid, larger_target, larger_valid.index.isin(larger_only)),
        "identifier_set_is_subset": int(len(smaller["frame"].loc[_valid_label_mask(smaller["frame"], smaller["summary"]["target_summary"]["target_column"])]) <= len(larger_valid)
        and (right_valid.index.isin(left_valid.index).all() if smaller is right else left_valid.index.isin(right_valid.index).all())),
        "shared_label_mismatch_count": int(left_label.ne(right_label).sum()),
        "shared_rows_with_any_semantic_feature_difference": int(mismatch_rows.sum()),
        "per_column_semantic_differences": mismatch_columns,
        "strict_recordwise_subset": bool((len(right_only) == 0 if smaller is right else len(left_only) == 0) and not mismatch_columns),
    }


def compare_cic_sources(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """Combine non-mutating schema and row-level mirror evidence."""
    return {"schema": compare_schema(left, right), "rows": compare_rows_safely(left, right)}


def build_source_fidelity_report(sources: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Build a source-fidelity report for every discovered local copy."""
    source_list = sorted(list(sources), key=lambda source: source["summary"]["filename"].casefold())
    comparisons = [compare_cic_sources(source_list[index], source_list[next_index]) for index in range(len(source_list)) for next_index in range(index + 1, len(source_list))]
    by_filename = {source["summary"]["filename"]: source for source in source_list}
    for comparison in comparisons:
        rows = comparison["rows"]
        if not rows["comparison_possible"] or rows["shared_rows_with_any_semantic_feature_difference"] == 0:
            continue
        left_source, right_source = by_filename[rows["left_filename"]], by_filename[rows["right_filename"]]
        smaller = left_source if rows["left_labeled_records"] < rows["right_labeled_records"] else right_source
        summary = smaller["summary"]
        if summary["fidelity_classification"] == FidelityClassification.SUBSET_OR_TRUNCATED.value:
            summary["fidelity_classification"] = FidelityClassification.TRANSFORMED.value
            summary["fidelity_note"] = (
                "Population counts show a subset/truncation, and shared identifier rows also have semantic feature-value differences relative to a larger local mirror. "
                "It is therefore not a strict record-wise subset."
            )
    recommended = None
    full = [source for source in source_list if source["summary"]["fidelity_classification"] == FidelityClassification.FULL_COUNT_MATCH.value]
    if full:
        selected = full[0]
        recommended = {
            "filename": selected["summary"]["filename"], "sha256": selected["summary"]["sha256"],
            "recommendation": "Preferred candidate: it matches all published totals as a physical table. This does not establish official byte-level provenance.",
        }
    else:
        totals_match = [source for source in source_list if source["summary"]["target_summary"]["recognized_class_counts"] == {"benign": OFFICIAL_COUNTS["benign"], "malicious": OFFICIAL_COUNTS["malicious"]}]
        if totals_match:
            selected = totals_match[0]
            recommended = {
                "filename": selected["summary"]["filename"], "sha256": selected["summary"]["sha256"],
                "recommendation": "Provisional candidate only: its recognized label records match published class totals, but its physical source table has an unexpected raw-label row and third-party provenance remains unresolved. Do not switch automatically.",
            }
    if recommended is None:
        recommended = {"filename": None, "sha256": None, "recommendation": "No source is recommended: none matches the documentary totals with sufficient structural evidence."}
    return {
        "audit_version": "1.0", "official_reference": {"url": OFFICIAL_CIC_URL, **OFFICIAL_COUNTS, "feature_count_ambiguity": "The CIC page states both 32 extracted and 37 representative static features."},
        "sources": [source["summary"] for source in source_list], "mirror_comparisons": comparisons,
        "recommendation": recommended,
        "limitations": [
            "All local copies are third-party mirrors; no byte-level official-source provenance was supplied.",
            "Identifier matching is performed only in memory and individual identifiers are never written to reports.",
            "Semantic value comparison normalizes only lexical numeric serialization (for example 1 and 1.0), not malformed tokens or category encodings.",
            "No raw source file, PDF, model, or training/evaluation pipeline was modified or executed.",
        ],
    }


def _markdown_table(headers: list[str], rows: Iterable[Iterable[Any]]) -> list[str]:
    materialized = list(rows)
    render = lambda value: "-" if value is None else str(value).replace("|", r"\|").replace("\n", " ")
    return ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |", *["| " + " | ".join(render(value) for value in row) + " |" for row in materialized]]


def source_fidelity_markdown(report: dict[str, Any]) -> str:
    """Render a factual source-fidelity conclusion without selecting a source."""
    lines = [
        "# CIC-Evasive-PDFMal2022 source-fidelity audit", "",
        "## Scope", "",
        "This is a read-only comparison of local extracted tabular mirrors. No PDF was opened, no raw source was changed, and no model training or cross-dataset classification was performed.", "",
        "## Documentary reference", "",
        f"The [CIC documentation]({report['official_reference']['url']}) reports {report['official_reference']['total_records']} records: {report['official_reference']['malicious']} malicious and {report['official_reference']['benign']} benign. It also states both 32 extracted and 37 representative static features; this inconsistency is retained rather than resolved by assumption.", "",
        "## Source inventory", "",
    ]
    lines.extend(_markdown_table(["File", "Format", "SHA-256", "Physical rows", "Recognized labels", "Benign", "Malicious", "Unexpected labels", "Classification"], [[
        source["filename"], source["format"], source["sha256"], source["dimensions"]["rows"], source["target_summary"]["recognized_label_rows"],
        source["target_summary"]["recognized_class_counts"].get("benign", 0), source["target_summary"]["recognized_class_counts"].get("malicious", 0),
        source["target_summary"]["unexpected_raw_label_counts"], source["fidelity_classification"],
    ] for source in report["sources"]]))
    for source in report["sources"]:
        diagnostic = source["unexpected_row_diagnostics"]
        if diagnostic["unexpected_target_rows"]:
            lines.append(
                f"- `{source['filename']}` has {diagnostic['unexpected_target_rows']} unexpected-target physical row(s): "
                f"{diagnostic['all_fields_textual_nan_rows']} are all textual `nan` across fields and "
                f"{diagnostic['actual_nan_cells_in_unexpected_rows']} actual NaN cell(s) occur in those rows. They were reported, not removed."
            )
    lines.extend(["", "## Mirror-to-mirror evidence", ""])
    if not report["mirror_comparisons"]:
        lines.append("Only one local tabular source was available; a mirror comparison is unavailable.")
    for comparison in report["mirror_comparisons"]:
        rows = comparison["rows"]
        if not rows["comparison_possible"]:
            lines.append(f"- Row comparison unavailable: {rows['reason']}")
            continue
        lines.extend([
            f"- Normalized schema order equal: `{comparison['schema']['normalized_column_order_equal']}`; raw header order equal: `{comparison['schema']['raw_column_order_equal']}`.",
            f"- Common identifier records: {rows['common_identifier_records']}; larger-only: {rows['larger_only_identifier_records']} with labels {rows['larger_only_label_counts']}; smaller-only: {rows['right_only_identifier_records'] if rows['larger_filename'] == rows['left_filename'] else rows['left_only_identifier_records']}.",
            f"- Shared label mismatches: {rows['shared_label_mismatch_count']}; shared records with at least one semantic feature difference: {rows['shared_rows_with_any_semantic_feature_difference']}; strict record-wise subset: `{rows['strict_recordwise_subset']}`.",
        ])
    lines.extend(["", "## Fidelity interpretation", "", "`FULL_COUNT_MATCH` would require a physical 10,025-row source with exactly the published benign/malicious totals and no unexpected label. `SUBSET_OR_TRUNCATED` captures a smaller clean source. `TRANSFORMED` records a physical/count/value-representation discrepancy. A match of counts alone never establishes official byte-level provenance.", "", "## Recommendation", "", f"- Candidate: `{report['recommendation']['filename']}`; SHA-256: `{report['recommendation']['sha256']}`.", f"- {report['recommendation']['recommendation']}", "", "## Limitations", "", *[f"- {item}" for item in report["limitations"]], ""])
    return "\n".join(lines)


def write_source_fidelity_outputs(report: dict[str, Any], reports_root: str | Path) -> dict[str, Path]:
    """Write safe, lightweight provenance outputs; raw tabular inputs remain untouched."""
    root = Path(reports_root)
    analysis, tables = root / "analysis", root / "tables" / "cic_source_fidelity"
    analysis.mkdir(parents=True, exist_ok=True)
    tables.mkdir(parents=True, exist_ok=True)
    paths = {
        "markdown": analysis / "cic_source_fidelity.md", "source_inventory": tables / "source_inventory.csv",
        "mirror_comparison": tables / "mirror_comparison.csv", "row_difference_summary": tables / "row_difference_summary.csv",
        "fidelity_assessment": tables / "fidelity_assessment.csv",
    }
    paths["markdown"].write_text(source_fidelity_markdown(report), encoding="utf-8")
    inventory = []
    assessment = []
    for source in report["sources"]:
        target = source["target_summary"]
        inventory.append({
            "filename": source["filename"], "relative_path": source["relative_path"], "format": source["format"], "file_size_bytes": source["file_size_bytes"], "sha256": source["sha256"],
            "rows": source["dimensions"]["rows"], "columns": source["dimensions"]["columns"], "columns_in_original_order_json": json.dumps(source["columns_in_original_order"]),
            "dtypes_json": json.dumps(source["data_types"], sort_keys=True), "target_column": target["target_column"], "physical_raw_label_counts_json": json.dumps(target["physical_raw_label_counts"], sort_keys=True),
            "recognized_label_rows": target["recognized_label_rows"], "recognized_class_counts_json": json.dumps(target["recognized_class_counts"], sort_keys=True), "unexpected_raw_label_counts_json": json.dumps(target["unexpected_raw_label_counts"], sort_keys=True),
            "candidate_predictive_feature_count": source["candidate_predictive_feature_count"], "identifier_column": source["identifier_column"],
            "source_type": source["provenance"]["source_type"], "source_platform": source["provenance"]["source_platform"], "retrieval_note": source["provenance"]["retrieval_note"],
            "unexpected_row_diagnostics_json": json.dumps(source["unexpected_row_diagnostics"], sort_keys=True), "population_fidelity_classification": source["population_fidelity_classification"], "fidelity_classification": source["fidelity_classification"], "fidelity_note": source.get("fidelity_note"),
        })
        assessment.append({"filename": source["filename"], "sha256": source["sha256"], "population_fidelity_classification": source["population_fidelity_classification"], "fidelity_classification": source["fidelity_classification"], "rationale": source.get("fidelity_note", "Physical counts, raw labels, and published CIC invariants were checked without changing the source.")})
    mirror_rows, row_rows = [], []
    for comparison in report["mirror_comparisons"]:
        mirror_rows.extend(comparison["schema"]["per_column"])
        row = comparison["rows"].copy()
        row["per_column_semantic_differences_json"] = json.dumps(row.pop("per_column_semantic_differences", []), ensure_ascii=False)
        row_rows.append(row)
    pd.DataFrame(inventory).to_csv(paths["source_inventory"], index=False)
    pd.DataFrame(mirror_rows).to_csv(paths["mirror_comparison"], index=False)
    pd.DataFrame(row_rows).to_csv(paths["row_difference_summary"], index=False)
    pd.DataFrame(assessment).to_csv(paths["fidelity_assessment"], index=False)
    return paths

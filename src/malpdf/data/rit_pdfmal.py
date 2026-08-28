"""Loading and non-mutating validation for RIT-PDFMal-2026 CSV files.

The loader deliberately disables pandas' automatic text-to-missing conversion.
This preserves tokens such as ``NA`` and ``null`` so an audit can distinguish
them from actual in-memory NaN values. No columns or cell values are changed.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from pandas.api import types as ptypes

TEXTUAL_MISSING_PLACEHOLDERS = frozenset(
    {"na", "n/a", "nan", "null", "none", "missing", "?"}
)
NEAR_CONSTANT_DOMINANCE_THRESHOLD = 0.995
EXTREMELY_LARGE_ABSOLUTE_THRESHOLD = 1_000_000_000_000
STRONG_ASSOCIATION_THRESHOLD = 0.95


class DatasetValidationError(ValueError):
    """Raised when a CSV cannot be loaded without altering its schema."""


def sha256_file(path: str | Path) -> str:
    """Return the SHA-256 checksum of a file without interpreting its content."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _csv_header(path: Path) -> list[str]:
    with path.open("r", encoding="utf-8-sig", newline="") as file_handle:
        reader = csv.reader(file_handle)
        try:
            header = next(reader)
        except StopIteration as error:
            raise DatasetValidationError("CSV is empty and has no header") from error

    if not header or any(column == "" for column in header):
        raise DatasetValidationError("CSV header contains an empty column name")
    duplicates = sorted({column for column in header if header.count(column) > 1})
    if duplicates:
        raise DatasetValidationError(
            f"CSV has duplicate column names; refusing to rename them: {duplicates}"
        )
    return header


def load_rit_pdfmal(path: str | Path) -> pd.DataFrame:
    """Load a RIT-PDFMal CSV while preserving its original column names and tokens.

    No columns are dropped, renamed, encoded, normalized, or imputed. Textual
    missing-value tokens remain text, allowing the validation report to describe
    them explicitly instead of conflating them with actual NaN values.
    """
    dataset_path = Path(path)
    if not dataset_path.is_file():
        raise FileNotFoundError(f"Dataset CSV not found: {dataset_path}")
    if dataset_path.suffix.lower() != ".csv":
        raise DatasetValidationError("RIT-PDFMal input must be a CSV file")

    expected_header = _csv_header(dataset_path)
    frame = pd.read_csv(
        dataset_path,
        encoding="utf-8-sig",
        low_memory=False,
        keep_default_na=False,
        na_filter=False,
    )
    if list(frame.columns) != expected_header:
        raise DatasetValidationError(
            "CSV parser changed the header; refusing to continue with a modified schema"
        )
    return frame


def _normalized_name(column: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", column.casefold()).strip("_")


def _json_scalar(value: Any) -> Any:
    """Convert pandas and NumPy scalar values to strict JSON-safe primitives."""
    if value is None:
        return None
    if isinstance(value, np.generic):
        value = value.item()
    if isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        if np.isnan(value):
            return "<NA>"
        if np.isposinf(value):
            return "Infinity"
        if np.isneginf(value):
            return "-Infinity"
        return value
    if pd.isna(value):
        return "<NA>"
    return str(value)


def _percentage(count: int | float, total: int) -> float:
    return 0.0 if total == 0 else round((float(count) / total) * 100, 6)


def _is_string_or_object(series: pd.Series) -> bool:
    return bool(ptypes.is_object_dtype(series.dtype) or ptypes.is_string_dtype(series.dtype))


def _is_categorical(series: pd.Series) -> bool:
    return isinstance(series.dtype, pd.CategoricalDtype)


def _is_numeric(series: pd.Series) -> bool:
    return bool(ptypes.is_numeric_dtype(series.dtype) and not ptypes.is_bool_dtype(series.dtype))


def _target_candidates(frame: pd.DataFrame) -> tuple[str | None, dict[str, Any]]:
    """Infer a target only when a column has explicit, label-like evidence.

    The audit deliberately will not select an arbitrary binary PDF feature as a
    target. An exact target-oriented column name is required for auto-selection.
    """
    exact_target_names = {
        "label",
        "labels",
        "target",
        "class",
        "classes",
        "classification",
        "ground_truth",
        "groundtruth",
        "y",
    }
    target_terms = ("label", "target", "class", "malware", "malicious", "benign")
    candidates: list[dict[str, Any]] = []

    for position, column in enumerate(frame.columns):
        normalized = _normalized_name(column)
        non_missing_unique = int(frame[column].nunique(dropna=True))
        name_score = 0
        name_evidence = "no target-oriented name signal"
        if normalized in exact_target_names:
            name_score = 100
            name_evidence = f"exact target-oriented header: {normalized}"
        elif any(term in normalized for term in target_terms):
            name_score = 40
            name_evidence = "target-oriented term appears in header"

        cardinality_score = 0
        if non_missing_unique == 2:
            cardinality_score = 10
        elif 2 < non_missing_unique <= 20:
            cardinality_score = 5
        position_score = 1 if position == len(frame.columns) - 1 else 0
        total_score = name_score + cardinality_score + position_score

        if total_score > 0:
            candidates.append(
                {
                    "column": column,
                    "position": position,
                    "non_missing_unique_values": non_missing_unique,
                    "dtype": str(frame[column].dtype),
                    "name_evidence": name_evidence,
                    "name_score": name_score,
                    "cardinality_score": cardinality_score,
                    "final_column_score": position_score,
                    "total_score": total_score,
                }
            )

    candidates.sort(key=lambda item: (-item["total_score"], item["position"]))
    selected = None
    if candidates and candidates[0]["name_score"] == 100 and candidates[0]["non_missing_unique_values"] >= 2:
        selected = str(candidates[0]["column"])

    method = {
        "selection_policy": (
            "All columns are scored using actual header semantics, observed cardinality, "
            "and final-column position. Automatic selection requires an exact "
            "target-oriented header plus at least two observed values."
        ),
        "selected_column": selected,
        "ranked_candidates": candidates,
    }
    return selected, method


def _target_distribution(series: pd.Series, row_count: int) -> list[dict[str, Any]]:
    counts = series.value_counts(dropna=False, sort=False)
    return [
        {
            "raw_value": _json_scalar(value),
            "count": int(count),
            "percentage": _percentage(int(count), row_count),
        }
        for value, count in counts.items()
    ]


def _missing_value_analysis(frame: pd.DataFrame) -> dict[str, dict[str, Any]]:
    row_count = len(frame)
    analysis: dict[str, dict[str, Any]] = {}
    for column in frame.columns:
        series = frame[column]
        actual_nan_count = int(series.isna().sum())
        as_text = series.astype("string")
        present = as_text.notna()
        stripped = as_text.str.strip()
        blank_string_count = int((present & stripped.eq("")).sum())
        placeholder_count = int(
            (present & stripped.str.casefold().isin(TEXTUAL_MISSING_PLACEHOLDERS)).sum()
        )
        observed_missing_count = actual_nan_count + blank_string_count + placeholder_count
        analysis[column] = {
            "actual_nan_count": actual_nan_count,
            "actual_nan_percentage": _percentage(actual_nan_count, row_count),
            "blank_string_count": blank_string_count,
            "blank_string_percentage": _percentage(blank_string_count, row_count),
            "textual_placeholder_count": placeholder_count,
            "textual_placeholder_percentage": _percentage(placeholder_count, row_count),
            "observed_missing_count": observed_missing_count,
            "observed_missing_percentage": _percentage(observed_missing_count, row_count),
        }
    return analysis


def _duplicate_analysis(frame: pd.DataFrame, target_column: str | None) -> dict[str, Any]:
    exact_repeated = frame.duplicated(keep="first")
    exact_members = frame.duplicated(keep=False)
    exact_duplicate_groups = int(frame.loc[exact_members].drop_duplicates().shape[0])
    result: dict[str, Any] = {
        "exact_duplicate_rows_excluding_first": int(exact_repeated.sum()),
        "exact_duplicate_rows_including_first": int(exact_members.sum()),
        "exact_duplicate_groups": exact_duplicate_groups,
        "feature_duplicate_analysis": None,
    }

    if target_column is None:
        return result

    feature_columns = [column for column in frame.columns if column != target_column]
    feature_frame = frame.loc[:, feature_columns]
    feature_repeated = feature_frame.duplicated(keep="first")
    feature_members = feature_frame.duplicated(keep=False)
    feature_duplicate_groups = int(feature_frame.loc[feature_members].drop_duplicates().shape[0])
    conflicts = (
        frame.groupby(feature_columns, dropna=False, sort=False)[target_column]
        .nunique(dropna=False)
        .gt(1)
    )
    result["feature_duplicate_analysis"] = {
        "target_column_ignored_for_comparison": target_column,
        "duplicate_feature_rows_excluding_first": int(feature_repeated.sum()),
        "duplicate_feature_rows_including_first": int(feature_members.sum()),
        "duplicate_feature_groups": feature_duplicate_groups,
        "feature_duplicate_groups_with_conflicting_target_values": int(conflicts.sum()),
    }
    return result


def _is_nonnegative_expected(column: str) -> bool:
    """Use conservative structural-name hints for the 'unexpected negative' flag."""
    normalized = _normalized_name(column)
    signed_terms = ("delta", "difference", "correlation", "coefficient", "score")
    if any(term in normalized for term in signed_terms):
        return False
    return True


def _numeric_sanity(frame: pd.DataFrame) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for column in frame.columns:
        series = frame[column]
        if not _is_numeric(series):
            continue
        values = series.to_numpy(dtype=float, na_value=np.nan)
        finite_values = values[np.isfinite(values)]
        negative_count = int((finite_values < 0).sum())
        finite_count = int(finite_values.size)
        result[column] = {
            "finite_value_count": finite_count,
            "min": None if finite_count == 0 else float(np.min(finite_values)),
            "max": None if finite_count == 0 else float(np.max(finite_values)),
            "mean": None if finite_count == 0 else float(np.mean(finite_values)),
            "median": None if finite_count == 0 else float(np.median(finite_values)),
            "standard_deviation": (
                None
                if finite_count == 0
                else (0.0 if finite_count == 1 else float(np.std(finite_values, ddof=1)))
            ),
            "negative_value_count": negative_count,
            "negative_values_unexpected_by_name_heuristic": (
                negative_count if _is_nonnegative_expected(column) else 0
            ),
            "infinity_count": int(np.isinf(values).sum()),
            "extremely_large_absolute_threshold": EXTREMELY_LARGE_ABSOLUTE_THRESHOLD,
            "extremely_large_value_count": int(
                (np.abs(finite_values) > EXTREMELY_LARGE_ABSOLUTE_THRESHOLD).sum()
            ),
        }
    return result


def _column_quality(frame: pd.DataFrame) -> dict[str, Any]:
    row_count = len(frame)
    columns: dict[str, dict[str, Any]] = {}
    constant_columns: list[str] = []
    near_constant_columns: list[dict[str, Any]] = []
    numeric_columns: list[str] = []
    string_or_object_columns: list[str] = []
    categorical_dtype_columns: list[str] = []
    boolean_columns: list[str] = []

    for column in frame.columns:
        series = frame[column]
        counts = series.value_counts(dropna=False)
        unique_count = int(series.nunique(dropna=False))
        dominant_value = None
        dominant_count = 0
        if not counts.empty:
            dominant_value = _json_scalar(counts.index[0])
            dominant_count = int(counts.iloc[0])
        dominance = 0.0 if row_count == 0 else dominant_count / row_count
        columns[column] = {
            "dtype": str(series.dtype),
            "unique_value_count_including_nan": unique_count,
            "dominant_value": dominant_value,
            "dominant_value_count": dominant_count,
            "dominant_value_percentage": _percentage(dominant_count, row_count),
        }
        if unique_count <= 1:
            constant_columns.append(column)
        elif dominance >= NEAR_CONSTANT_DOMINANCE_THRESHOLD:
            near_constant_columns.append(
                {
                    "column": column,
                    "dominant_value": dominant_value,
                    "dominant_value_count": dominant_count,
                    "dominant_value_percentage": _percentage(dominant_count, row_count),
                }
            )
        if _is_numeric(series):
            numeric_columns.append(column)
        if _is_string_or_object(series):
            string_or_object_columns.append(column)
        if _is_categorical(series):
            categorical_dtype_columns.append(column)
        if ptypes.is_bool_dtype(series.dtype):
            boolean_columns.append(column)

    return {
        "near_constant_dominance_threshold": NEAR_CONSTANT_DOMINANCE_THRESHOLD,
        "per_column": columns,
        "constant_columns": constant_columns,
        "near_constant_columns": near_constant_columns,
        "numeric_columns": numeric_columns,
        "string_or_object_columns": string_or_object_columns,
        "categorical_dtype_columns": categorical_dtype_columns,
        "boolean_columns": boolean_columns,
    }


def _name_contains_any(column: str, terms: tuple[str, ...]) -> bool:
    normalized = _normalized_name(column)
    tokens = set(normalized.split("_"))
    return any(term == normalized or term in tokens for term in terms)


def _identifier_and_metadata_checks(frame: pd.DataFrame) -> dict[str, list[dict[str, Any]]]:
    identifier_terms = ("uuid", "guid", "identifier", "hash", "sha", "md5", "filename", "file_name")
    metadata_terms = ("source", "collection", "dataset", "corpus", "family", "origin", "split", "fold")
    filename_terms = ("filename", "file_name", "filepath", "file_path", "path")
    result = {
        "identifier_like_columns": [],
        "filename_or_path_columns": [],
        "source_or_collection_metadata_columns": [],
    }
    for column in frame.columns:
        normalized = _normalized_name(column)
        unique_count = int(frame[column].nunique(dropna=False))
        uniqueness_percentage = _percentage(unique_count, len(frame))
        is_id_name = (
            normalized == "id"
            or normalized.startswith("id_")
            or normalized.endswith("_id")
            or _name_contains_any(column, identifier_terms)
        )
        details = {
            "column": column,
            "unique_value_count_including_nan": unique_count,
            "unique_value_percentage": uniqueness_percentage,
        }
        if is_id_name:
            result["identifier_like_columns"].append(details)
        if _name_contains_any(column, filename_terms):
            result["filename_or_path_columns"].append(details)
        if _name_contains_any(column, metadata_terms):
            result["source_or_collection_metadata_columns"].append(details)
    return result


def _cramers_v(feature: pd.Series, target: pd.Series) -> float | None:
    table = pd.crosstab(feature, target, dropna=False)
    observed = table.to_numpy(dtype=float)
    total = observed.sum()
    if total == 0 or min(observed.shape) < 2:
        return None
    expected = np.outer(observed.sum(axis=1), observed.sum(axis=0)) / total
    valid = expected > 0
    chi_squared = ((observed - expected) ** 2 / np.where(valid, expected, 1)).sum()
    denominator = min(observed.shape[0] - 1, observed.shape[1] - 1)
    return None if denominator == 0 else float(np.sqrt((chi_squared / total) / denominator))


def _leakage_checks(frame: pd.DataFrame, target_column: str | None) -> dict[str, Any]:
    related_terms = ("label", "target", "class", "malware", "malicious", "benign")
    target_related_names = []
    for column in frame.columns:
        if column != target_column and _name_contains_any(column, related_terms):
            target_related_names.append(column)

    result: dict[str, Any] = {
        "target_related_name_columns": target_related_names,
        "identifier_and_metadata": _identifier_and_metadata_checks(frame),
        "strong_univariate_associations": [],
        "exact_target_match_columns": [],
        "association_method": (
            "Numeric features use absolute Pearson correlation only when the selected "
            "target is numeric with exactly two values. String/object/categorical features "
            "use Cramer's V. Values at or above 0.95 are reported as suspicious."
        ),
        "strong_association_threshold": STRONG_ASSOCIATION_THRESHOLD,
    }
    if target_column is None:
        return result

    target = frame[target_column]
    target_is_binary_numeric = _is_numeric(target) and int(target.nunique(dropna=True)) == 2
    for column in frame.columns:
        if column == target_column:
            continue
        feature = frame[column]
        both_present = ~(feature.isna() | target.isna())
        if bool(both_present.any()):
            exact_match_rate = float((feature[both_present] == target[both_present]).mean())
            if exact_match_rate == 1.0:
                result["exact_target_match_columns"].append(
                    {"column": column, "matching_rows": int(both_present.sum())}
                )

        if target_is_binary_numeric and _is_numeric(feature):
            feature_values = feature.to_numpy(dtype=float, na_value=np.nan)
            target_numeric = target.to_numpy(dtype=float, na_value=np.nan)
            usable = np.isfinite(feature_values) & np.isfinite(target_numeric)
            if int(usable.sum()) < 2 or np.std(feature_values[usable]) == 0:
                continue
            association = abs(float(np.corrcoef(feature_values[usable], target_numeric[usable])[0, 1]))
            if association >= STRONG_ASSOCIATION_THRESHOLD:
                result["strong_univariate_associations"].append(
                    {
                        "column": column,
                        "method": "absolute_pearson_correlation",
                        "value": association,
                        "rows_used_for_calculation": int(usable.sum()),
                    }
                )
        elif _is_string_or_object(feature) or _is_categorical(feature) or ptypes.is_bool_dtype(feature.dtype):
            association = _cramers_v(feature, target)
            if association is not None and association >= STRONG_ASSOCIATION_THRESHOLD:
                result["strong_univariate_associations"].append(
                    {
                        "column": column,
                        "method": "cramers_v",
                        "value": association,
                        "rows_used_for_calculation": int(len(frame)),
                    }
                )
    return result


def validate_rit_pdfmal(
    frame: pd.DataFrame,
    dataset_path: str | Path | None = None,
) -> dict[str, Any]:
    """Build a non-mutating validation report for an already loaded dataframe."""
    if frame.columns.has_duplicates:
        raise DatasetValidationError("Dataframe has duplicate column names")

    path = Path(dataset_path) if dataset_path is not None else None
    target_column, target_detection = _target_candidates(frame)
    target_report: dict[str, Any] = {
        "candidate_column": target_column,
        "identification": target_detection,
        "distribution": None,
    }
    if target_column is not None:
        target_report["distribution"] = _target_distribution(frame[target_column], len(frame))

    dataset_metadata = {
        "filename": None if path is None else path.name,
        "sha256": None if path is None else sha256_file(path),
        "byte_size": None if path is None else path.stat().st_size,
    }
    return {
        "audit_version": "1.0",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset": dataset_metadata,
        "dimensions": {"rows": int(frame.shape[0]), "columns": int(frame.shape[1])},
        "columns_in_original_order": list(frame.columns),
        "data_types": {column: str(frame[column].dtype) for column in frame.columns},
        "target": target_report,
        "missing_value_policy": {
            "actual_nan_definition": "Pandas NaN/NA values present in the loaded dataframe.",
            "textual_placeholder_definition": sorted(TEXTUAL_MISSING_PLACEHOLDERS),
            "loader_behavior": (
                "Automatic text-to-NA parsing is disabled, so textual tokens remain visible "
                "and are reported separately from actual NaN values."
            ),
        },
        "missing_values": _missing_value_analysis(frame),
        "duplicates": _duplicate_analysis(frame, target_column),
        "column_quality": _column_quality(frame),
        "numeric_sanity": _numeric_sanity(frame),
        "potential_leakage": _leakage_checks(frame, target_column),
        "assumptions": [
            "This is a read-only audit; the source CSV is never modified.",
            "No columns are dropped, imputed, encoded, normalized, or renamed.",
            "Near-constant means one value occupies at least 99.5% of rows.",
            "Extremely large means an absolute numeric value greater than 1e12.",
            "Negative values are flagged as unexpected by a conservative column-name heuristic; review them with dataset documentation.",
            "Leakage indicators are descriptive flags, not proof that a feature is invalid or should be removed.",
        ],
    }


def inspect_rit_pdfmal(path: str | Path) -> dict[str, Any]:
    """Load a CSV and return its complete RIT-PDFMal inspection report."""
    dataset_path = Path(path)
    return validate_rit_pdfmal(load_rit_pdfmal(dataset_path), dataset_path)


def _markdown_cell(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, float):
        return f"{value:.6g}"
    return str(value).replace("|", r"\|").replace("\n", " ")


def _markdown_table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    lines.extend("| " + " | ".join(_markdown_cell(cell) for cell in row) + " |" for row in rows)
    return lines


def report_to_markdown(report: dict[str, Any]) -> str:
    """Render a complete human-readable Markdown version of an audit report."""
    dataset = report["dataset"]
    dimensions = report["dimensions"]
    target = report["target"]
    quality = report["column_quality"]
    lines = [
        "# RIT-PDFMal-2026 dataset inspection",
        "",
        f"- Dataset filename: `{dataset['filename']}`",
        f"- SHA-256: `{dataset['sha256']}`",
        f"- Byte size: {dataset['byte_size']}",
        f"- Generated (UTC): {report['generated_at_utc']}",
        "",
        "## Dimensions",
        "",
        f"- Rows: {dimensions['rows']}",
        f"- Columns: {dimensions['columns']}",
        "",
        "## Schema (original column order)",
        "",
    ]
    lines.extend(
        _markdown_table(
            ["#", "Column", "dtype"],
            [
                [index, column, report["data_types"][column]]
                for index, column in enumerate(report["columns_in_original_order"], start=1)
            ],
        )
    )

    lines.extend(["", "## Candidate target / label", ""])
    lines.append(f"Selected candidate: `{target['candidate_column']}`")
    lines.append("")
    lines.append(target["identification"]["selection_policy"])
    lines.append("")
    candidates = target["identification"]["ranked_candidates"]
    if candidates:
        lines.extend(
            _markdown_table(
                ["Column", "Score", "Observed values", "Evidence"],
                [
                    [
                        item["column"],
                        item["total_score"],
                        item["non_missing_unique_values"],
                        item["name_evidence"],
                    ]
                    for item in candidates
                ],
            )
        )
    else:
        lines.append("No column met the candidate criteria.")
    if target["distribution"] is not None:
        lines.extend(["", "### Target distribution", ""])
        lines.extend(
            _markdown_table(
                ["Raw label value", "Count", "Percentage"],
                [
                    [item["raw_value"], item["count"], f"{item['percentage']:.6f}%"]
                    for item in target["distribution"]
                ],
            )
        )

    lines.extend(["", "## Missing-value analysis", ""])
    lines.append(report["missing_value_policy"]["loader_behavior"])
    lines.append("")
    lines.extend(
        _markdown_table(
            ["Column", "Actual NaN", "Blank strings", "Text placeholders", "Observed missing"],
            [
                [
                    column,
                    f"{values['actual_nan_count']} ({values['actual_nan_percentage']:.6f}%)",
                    f"{values['blank_string_count']} ({values['blank_string_percentage']:.6f}%)",
                    f"{values['textual_placeholder_count']} ({values['textual_placeholder_percentage']:.6f}%)",
                    f"{values['observed_missing_count']} ({values['observed_missing_percentage']:.6f}%)",
                ]
                for column, values in report["missing_values"].items()
            ],
        )
    )

    duplicates = report["duplicates"]
    lines.extend(["", "## Duplicate analysis", ""])
    lines.extend(
        [
            f"- Exact duplicate rows excluding the first occurrence: {duplicates['exact_duplicate_rows_excluding_first']}",
            f"- Exact duplicate rows including the first occurrence: {duplicates['exact_duplicate_rows_including_first']}",
            f"- Exact duplicate groups: {duplicates['exact_duplicate_groups']}",
        ]
    )
    feature_duplicates = duplicates["feature_duplicate_analysis"]
    if feature_duplicates is not None:
        lines.extend(
            [
                f"- Feature duplicate rows excluding the first (ignoring `{feature_duplicates['target_column_ignored_for_comparison']}`): {feature_duplicates['duplicate_feature_rows_excluding_first']}",
                f"- Feature duplicate groups with conflicting target values: {feature_duplicates['feature_duplicate_groups_with_conflicting_target_values']}",
            ]
        )

    lines.extend(["", "## Column quality", ""])
    lines.extend(
        _markdown_table(
            ["Column", "dtype", "Unique values", "Dominant value", "Dominant percentage"],
            [
                [
                    column,
                    values["dtype"],
                    values["unique_value_count_including_nan"],
                    values["dominant_value"],
                    f"{values['dominant_value_percentage']:.6f}%",
                ]
                for column, values in quality["per_column"].items()
            ],
        )
    )
    lines.extend(
        [
            "",
            f"- Constant columns: {quality['constant_columns'] or 'None'}",
            f"- Near-constant threshold: {quality['near_constant_dominance_threshold']:.1%}",
            f"- Near-constant columns: {quality['near_constant_columns'] or 'None'}",
            f"- String/object columns: {quality['string_or_object_columns'] or 'None'}",
            f"- Categorical-dtype columns: {quality['categorical_dtype_columns'] or 'None'}",
            f"- Numeric columns: {quality['numeric_columns'] or 'None'}",
        ]
    )

    lines.extend(["", "## Numeric sanity checks", ""])
    lines.extend(
        _markdown_table(
            ["Column", "Min", "Max", "Mean", "Median", "Std. dev.", "Negative", "Infinities", "|x| > 1e12"],
            [
                [
                    column,
                    values["min"],
                    values["max"],
                    values["mean"],
                    values["median"],
                    values["standard_deviation"],
                    values["negative_values_unexpected_by_name_heuristic"],
                    values["infinity_count"],
                    values["extremely_large_value_count"],
                ]
                for column, values in report["numeric_sanity"].items()
            ],
        )
    )

    leakage = report["potential_leakage"]
    identifiers = leakage["identifier_and_metadata"]
    lines.extend(["", "## Potential leakage indicators", ""])
    lines.extend(
        [
            f"- Target-related names outside the selected target: {leakage['target_related_name_columns'] or 'None'}",
            f"- Identifier-like columns: {identifiers['identifier_like_columns'] or 'None'}",
            f"- Filename/path columns: {identifiers['filename_or_path_columns'] or 'None'}",
            f"- Source/collection metadata columns: {identifiers['source_or_collection_metadata_columns'] or 'None'}",
            f"- Exact target-match columns: {leakage['exact_target_match_columns'] or 'None'}",
            f"- Strong univariate associations (threshold {leakage['strong_association_threshold']:.2f}): {leakage['strong_univariate_associations'] or 'None'}",
        ]
    )

    lines.extend(["", "## Assumptions and scope", ""])
    lines.extend(f"- {assumption}" for assumption in report["assumptions"])
    lines.append("")
    return "\n".join(lines)


def write_inspection_reports(
    report: dict[str, Any], markdown_path: str | Path, json_path: str | Path
) -> None:
    """Write Markdown and strict JSON audit reports without touching the dataset."""
    markdown_output = Path(markdown_path)
    json_output = Path(json_path)
    markdown_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.parent.mkdir(parents=True, exist_ok=True)
    markdown_output.write_text(report_to_markdown(report), encoding="utf-8")
    json_output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )

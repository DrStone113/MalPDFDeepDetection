"""Read-only loading and audit utilities for CIC-Evasive-PDFMal2022 tables.

These utilities work only with the already extracted CSV or Parquet feature
table. They neither open PDFs nor mutate, encode, impute, rename, or rewrite
the source dataset.
"""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from pandas.api import types as ptypes

from malpdf.data.rit_pdfmal import TEXTUAL_MISSING_PLACEHOLDERS, sha256_file

OFFICIAL_CIC_URL = "https://www.unb.ca/cic/datasets/pdfmal-2022.html"
OFFICIAL_COUNTS = {"total_records": 10_025, "malicious": 5_557, "benign": 4_468}
EXPECTED_FILENAME = "PDFMalware2022.parquet"
NEAR_CONSTANT_DOMINANCE_THRESHOLD = 0.995
_TARGET_NAMES = {"label", "labels", "target", "class", "classes", "classification"}
_NUMERIC_LEXICAL = re.compile(r"[+-]?\d+(?:\.\d+)?")
_HASH_LIKE = re.compile(r"[0-9a-fA-F]{32,128}")


class CICDatasetError(ValueError):
    """Raised when a CIC dataset cannot be audited without changing it."""


@dataclass(frozen=True)
class CICDatasetDiscovery:
    """The deterministic result of looking for an allowed tabular CIC file."""

    selected_path: Path
    candidates: tuple[Path, ...]
    selection_reason: str


def _json_value(value: Any) -> Any:
    if isinstance(value, np.generic):
        value = value.item()
    if value is None:
        return None
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
    return 0.0 if total == 0 else round(float(count) * 100 / total, 6)


def _normalise_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.casefold()).strip("_")


def _relative_path_for_report(path: Path) -> str:
    """Prefer a workspace-relative provenance path without assuming one exists."""
    try:
        return str(path.resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(path)


def _is_native_numeric(series: pd.Series) -> bool:
    return bool(ptypes.is_numeric_dtype(series.dtype) and not ptypes.is_bool_dtype(series.dtype))


def _is_text_like(series: pd.Series) -> bool:
    return bool(
        ptypes.is_object_dtype(series.dtype)
        or ptypes.is_string_dtype(series.dtype)
        or isinstance(series.dtype, pd.CategoricalDtype)
    )


def _csv_header(path: Path) -> list[str]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        try:
            header = next(csv.reader(handle))
        except StopIteration as error:
            raise CICDatasetError("CIC CSV is empty") from error
    if not header or any(name == "" for name in header) or len(set(header)) != len(header):
        raise CICDatasetError("CIC CSV header is empty or contains duplicate column names")
    return header


def discover_cic_sources(directory: str | Path) -> tuple[Path, ...]:
    """Discover every local CSV/Parquet CIC table in deterministic path order."""
    root = Path(directory)
    if not root.is_dir():
        raise FileNotFoundError(f"CIC dataset directory not found: {root}")
    candidates = tuple(sorted(
        (path for path in root.rglob("*") if path.is_file() and path.suffix.casefold() in {".csv", ".parquet"}),
        key=lambda path: (str(path.relative_to(root)).casefold(), str(path)),
    ))
    if not candidates:
        raise FileNotFoundError(f"No CSV or Parquet CIC candidate found in: {root}")
    return candidates


def discover_cic_dataset(directory: str | Path) -> CICDatasetDiscovery:
    """Select the expected local feature table or fail on an ambiguous directory."""
    candidates = discover_cic_sources(directory)
    expected = [path for path in candidates if path.name.casefold() == EXPECTED_FILENAME.casefold()]
    if len(expected) == 1:
        return CICDatasetDiscovery(expected[0], candidates, "matched expected PDFMalware2022.parquet filename")
    if len(candidates) == 1:
        return CICDatasetDiscovery(candidates[0], candidates, "only CSV/Parquet candidate in directory")
    names = ", ".join(path.name for path in candidates)
    raise CICDatasetError(
        "Multiple CIC tabular candidates are present without one exact expected filename; "
        f"manual schema review is required: {names}"
    )


def load_cic_pdfmal(path: str | Path) -> pd.DataFrame:
    """Load a CIC CSV or Parquet table without changing source column values."""
    dataset_path = Path(path)
    if not dataset_path.is_file():
        raise FileNotFoundError(f"CIC feature table not found: {dataset_path}")
    suffix = dataset_path.suffix.casefold()
    if suffix == ".parquet":
        frame = pd.read_parquet(dataset_path)
    elif suffix == ".csv":
        expected_header = _csv_header(dataset_path)
        frame = pd.read_csv(
            dataset_path, encoding="utf-8-sig", low_memory=False, keep_default_na=False, na_filter=False
        )
        if list(frame.columns) != expected_header:
            raise CICDatasetError("CIC CSV parser changed the header")
    else:
        raise CICDatasetError("CIC feature input must be .csv or .parquet")
    if frame.columns.has_duplicates:
        raise CICDatasetError("CIC table has duplicate column names; refusing to rename them")
    return frame


def detect_cic_target(frame: pd.DataFrame) -> tuple[str | None, dict[str, Any]]:
    """Identify a target by observed header and cardinality evidence, not position alone."""
    candidates: list[dict[str, Any]] = []
    for position, column in enumerate(frame.columns):
        normalised = _normalise_name(str(column))
        unique_values = int(frame[column].nunique(dropna=True))
        name_score = 100 if normalised in _TARGET_NAMES else 0
        cardinality_score = 10 if unique_values == 2 else 5 if 2 < unique_values <= 20 else 0
        score = name_score + cardinality_score + (1 if position == len(frame.columns) - 1 else 0)
        if score:
            candidates.append(
                {
                    "column": str(column), "position": position, "dtype": str(frame[column].dtype),
                    "non_missing_unique_values": unique_values, "name_score": name_score,
                    "cardinality_score": cardinality_score, "total_score": score,
                }
            )
    candidates.sort(key=lambda item: (-item["total_score"], item["position"]))
    selected = candidates[0]["column"] if candidates and candidates[0]["name_score"] == 100 and candidates[0]["non_missing_unique_values"] >= 2 else None
    return selected, {
        "selection_policy": "Automatic selection requires an exact target-oriented header and at least two observed values.",
        "selected_column": selected,
        "ranked_candidates": candidates,
    }


def propose_canonical_label_mapping(series: pd.Series) -> dict[str, Any]:
    """Document a Benign/Malicious-to-0/1 proposal without transforming labels."""
    raw_values = [_json_value(value) for value in series.drop_duplicates().tolist()]
    by_normalised = {str(value).strip().casefold(): value for value in series.dropna().drop_duplicates().tolist()}
    expected = {"benign", "malicious"}
    unexpected = sorted(set(by_normalised).difference(expected))
    missing = sorted(expected.difference(by_normalised))
    is_valid = not unexpected and not missing and len(by_normalised) == 2
    raw_mapping: dict[str, int] = {}
    if is_valid:
        raw_mapping[str(by_normalised["benign"])] = 0
        raw_mapping[str(by_normalised["malicious"])] = 1
    return {
        "proposed_canonical_semantics": {"benign": 0, "malicious": 1},
        "raw_to_canonical_mapping": raw_mapping,
        "raw_values": raw_values,
        "is_valid_for_future_training_readiness": is_valid,
        "unexpected_normalized_values": unexpected,
        "missing_expected_values": missing,
        "scope": "Documentation only. The raw Class values were not transformed.",
    }


def _column_role(column: str, series: pd.Series, target_column: str | None) -> tuple[str, str]:
    if column == target_column:
        return "target", "Selected from actual target-oriented header and observed binary labels."
    name = _normalise_name(column)
    text_values = series.astype("string").dropna()
    hash_like_fraction = 0.0 if len(text_values) == 0 else float(text_values.str.fullmatch(_HASH_LIKE).mean())
    if any(term in name for term in ("filename", "file_name", "filepath", "file_path", "hash", "sha", "sample_id", "row_id")):
        return "identifier", "Header is identifier-like; FileName values are not predictive features."
    if hash_like_fraction >= 0.95 and series.nunique(dropna=False) == len(series):
        return "identifier", "Unique hash-like values indicate a sample identifier, not a predictive feature."
    if any(term in name for term in ("source", "collection", "dataset", "family", "split", "timestamp")):
        return "metadata", "Header appears to describe provenance or collection metadata."
    return "candidate_predictive_feature", "Not target/identifier/metadata by conservative header and value checks."


def classify_cic_columns(frame: pd.DataFrame, target_column: str | None) -> dict[str, dict[str, str]]:
    """Classify source roles without dropping any column."""
    return {
        str(column): {"classification": _column_role(str(column), frame[column], target_column)[0], "reason": _column_role(str(column), frame[column], target_column)[1]}
        for column in frame.columns
    }


def _text_quality(series: pd.Series) -> dict[str, Any] | None:
    if not _is_text_like(series):
        return None
    values = series.astype("string")
    present = values.dropna()
    numeric_lexical = present.str.fullmatch(_NUMERIC_LEXICAL).fillna(False)
    invalid = present.loc[~numeric_lexical]
    lower = present.str.strip().str.casefold()
    booleans = present.loc[lower.isin({"yes", "no", "true", "false"})]
    specials = present.loc[present.str.contains(r"[^A-Za-z0-9 ._+\-]", regex=True, na=False)]
    name = _normalise_name(str(series.name))
    if len(present) and bool(numeric_lexical.all()):
        likely_semantic_type = "integer-like values stored as text/category"
    elif name == "text":
        likely_semantic_type = "mixed text-presence indicator with sentinel/numeric tokens"
    elif name == "header":
        likely_semantic_type = "raw PDF header/version-like string"
    elif len(booleans):
        likely_semantic_type = "textual boolean/category mixed with other raw tokens"
    else:
        likely_semantic_type = "mixed numeric/text categorical representation"
    return {
        "observed_raw_values": [{"value": _json_value(value), "count": int(count)} for value, count in series.value_counts(dropna=False).head(30).items()],
        "numeric_lexical_count": int(numeric_lexical.sum()),
        "numeric_lexical_percentage": _percentage(int(numeric_lexical.sum()), len(series)),
        "non_numeric_or_malformed_examples": [{"value": _json_value(value), "count": int(count)} for value, count in invalid.value_counts().head(20).items()],
        "textual_boolean_examples": [{"value": _json_value(value), "count": int(count)} for value, count in booleans.value_counts().items()],
        "special_character_examples": [{"value": _json_value(value), "count": int(count)} for value, count in specials.value_counts().head(20).items()],
        "likely_semantic_type": likely_semantic_type,
        "future_encoding_assessment": (
            "All observed non-missing values are lexical numbers; explicit parsing could be reviewed later."
            if len(present) and bool(numeric_lexical.all())
            else "Raw categorical/malformed representation remains unverified; no encoding is applied."
        ),
    }


def _profile_column(column: str, series: pd.Series, row_count: int, role: str) -> dict[str, Any]:
    missing = int(series.isna().sum())
    strings = series.astype("string")
    present = strings.notna()
    stripped = strings.str.strip()
    blank = int((present & stripped.eq("")).sum())
    placeholders = int((present & stripped.str.casefold().isin(TEXTUAL_MISSING_PLACEHOLDERS)).sum())
    numeric = _is_native_numeric(series)
    infinities = 0
    negatives = 0
    zero_fraction: float | None = None
    numeric_stats: dict[str, float | int | None] = {"min": None, "max": None, "mean": None, "median": None, "standard_deviation": None}
    numeric_summary_basis = "not_applicable"
    if numeric:
        values = series.astype(float)
        infinities = int(np.isinf(values).sum())
        finite = values.loc[np.isfinite(values)]
        negatives = int((finite < 0).sum())
        zero_fraction = 0.0 if len(finite) == 0 else round(float((finite == 0).mean()), 6)
        numeric_summary_basis = "native_numeric_values"
        if len(finite):
            numeric_stats = {
                "min": float(finite.min()), "max": float(finite.max()), "mean": float(finite.mean()),
                "median": float(finite.median()), "standard_deviation": float(finite.std(ddof=1)) if len(finite) > 1 else 0.0,
            }
    elif _is_text_like(series):
        lexical = strings.loc[present & stripped.str.fullmatch(_NUMERIC_LEXICAL).fillna(False)]
        if len(lexical):
            parsed = pd.to_numeric(lexical, errors="raise")
            negatives = int((parsed < 0).sum())
            zero_fraction = round(float((parsed == 0).mean()), 6)
            numeric_summary_basis = "lexical_numeric_subset_only; raw strings were not coerced"
            numeric_stats = {
                "min": float(parsed.min()), "max": float(parsed.max()), "mean": float(parsed.mean()),
                "median": float(parsed.median()), "standard_deviation": float(parsed.std(ddof=1)) if len(parsed) > 1 else 0.0,
            }
    counts = series.value_counts(dropna=False)
    dominant_count = 0 if counts.empty else int(counts.iloc[0])
    dominant_value = None if counts.empty else _json_value(counts.index[0])
    unique = int(series.nunique(dropna=False))
    representative_values = [
        {"value": _json_value(value), "count": int(count)} for value, count in counts.head(12).items()
    ]
    string_audit = _text_quality(series)
    identifier_values_redacted = role == "identifier"
    if identifier_values_redacted:
        # Individual file-like hashes/IDs are unnecessary for a schema audit and
        # must not leak from an ignored dataset into a tracked research report.
        representative_values = [{"value": "<redacted identifier values>", "count": int(series.notna().sum())}]
        dominant_value = "<redacted identifier value>"
        if string_audit is not None:
            string_audit = {
                **string_audit,
                "observed_raw_values": [],
                "non_numeric_or_malformed_examples": [],
                "textual_boolean_examples": [],
                "special_character_examples": [],
                "likely_semantic_type": "identifier-like hash/ID; raw values redacted",
                "identifier_values_redacted": True,
                "redaction_note": "Individual identifier values are omitted from derived reports; uniqueness and hash-like classification remain recorded.",
            }
    return {
        "column": column, "role": role, "dtype": str(series.dtype),
        "unique_value_count_including_nan": unique, "actual_nan_count": missing,
        "actual_nan_percentage": _percentage(missing, row_count), "blank_string_count": blank,
        "blank_string_percentage": _percentage(blank, row_count), "textual_placeholder_count": placeholders,
        "textual_placeholder_percentage": _percentage(placeholders, row_count),
        "dominant_value": dominant_value, "dominant_count": dominant_count,
        "dominant_percentage": _percentage(dominant_count, row_count), "is_constant": unique == 1,
        "is_near_constant": unique > 1 and (dominant_count / row_count if row_count else 0.0) >= NEAR_CONSTANT_DOMINANCE_THRESHOLD,
        "numeric_summary": numeric_stats, "numeric_summary_basis": numeric_summary_basis,
        "infinity_count": infinities, "negative_value_count": negatives,
        "zero_fraction": zero_fraction, "representative_values": representative_values,
        "identifier_values_redacted": identifier_values_redacted, "string_value_audit": string_audit,
    }


def _duplicate_summary(frame: pd.DataFrame, predictive_columns: list[str], target_column: str | None) -> dict[str, Any]:
    exact_repeated = int(frame.duplicated(keep="first").sum())
    result: dict[str, Any] = {
        "exact_duplicate_rows_excluding_first": exact_repeated,
        "exact_duplicate_rows_including_first": int(frame.duplicated(keep=False).sum()),
        "duplicate_predictive_feature_rows_excluding_first": None,
        "duplicate_predictive_feature_rows_including_first": None,
        "duplicate_predictive_feature_groups": None,
        "conflicting_labels_for_identical_predictive_feature_vectors": None,
        "terminology_note": "Identical feature vectors are not called duplicate PDF files; no original-file identity is proven here.",
    }
    if not predictive_columns:
        return result
    features = frame.loc[:, predictive_columns]
    result["duplicate_predictive_feature_rows_excluding_first"] = int(features.duplicated(keep="first").sum())
    members = features.duplicated(keep=False)
    result["duplicate_predictive_feature_rows_including_first"] = int(members.sum())
    result["duplicate_predictive_feature_groups"] = int(features.loc[members].drop_duplicates().shape[0])
    if target_column is not None:
        labels_per_vector = frame.groupby(predictive_columns, observed=True, dropna=False)[target_column].nunique(dropna=False)
        result["conflicting_labels_for_identical_predictive_feature_vectors"] = int((labels_per_vector > 1).sum())
    return result


_CIC_MEANINGS: dict[str, tuple[str, str, str]] = {
    "PdfSize": ("PDF document size.", "unit not stated on the official dataset page", "verified"),
    "MetadataSize": ("Metadata section size.", "unit not stated on the official dataset page", "verified"),
    "Pages": ("Number of pages.", "count", "verified"),
    "XrefLength": ("Number of entries in PDF Xref tables.", "count", "verified"),
    "TitleCharacters": ("Number of characters in the title.", "characters", "verified"),
    "isEncrypted": ("Whether the PDF document is password protected.", "binary/indicator documented; local values require audit", "verified"),
    "EmbeddedFiles": ("Number of embedded files.", "count", "verified"),
    "Images": ("Number of images in the document.", "count", "verified"),
    "Text": ("Presence of text inside the PDF.", "categorical/indicator", "verified"),
    "Header": ("Presence of a valid PDF header.", "categorical/header representation", "verified"),
    "Obj": ("Number of indirect objects.", "count", "verified"),
    "Stream": ("Number of streams.", "count", "verified"),
    "Trailer": ("Number of trailers.", "count", "verified"),
    "StartXref": ("Number of startxref keywords.", "count", "verified"),
    "ObjStm": ("Number of stream objects (ObjStm).", "count", "verified"),
    "JS": ("Number of JS keywords/objects containing JavaScript code.", "count", "verified"),
    "Javascript": ("Number of JavaScript keywords/objects containing JavaScript code.", "count", "verified"),
    "AA": ("Number of AA keywords.", "count", "verified"),
    "OpenAction": ("Number of OpenAction keywords.", "count", "verified"),
    "Acroform": ("Number of Acroform tags.", "count", "verified"),
    "JBIG2Decode": ("Presence of the JBig2Decode filter.", "presence/indicator", "verified"),
    "RichMedia": ("Number of RichMedia keywords.", "count", "verified"),
    "Launch": ("Number of Launch keywords.", "count", "verified"),
    "XFA": ("XFA feature related to XML Form Architecture.", "count/indicator not fully specified", "verified"),
    "Xref": ("Number of Xref tables.", "count", "verified"),
    "Endobj": ("Not separately defined on the official dataset page.", "unverified", "unverified"),
    "Endstream": ("Not separately defined on the official dataset page.", "unverified", "unverified"),
    "PageNo": ("Not separately defined on the official dataset page.", "unverified", "unverified"),
    "Encrypt": ("Local column is distinct from isEncrypted; exact meaning is not separately defined.", "unverified", "unverified"),
    "EmbeddedFile": ("Local column is distinct from EmbeddedFiles; exact meaning is not separately defined.", "unverified", "unverified"),
    "Colors": ("Different colors used in the PDF.", "count/quantity", "verified"),
}


def build_cic_feature_dictionary(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Describe each actual candidate CIC predictor with source-qualified evidence."""
    profiles = report["column_profiles"]
    result: list[dict[str, Any]] = []
    for column in report["candidate_predictive_columns"]:
        meaning, unit, status = _CIC_MEANINGS.get(
            column, ("No verified feature description located in the official CIC page.", "unverified", "unverified")
        )
        profile = profiles[column]
        result.append({
            "column": column, "normalized_descriptive_name": _normalise_name(column),
            "documented_meaning": meaning, "local_dtype": profile["dtype"], "unit_if_known": unit,
            "representative_values": profile["representative_values"],
            "special_value_semantics": "Observed raw special values are reported; their CIC semantics are not inferred unless the official page states them.",
            "evidence": OFFICIAL_CIC_URL if status == "verified" else "Local schema only; official page does not separately define this column.",
            "verification_status": status,
        })
    return result


def validate_cic_pdfmal(frame: pd.DataFrame, dataset_path: str | Path | None = None) -> dict[str, Any]:
    """Build a complete read-only audit report for an already loaded CIC table."""
    if frame.columns.has_duplicates:
        raise CICDatasetError("CIC dataframe has duplicate column names")
    target_column, target_detection = detect_cic_target(frame)
    roles = classify_cic_columns(frame, target_column)
    predictive = [column for column in frame.columns if roles[str(column)]["classification"] == "candidate_predictive_feature"]
    profiles = {str(column): _profile_column(str(column), frame[column], len(frame), roles[str(column)]["classification"]) for column in frame.columns}
    distribution = [] if target_column is None else [
        {"raw_value": _json_value(value), "count": int(count), "percentage": _percentage(int(count), len(frame))}
        for value, count in frame[target_column].value_counts(dropna=False, sort=False).items()
    ]
    label_mapping = None if target_column is None else propose_canonical_label_mapping(frame[target_column])
    observed_counts = {str(item["raw_value"]).casefold(): item["count"] for item in distribution}
    class_comparison = {
        "official_reference": {"source_url": OFFICIAL_CIC_URL, **OFFICIAL_COUNTS},
        "observed": {"total_records": len(frame), "malicious": observed_counts.get("malicious"), "benign": observed_counts.get("benign")},
        "difference_observed_minus_official": {
            "total_records": len(frame) - OFFICIAL_COUNTS["total_records"],
            "malicious": None if observed_counts.get("malicious") is None else observed_counts["malicious"] - OFFICIAL_COUNTS["malicious"],
            "benign": None if observed_counts.get("benign") is None else observed_counts["benign"] - OFFICIAL_COUNTS["benign"],
        },
    }
    class_comparison["matches_official_counts"] = all(value in (0, None) for value in class_comparison["difference_observed_minus_official"].values())
    path = None if dataset_path is None else Path(dataset_path)
    report = {
        "audit_version": "1.0", "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "mirror_provenance": {"source_type": "third-party mirror", "source_platform": "Kaggle", "source_filename": "PDFMalware2022.parquet", "identity_caution": "This local mirror is not claimed to be an official CIC file or byte-identical to the CIC original."},
        "dataset": {"filename": None if path is None else path.name, "relative_path": None if path is None else _relative_path_for_report(path), "sha256": None if path is None else sha256_file(path), "byte_size": None if path is None else path.stat().st_size},
        "dimensions": {"rows": int(frame.shape[0]), "columns": int(frame.shape[1])},
        "columns_in_original_order": [str(column) for column in frame.columns],
        "data_types": {str(column): str(frame[column].dtype) for column in frame.columns},
        "target": {"candidate_column": target_column, "identification": target_detection, "distribution": distribution, "proposed_label_mapping": label_mapping},
        "official_identity_comparison": class_comparison,
        "documentation_feature_count_ambiguity": "The official CIC page says 32 extracted features and elsewhere describes 37 static representative features. The actual local schema, not either prose count, is the audit ground truth.",
        "column_roles": roles, "candidate_predictive_columns": predictive,
        "column_type_summary": {
            "native_numeric_columns": [str(column) for column in frame.columns if _is_native_numeric(frame[column])],
            "text_object_or_categorical_columns": [str(column) for column in frame.columns if _is_text_like(frame[column])],
            "constant_columns": [str(column) for column, profile in profiles.items() if profile["is_constant"]],
            "near_constant_columns": [str(column) for column, profile in profiles.items() if profile["is_near_constant"]],
        },
        "column_profiles": profiles,
        "duplicate_summary": _duplicate_summary(frame, predictive, target_column),
        "assumptions": [
            "The audit is read-only and never modifies the raw CSV/Parquet file.",
            "Actual NaN, blank strings, and textual placeholders are reported separately.",
            "Negative raw values such as -1 are reported as observed values, not silently converted to missing values.",
            "Near-constant means a dominant value occupies at least 99.5% of rows.",
            "Identifier/metadata classification is a future-feature-use warning, not a raw-data deletion instruction.",
        ],
    }
    report["feature_dictionary"] = build_cic_feature_dictionary(report)
    return report


def inspect_cic_pdfmal(path: str | Path) -> dict[str, Any]:
    """Load a CIC tabular feature file and return the complete non-mutating audit."""
    dataset_path = Path(path)
    return validate_cic_pdfmal(load_cic_pdfmal(dataset_path), dataset_path)


def feature_profile_table(report: dict[str, Any]) -> pd.DataFrame:
    """Flatten per-column audit fields for a tracked research CSV."""
    rows: list[dict[str, Any]] = []
    for profile in report["column_profiles"].values():
        numeric = profile["numeric_summary"]
        text = profile["string_value_audit"]
        rows.append({
            "column": profile["column"], "role": profile["role"], "dtype": profile["dtype"],
            "unique_value_count_including_nan": profile["unique_value_count_including_nan"],
            "actual_nan_count": profile["actual_nan_count"], "actual_nan_percentage": profile["actual_nan_percentage"],
            "blank_string_count": profile["blank_string_count"], "textual_placeholder_count": profile["textual_placeholder_count"],
            "negative_value_count": profile["negative_value_count"], "infinity_count": profile["infinity_count"],
            "zero_fraction": profile["zero_fraction"], "is_constant": profile["is_constant"], "is_near_constant": profile["is_near_constant"],
            "min": numeric["min"], "max": numeric["max"], "mean": numeric["mean"], "median": numeric["median"], "standard_deviation": numeric["standard_deviation"],
            "numeric_summary_basis": profile["numeric_summary_basis"],
            "numeric_lexical_count": None if text is None else text["numeric_lexical_count"],
            "numeric_lexical_percentage": None if text is None else text["numeric_lexical_percentage"],
            "likely_semantic_type": None if text is None else text["likely_semantic_type"],
            "representative_values_json": json.dumps(profile["representative_values"], ensure_ascii=False),
            "string_audit_json": None if text is None else json.dumps(text, ensure_ascii=False),
        })
    return pd.DataFrame(rows)


def _markdown_cell(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.6g}"
    return str(value).replace("|", r"\|").replace("\n", " ")


def _markdown_table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    return [
        "| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |",
        *["| " + " | ".join(_markdown_cell(value) for value in row) + " |" for row in rows],
    ]


def cic_audit_markdown(report: dict[str, Any]) -> str:
    """Render a factual human-readable audit; detail remains in its CSV/JSON tables."""
    dataset = report["dataset"]
    target = report["target"]
    identity = report["official_identity_comparison"]
    roles = report["column_roles"]
    profiles = report["column_profiles"]
    malformed = [
        (column, values["string_value_audit"]["numeric_lexical_count"], values["string_value_audit"]["non_numeric_or_malformed_examples"])
        for column, values in profiles.items() if values["role"] == "candidate_predictive_feature" and values["string_value_audit"] is not None and values["string_value_audit"]["non_numeric_or_malformed_examples"]
    ]
    lines = [
        "# CIC-Evasive-PDFMal2022 local mirror audit", "",
        "## Scope and provenance", "",
        "- Read-only audit of an extracted tabular feature table; no PDF was opened, executed, downloaded, or rendered.",
        "- Source type: third-party mirror; source platform: Kaggle.",
        "- The local file is not claimed to be an official CIC file or byte-identical to the original.",
        f"- Filename: `{dataset['filename']}`; relative path: `{dataset['relative_path']}`.",
        f"- SHA-256: `{dataset['sha256']}`; byte size: {dataset['byte_size']}.",
        f"- Actual shape: {report['dimensions']['rows']} rows x {report['dimensions']['columns']} columns.", "",
        "## Official identity comparison", "",
        f"The [official CIC page]({OFFICIAL_CIC_URL}) reports 10,025 records: 5,557 malicious and 4,468 benign. The local mirror has {identity['observed']['total_records']} rows, {identity['observed']['malicious']} malicious, and {identity['observed']['benign']} benign: differences are {identity['difference_observed_minus_official']}. This is a material mirror discrepancy and must be resolved or explicitly accepted before any cross-dataset benchmark.",
        "",
        "The official page also says both 32 extracted features and 37 static representative features in different sections. The actual local schema is therefore the implementation ground truth; it has one identifier, one target, and " + str(len(report['candidate_predictive_columns'])) + " candidate predictive features.",
        "", "## Schema and target", "",
    ]
    lines.extend(_markdown_table(["#", "Column", "dtype", "Role"], [[index, column, report['data_types'][column], roles[column]['classification']] for index, column in enumerate(report['columns_in_original_order'], start=1)]))
    lines.extend(["", f"Target selected from actual schema: `{target['candidate_column']}`.", ""])
    lines.extend(_markdown_table(["Raw label", "Count", "Percentage"], [[item['raw_value'], item['count'], f"{item['percentage']:.6f}%"] for item in target['distribution']]))
    mapping = target['proposed_label_mapping']
    lines.extend(["", f"Proposed documentation-only canonical mapping: `{mapping['raw_to_canonical_mapping']}`; valid: `{mapping['is_valid_for_future_training_readiness']}`. No label was transformed.", "", "## Data quality", ""])
    lines.extend(_markdown_table(["Column", "NaN", "Blank", "Placeholders", "Negative", "Zero fraction", "Constant", "Near-constant"], [[column, values['actual_nan_count'], values['blank_string_count'], values['textual_placeholder_count'], values['negative_value_count'], values['zero_fraction'], values['is_constant'], values['is_near_constant']] for column, values in profiles.items()]))
    type_summary = report["column_type_summary"]
    lines.extend([
        "",
        f"- Native numeric columns: {', '.join(type_summary['native_numeric_columns']) or 'none'}.",
        f"- Text/object/categorical columns: {', '.join(type_summary['text_object_or_categorical_columns']) or 'none'}.",
        f"- Constant columns: {', '.join(type_summary['constant_columns']) or 'none'}; near-constant columns: {', '.join(type_summary['near_constant_columns']) or 'none'}.",
    ])
    duplicate = report['duplicate_summary']
    lines.extend(["", f"- Exact duplicate rows excluding first: {duplicate['exact_duplicate_rows_excluding_first']}.", f"- Duplicate predictive vectors excluding first: {duplicate['duplicate_predictive_feature_rows_excluding_first']}.", f"- Predictive-vector groups with conflicting labels: {duplicate['conflicting_labels_for_identical_predictive_feature_vectors']}.", f"- {duplicate['terminology_note']}", "", "## String and malformed-value audit", ""])
    if malformed:
        lines.extend(_markdown_table(["Column", "Lexical numeric values", "Malformed/non-numeric examples"], [[column, count, examples] for column, count, examples in malformed]))
    else:
        lines.append("No text-like predictive column had non-numeric examples.")
    lines.extend(["", "## Identifier and feature dictionary", "", "- `FileName` is identifier-like: it contains unique hash-like strings and is excluded from the candidate predictive-feature list.", "- The full per-column profile and CIC feature dictionary are stored in the accompanying CSV and JSON metadata. Meanings not explicitly documented by the official page are marked unverified.", "", "## Training-readiness conclusion", "", "No model training, label encoding, numeric coercion, imputation, normalization, outlier removal, feature selection, or cross-dataset evaluation was performed. The mirror row/class-count discrepancy and malformed categorical representations require documented review before any future training or evaluation.", ""])
    return "\n".join(lines)


def write_cic_audit_outputs(report: dict[str, Any], reports_root: str | Path) -> dict[str, Path]:
    """Persist derived research reports only; never rewrite the raw CIC table."""
    root = Path(reports_root)
    analysis = root / "analysis"
    tables = root / "tables" / "cic_audit"
    analysis.mkdir(parents=True, exist_ok=True)
    tables.mkdir(parents=True, exist_ok=True)
    paths = {
        "markdown": analysis / "cic_dataset_audit.md", "json": analysis / "cic_dataset_audit.json",
        "feature_profile": tables / "feature_profile.csv", "class_distribution": tables / "class_distribution.csv",
        "duplicate_summary": tables / "duplicate_summary.csv", "feature_dictionary": tables / "feature_dictionary.csv",
    }
    paths["markdown"].write_text(cic_audit_markdown(report), encoding="utf-8")
    paths["json"].write_text(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    feature_profile_table(report).to_csv(paths["feature_profile"], index=False)
    official = report["official_identity_comparison"]["official_reference"]
    observed = report["official_identity_comparison"]["observed"]
    pd.DataFrame([
        {
            "class_or_total": "total_records", "raw_label": None, "observed_count": observed["total_records"],
            "observed_percentage": 100.0, "official_count": official["total_records"],
            "difference_observed_minus_official": observed["total_records"] - official["total_records"],
        },
        *[
            {
                "class_or_total": str(item["raw_value"]).casefold(), "raw_label": item["raw_value"],
                "observed_count": item["count"], "observed_percentage": item["percentage"],
                "official_count": official.get(str(item["raw_value"]).casefold()),
                "difference_observed_minus_official": None if official.get(str(item["raw_value"]).casefold()) is None else item["count"] - official[str(item["raw_value"]).casefold()],
            }
            for item in report["target"]["distribution"]
        ],
    ]).to_csv(paths["class_distribution"], index=False)
    pd.DataFrame([report["duplicate_summary"]]).to_csv(paths["duplicate_summary"], index=False)
    pd.DataFrame(report["feature_dictionary"]).to_csv(paths["feature_dictionary"], index=False)
    return paths

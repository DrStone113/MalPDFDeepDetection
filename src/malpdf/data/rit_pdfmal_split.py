"""Deterministic, duplicate-aware splitting for RIT-PDFMal-2026.

This module creates derived split metadata only. It never changes, rewrites, or
copies the raw dataset's feature values.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import date, datetime, time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from malpdf.data.rit_pdfmal import load_rit_pdfmal, sha256_file

TARGET_COLUMN = "Label"
SPLIT_NAMES = ("train", "validation", "test")
DEFAULT_SPLIT_PROPORTIONS = {"train": 0.60, "validation": 0.20, "test": 0.20}
DEFAULT_SPLIT_SEED = 42


class SplitValidationError(ValueError):
    """Raised when a group-aware split cannot meet its invariants."""


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


def _canonical_value(value: Any) -> list[str]:
    """Represent one scalar with its type so hash input is unambiguous and stable."""
    if isinstance(value, np.generic):
        value = value.item()
    if pd.isna(value):
        return ["missing", ""]
    if isinstance(value, bool):
        return ["bool", "true" if value else "false"]
    if isinstance(value, int):
        return ["int", str(value)]
    if isinstance(value, float):
        if np.isposinf(value):
            return ["float", "Infinity"]
        if np.isneginf(value):
            return ["float", "-Infinity"]
        return ["float", value.hex()]
    if isinstance(value, (datetime, date, time)):
        return ["datetime", value.isoformat()]
    return ["string", str(value)]


def _canonical_row(columns: list[str], values: tuple[Any, ...]) -> str:
    representation = [[column, _canonical_value(value)] for column, value in zip(columns, values)]
    return json.dumps(representation, ensure_ascii=False, separators=(",", ":"))


def _hash_text(namespace: str, text: str) -> str:
    return hashlib.sha256(f"{namespace}\x1f{text}".encode("utf-8")).hexdigest()


def build_duplicate_group_ids(
    frame: pd.DataFrame, target_column: str = TARGET_COLUMN
) -> pd.Series:
    """Hash all feature values in original column order to form duplicate-group IDs.

    The target is excluded. The DataFrame index is never read or included in a
    hash, so the identifier is determined solely by feature names and values.
    """
    if target_column not in frame.columns:
        raise SplitValidationError(f"Target column {target_column!r} is not present")
    feature_columns = [column for column in frame.columns if column != target_column]
    if not feature_columns:
        raise SplitValidationError("At least one feature column is required for grouping")
    feature_values = frame.loc[:, feature_columns].itertuples(index=False, name=None)
    group_ids = [
        f"group_{_hash_text('rit-pdfmal-feature-group-v1', _canonical_row(feature_columns, values))}"
        for values in feature_values
    ]
    return pd.Series(group_ids, index=frame.index, name="duplicate_group_id", dtype="string")


def build_deterministic_sample_ids(frame: pd.DataFrame) -> pd.Series:
    """Create unique sample IDs without using DataFrame row indexes.

    Repeated, fully identical rows are assigned an occurrence number within their
    identical canonical record. Those rows are interchangeable and remain in the
    same duplicate group, while each manifest row still receives a unique ID.
    """
    columns = list(frame.columns)
    occurrences: Counter[str] = Counter()
    sample_ids: list[str] = []
    for values in frame.itertuples(index=False, name=None):
        record_hash = _hash_text("rit-pdfmal-record-v1", _canonical_row(columns, values))
        occurrences[record_hash] += 1
        sample_ids.append(
            "sample_"
            + _hash_text("rit-pdfmal-sample-v1", f"{record_hash}:{occurrences[record_hash]}")
        )
    return pd.Series(sample_ids, index=frame.index, name="sample_id", dtype="string")


def _label_distribution(series: pd.Series, denominator: int) -> list[dict[str, Any]]:
    counts = series.value_counts(dropna=False, sort=False)
    return [
        {
            "raw_label": _json_value(label),
            "count": int(count),
            "percentage": 0.0 if denominator == 0 else round((int(count) / denominator) * 100, 6),
        }
        for label, count in counts.items()
    ]


def _group_table(
    frame: pd.DataFrame, group_ids: pd.Series, target_column: str
) -> pd.DataFrame:
    if len(frame) != len(group_ids):
        raise SplitValidationError("Group IDs do not cover every input row")
    if frame[target_column].isna().any():
        raise SplitValidationError("Target labels contain missing values and cannot be stratified")

    records = pd.DataFrame(
        {
            "duplicate_group_id": group_ids.to_numpy(copy=False),
            target_column: frame[target_column].to_numpy(copy=False),
        }
    )
    target_cardinality = records.groupby("duplicate_group_id", sort=False)[target_column].nunique(
        dropna=False
    )
    conflicting_ids = sorted(target_cardinality[target_cardinality > 1].index.tolist())
    if conflicting_ids:
        preview = ", ".join(conflicting_ids[:5])
        raise SplitValidationError(
            "A duplicate feature group contains multiple target labels; cannot create "
            f"a pure group-aware stratified split. Examples: {preview}"
        )

    group_sizes = records.groupby("duplicate_group_id", sort=False).size().rename("group_size")
    group_labels = records.groupby("duplicate_group_id", sort=False)[target_column].first()
    return pd.concat([group_sizes, group_labels], axis=1).reset_index()


def duplicate_group_statistics(
    frame: pd.DataFrame, group_ids: pd.Series, target_column: str = TARGET_COLUMN
) -> dict[str, Any]:
    """Report group cardinality, labels, and purity without changing any rows."""
    groups = _group_table(frame, group_ids, target_column)
    sizes = groups["group_size"]
    duplicate_groups = groups.loc[groups["group_size"] > 1]
    top_groups = groups.sort_values(
        ["group_size", "duplicate_group_id"], ascending=[False, True], kind="stable"
    ).head(20)

    label_distribution: list[dict[str, Any]] = []
    for label, label_groups in groups.groupby(target_column, sort=False, dropna=False):
        group_count = int(len(label_groups))
        row_count = int(label_groups["group_size"].sum())
        label_distribution.append(
            {
                "raw_label": _json_value(label),
                "group_count": group_count,
                "group_percentage": round((group_count / len(groups)) * 100, 6),
                "row_count": row_count,
                "row_percentage": round((row_count / len(frame)) * 100, 6),
            }
        )

    return {
        "total_groups": int(len(groups)),
        "singleton_groups": int((sizes == 1).sum()),
        "duplicate_groups": int((sizes > 1).sum()),
        "group_size": {
            "minimum": int(sizes.min()),
            "median": float(sizes.median()),
            "mean": float(sizes.mean()),
            "maximum": int(sizes.max()),
        },
        "top_20_largest_duplicate_groups": [
            {
                "duplicate_group_id": row.duplicate_group_id,
                "group_size": int(row.group_size),
                "raw_label": _json_value(getattr(row, target_column)),
            }
            for row in top_groups.itertuples(index=False)
        ],
        "label_distribution_by_group": label_distribution,
        "target_label_purity": {
            "all_groups_have_one_target_label": True,
            "conflicting_group_count": 0,
            "conflicting_group_ids": [],
        },
    }


def _tie_break_hash(seed: int, *values: Any) -> str:
    payload = "\x1f".join([str(seed), *(str(value) for value in values)])
    return _hash_text("rit-pdfmal-split-tie-break-v1", payload)


def _validate_proportions(proportions: dict[str, float]) -> None:
    if tuple(proportions) != SPLIT_NAMES:
        raise SplitValidationError(
            f"Split proportions must use this order and names: {', '.join(SPLIT_NAMES)}"
        )
    if any(value <= 0 for value in proportions.values()):
        raise SplitValidationError("All split proportions must be positive")
    if not np.isclose(sum(proportions.values()), 1.0):
        raise SplitValidationError("Split proportions must sum to 1.0")


def _assign_groups(
    groups: pd.DataFrame, target_column: str, seed: int, proportions: dict[str, float]
) -> dict[str, str]:
    """Assign pure label groups with a deterministic row-count balancing heuristic."""
    assignments: dict[str, str] = {}
    for label, label_groups in groups.groupby(target_column, sort=False, dropna=False):
        records = [
            {
                "duplicate_group_id": row.duplicate_group_id,
                "group_size": int(row.group_size),
            }
            for row in label_groups.itertuples(index=False)
        ]
        records.sort(
            key=lambda row: (
                -row["group_size"],
                _tie_break_hash(seed, "group-order", label, row["duplicate_group_id"]),
                row["duplicate_group_id"],
            )
        )
        total_class_rows = sum(row["group_size"] for row in records)
        desired_rows = {
            split_name: proportions[split_name] * total_class_rows for split_name in SPLIT_NAMES
        }
        assigned_rows = {split_name: 0 for split_name in SPLIT_NAMES}

        for row in records:
            size = row["group_size"]
            costs: list[tuple[float, str, str]] = []
            for split_name in SPLIT_NAMES:
                before = assigned_rows[split_name] - desired_rows[split_name]
                after = assigned_rows[split_name] + size - desired_rows[split_name]
                costs.append(
                    (
                        after**2 - before**2,
                        _tie_break_hash(seed, "split-choice", label, row["duplicate_group_id"], split_name),
                        split_name,
                    )
                )
            _, _, selected_split = min(costs)
            assignments[row["duplicate_group_id"]] = selected_split
            assigned_rows[selected_split] += size
    return assignments


def _split_statistics(
    manifest: pd.DataFrame, target_column: str, total_rows: int
) -> dict[str, dict[str, Any]]:
    statistics: dict[str, dict[str, Any]] = {}
    for split_name in SPLIT_NAMES:
        subset = manifest.loc[manifest["split"] == split_name]
        row_count = int(len(subset))
        benign_count = int((subset[target_column] == 0).sum())
        malicious_count = int((subset[target_column] == 1).sum())
        statistics[split_name] = {
            "row_count": row_count,
            "percentage_of_total_rows": round((row_count / total_rows) * 100, 6),
            "unique_group_count": int(subset["duplicate_group_id"].nunique()),
            "benign": {
                "raw_label": 0,
                "count": benign_count,
                "percentage_of_split": round((benign_count / row_count) * 100, 6)
                if row_count
                else 0.0,
            },
            "malicious": {
                "raw_label": 1,
                "count": malicious_count,
                "percentage_of_split": round((malicious_count / row_count) * 100, 6)
                if row_count
                else 0.0,
            },
            "raw_label_distribution": _label_distribution(subset[target_column], row_count),
        }
    return statistics


def validate_split_manifest(
    frame: pd.DataFrame,
    manifest: pd.DataFrame,
    target_column: str = TARGET_COLUMN,
) -> dict[str, Any]:
    """Check assignment, purity, and duplicate-leakage invariants."""
    required_columns = {"sample_id", "duplicate_group_id", "split", target_column}
    missing_columns = required_columns.difference(manifest.columns)
    if missing_columns:
        raise SplitValidationError(f"Manifest is missing columns: {sorted(missing_columns)}")

    split_sets = {
        split_name: set(
            manifest.loc[manifest["split"] == split_name, "duplicate_group_id"].astype(str)
        )
        for split_name in SPLIT_NAMES
    }
    group_overlaps = {
        "train_validation": len(split_sets["train"].intersection(split_sets["validation"])),
        "train_test": len(split_sets["train"].intersection(split_sets["test"])),
        "validation_test": len(split_sets["validation"].intersection(split_sets["test"])),
    }
    labels_preserved = _label_distribution(frame[target_column], len(frame)) == _label_distribution(
        manifest[target_column], len(manifest)
    )
    assignment_complete = (
        len(manifest) == len(frame)
        and manifest["sample_id"].nunique() == len(manifest)
        and manifest["split"].isin(SPLIT_NAMES).all()
        and not manifest["split"].isna().any()
    )
    group_pure_assignment = bool(
        (manifest.groupby("duplicate_group_id", sort=False)["split"].nunique() == 1).all()
    )
    validation = {
        "zero_group_overlap": {
            **group_overlaps,
            "is_valid": all(count == 0 for count in group_overlaps.values()),
        },
        "zero_feature_vector_duplicate_leakage": {
            **group_overlaps,
            "is_valid": all(count == 0 for count in group_overlaps.values()),
            "basis": "Duplicate-group IDs are SHA-256 hashes of all feature values excluding Label.",
        },
        "all_rows_assigned_exactly_once": {
            "manifest_row_count": int(len(manifest)),
            "source_row_count": int(len(frame)),
            "unique_sample_identifier_count": int(manifest["sample_id"].nunique()),
            "is_valid": assignment_complete,
        },
        "target_labels_preserved": {
            "is_valid": labels_preserved,
            "source_distribution": _label_distribution(frame[target_column], len(frame)),
            "manifest_distribution": _label_distribution(manifest[target_column], len(manifest)),
        },
        "one_split_per_duplicate_group": {"is_valid": group_pure_assignment},
    }
    if not all(section["is_valid"] for section in validation.values()):
        raise SplitValidationError(f"Split validation failed: {validation}")
    return validation


def create_rit_pdfmal_split(
    frame: pd.DataFrame,
    *,
    seed: int = DEFAULT_SPLIT_SEED,
    proportions: dict[str, float] | None = None,
    target_column: str = TARGET_COLUMN,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Create a deterministic 60/20/20-style split manifest from a loaded frame."""
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise SplitValidationError("Seed must be an integer")
    split_proportions = (
        DEFAULT_SPLIT_PROPORTIONS.copy() if proportions is None else proportions.copy()
    )
    _validate_proportions(split_proportions)
    if target_column != TARGET_COLUMN:
        raise SplitValidationError(f"RIT-PDFMal split target must be {TARGET_COLUMN!r}")
    if target_column not in frame.columns:
        raise SplitValidationError(f"Target column {target_column!r} is not present")

    group_ids = build_duplicate_group_ids(frame, target_column)
    groups = _group_table(frame, group_ids, target_column)
    group_statistics = duplicate_group_statistics(frame, group_ids, target_column)
    group_assignments = _assign_groups(groups, target_column, seed, split_proportions)
    sample_ids = build_deterministic_sample_ids(frame)
    manifest = pd.DataFrame(
        {
            "sample_id": sample_ids.to_numpy(copy=False),
            "duplicate_group_id": group_ids.to_numpy(copy=False),
            "split": [group_assignments[group_id] for group_id in group_ids],
            target_column: frame[target_column].to_numpy(copy=False),
        }
    )
    validation = validate_split_manifest(frame, manifest, target_column)
    result = {
        "seed": seed,
        "target_column": target_column,
        "split_proportions": split_proportions,
        "group_statistics": group_statistics,
        "split_statistics": _split_statistics(manifest, target_column, len(frame)),
        "hard_validation": validation,
    }
    return manifest, result


def build_split_report(
    dataset_path: str | Path, split_result: dict[str, Any]
) -> dict[str, Any]:
    """Attach dataset provenance and algorithm details to a split result."""
    path = Path(dataset_path)
    return {
        "report_version": "1.0",
        "dataset": {
            "filename": path.name,
            "sha256": sha256_file(path),
            "byte_size": path.stat().st_size,
        },
        "seed": split_result["seed"],
        "target_column": split_result["target_column"],
        "label_interpretation": {
            "benign_raw_label": 0,
            "malicious_raw_label": 1,
            "assumption": (
                "Split summaries call raw Label=0 benign and raw Label=1 malicious; "
                "no labels are encoded or changed."
            ),
        },
        "splitting_algorithm": {
            "name": "deterministic_labelwise_greedy_group_assignment",
            "group_identifier": (
                "SHA-256 of a canonical, type-tagged representation of every feature "
                "column in original order, excluding Label."
            ),
            "strategy": (
                "Pure duplicate groups are processed per raw label in descending group-size "
                "order. Each group is assigned to the split that minimizes the incremental "
                "squared error from that label's requested row proportion. SHA-256 seeded "
                "tie-breaks make equal-cost choices deterministic."
            ),
        },
        "requested_split_proportions": split_result["split_proportions"],
        "duplicate_group_statistics": split_result["group_statistics"],
        "split_statistics": split_result["split_statistics"],
        "hard_validation": split_result["hard_validation"],
        "scope": [
            "The raw CSV is read through load_rit_pdfmal and is never rewritten.",
            "No rows are removed, including duplicate rows.",
            "No normalization, feature selection, imputation, encoding, or model training is performed.",
        ],
    }


def write_split_artifacts(
    manifest: pd.DataFrame,
    report: dict[str, Any],
    manifest_path: str | Path,
    report_path: str | Path,
) -> None:
    """Write only derived manifest/report files, never the source dataset."""
    manifest_output = Path(manifest_path)
    report_output = Path(report_path)
    manifest_output.parent.mkdir(parents=True, exist_ok=True)
    report_output.parent.mkdir(parents=True, exist_ok=True)
    manifest.to_csv(manifest_output, index=False)
    report_output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def split_rit_pdfmal_file(
    dataset_path: str | Path,
    *,
    seed: int = DEFAULT_SPLIT_SEED,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Load RIT-PDFMal through the project loader and build its split artifacts."""
    frame = load_rit_pdfmal(dataset_path)
    manifest, result = create_rit_pdfmal_split(frame, seed=seed)
    return manifest, build_split_report(dataset_path, result)

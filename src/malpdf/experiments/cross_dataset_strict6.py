"""Strict six-feature RIT-to-CIC transfer benchmark infrastructure.

This module prepares a conservative, future-only benchmark.  It performs no
model fitting unless a caller explicitly invokes ``execute_*`` after a complete
preflight passes.  In particular, an unexplained value difference for any
STRICT6 feature across the two local CIC mirrors stops execution.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

import joblib
import numpy as np
import pandas as pd
import yaml
from sklearn.model_selection import train_test_split

from malpdf.data.cic_pdfmal import load_cic_pdfmal, validate_cic_pdfmal
from malpdf.data.cross_dataset_schema import AlignmentStatus, build_mapping_resolution_report
from malpdf.data.rit_pdfmal import load_rit_pdfmal, sha256_file
from malpdf.data.rit_pdfmal_paper_alignment import TARGET_COLUMN
from malpdf.data.rit_pdfmal_split import build_deterministic_sample_ids
from malpdf.evaluation.binary import evaluate_binary_predictions, fit_predict_and_measure
from malpdf.experiments.protocol_p import collect_environment_metadata, repository_git_state
from malpdf.models.classical import MODEL_NAMES, create_model, model_configurations
from malpdf.reproducibility import set_random_seed

EXPERIMENT_NAME = "cross_dataset_strict6"
STRICT6_SCHEMA_VERSION = "strict6-v1-alignment-v2"
STRICT_FEATURES = (
    "metadata_size",
    "xref_length",
    "title_length",
    "embedded_files",
    "trailer",
    "objstm",
)
RIT_DATASET_SHA256 = "2f270ab31fbfe8821fd7f54608cb1aa694a0a8d0bbf2ca000942a68213ef8623"
CIC_CSV_SHA256 = "61686c9b323cb41bf8c048e5e4fe1e43eaf7d8d634667dc256a1349d6242b489"
CIC_PARQUET_SHA256 = "25db2059d59207d2040c5a999838514579ed4667b2b7fa39f2398dee484caf65"
CIC_EXPECTED_ROWS = 10_025
CIC_EXPECTED_COUNTS = {0: 4_468, 1: 5_557}
CSV_STRICT6_SOURCE_COLUMNS = {
    "metadata_size": "metadata size", "xref_length": "xref Length", "title_length": "title characters",
    "embedded_files": "embedded files", "trailer": "trailer", "objstm": "ObjStm",
}
SPLIT_SEED = 42
MODEL_RANDOM_STATE = 42
TRACK_NAMES = ("within_rit", "within_cic", "rit_to_cic", "cic_to_rit")
METRIC_NAMES = (
    "accuracy", "precision_malicious", "recall_malicious", "f1_malicious",
    "precision_macro", "recall_macro", "f1_macro", "roc_auc", "pr_auc", "mcc",
)
RUNTIME_NAMES = (
    "training_seconds", "test_inference_total_seconds",
    "test_inference_milliseconds_per_sample",
)


class Strict6Error(RuntimeError):
    """Raised when a fixed cross-dataset research invariant is not satisfied."""


def _normalise_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.casefold()).strip("_")


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_run_id(run_id: str) -> str:
    if not run_id or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_." for char in run_id):
        raise Strict6Error("run_id must be non-empty and contain only letters, numbers, '-', '_', or '.'")
    return run_id


@dataclass(frozen=True)
class CanonicalDatasetView:
    """Read-only numeric projection used by the frozen STRICT6 experiment."""

    name: str
    source_path: Path
    source_sha256: str
    features: pd.DataFrame
    labels: pd.Series
    safe_sample_ids: pd.Series
    source_columns: dict[str, str]
    target_column: str
    raw_label_mapping: dict[str, int]
    canonical_view_sha256: str
    excluded_invalid_target_rows: int = 0
    numeric_validation_errors: tuple[str, ...] = ()

    def counts(self) -> dict[int, int]:
        return {label: int((self.labels == label).sum()) for label in (0, 1)}


@dataclass(frozen=True)
class Strict6Paths:
    run_id: str
    reports_directory: Path
    artifact_directory: Path
    experiment_config_json: Path
    environment_json: Path
    source_provenance_json: Path
    strict_schema_json: Path
    mirror_stability_csv: Path
    distribution_shift_csv: Path
    metrics_json: Path
    comparison_csv: Path
    run_summary_markdown: Path

    def summary_csv(self, track: str) -> Path:
        return self.reports_directory / f"{track}_summary.csv"

    def split_manifest_csv(self, track: str) -> Path:
        return self.reports_directory / f"{track}_split_manifest.csv"


@dataclass(frozen=True)
class Strict6Preflight:
    repository_root: Path
    rit: CanonicalDatasetView
    cic: CanonicalDatasetView
    cic_parquet: CanonicalDatasetView
    schema_records: tuple[dict[str, Any], ...]
    mirror_stability: tuple[dict[str, Any], ...]
    distribution_shift: tuple[dict[str, Any], ...]
    within_splits: dict[str, dict[str, Any]]
    config: dict[str, Any]
    environment: dict[str, Any]
    benchmark_code_commit: str
    paths: Strict6Paths
    training_ready: bool
    readiness_failures: tuple[str, ...]


def strict6_paths(repository_root: str | Path, run_id: str) -> Strict6Paths:
    """Return dedicated immutable paths without touching historical protocols."""
    root = Path(repository_root).resolve()
    safe_id = _safe_run_id(run_id)
    reports = root / "reports" / "experiments" / EXPERIMENT_NAME / safe_id
    artifacts = root / "artifacts" / EXPERIMENT_NAME / safe_id
    return Strict6Paths(
        run_id=safe_id, reports_directory=reports, artifact_directory=artifacts,
        experiment_config_json=reports / "experiment_config.json",
        environment_json=reports / "environment.json",
        source_provenance_json=reports / "source_provenance.json",
        strict_schema_json=reports / "strict6_schema.json",
        mirror_stability_csv=reports / "mirror_stability.csv",
        distribution_shift_csv=reports / "distribution_shift.csv",
        metrics_json=reports / "metrics.json", comparison_csv=reports / "comparison.csv",
        run_summary_markdown=reports / "run_summary.md",
    )


def load_strict6_configuration(path: str | Path) -> dict[str, Any]:
    """Load the tracked frozen design; no mutable library defaults are used."""
    with Path(path).open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle)
    if not isinstance(payload, dict):
        raise Strict6Error("STRICT6 configuration must be a mapping")
    validate_strict6_configuration(payload)
    return payload


def validate_strict6_configuration(config: dict[str, Any]) -> None:
    """Reject changes that would silently alter this fixed initial experiment."""
    if config.get("experiment") != EXPERIMENT_NAME:
        raise Strict6Error("Unexpected cross-dataset experiment name")
    if tuple(config.get("strict_feature_order", ())) != STRICT_FEATURES:
        raise Strict6Error("STRICT6 feature order differs from frozen alignment metadata")
    if config.get("strict_schema_version") != STRICT6_SCHEMA_VERSION:
        raise Strict6Error("Unexpected STRICT6 schema version")
    source = config.get("cic_source", {})
    if source.get("filename") != "PDFMalware2022.csv" or source.get("sha256") != CIC_CSV_SHA256:
        raise Strict6Error("STRICT6 requires the explicitly selected CIC CSV candidate and checksum")
    if source.get("source_type") != "third-party mirror" or source.get("fidelity_status") != "TRANSFORMED":
        raise Strict6Error("CIC source provenance must retain third-party/TRANSFORMED status")
    if config.get("rit_sha256") != RIT_DATASET_SHA256:
        raise Strict6Error("Unexpected verified RIT dataset checksum")
    if config.get("split_seed") != SPLIT_SEED or config.get("model_random_state") != MODEL_RANDOM_STATE:
        raise Strict6Error("STRICT6 seeds are fixed at 42")
    if tuple(config.get("tracks", ())) != TRACK_NAMES or tuple(config.get("models", ())) != MODEL_NAMES:
        raise Strict6Error("STRICT6 must contain the frozen four tracks and five model families")
    if config.get("expected_result_count") != 20:
        raise Strict6Error("STRICT6 expected result matrix must be 4 x 5 = 20")
    if config.get("cic_csv_strict6_source_columns") != CSV_STRICT6_SOURCE_COLUMNS:
        raise Strict6Error("CIC CSV STRICT6 source-column metadata differs from the committed alignment decision")


def _strict_schema_from_report(cic_report: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    """Consume only v2 alignment metadata and assert it has not drifted."""
    report = build_mapping_resolution_report(cic_report)
    records = tuple(report["common_strict_v2"])
    if tuple(record["canonical_name"] for record in records) != STRICT_FEATURES:
        raise Strict6Error("Committed alignment metadata no longer resolves to the frozen six features")
    if any(record["status"] != AlignmentStatus.EXACT.value for record in records):
        raise Strict6Error("Every STRICT6 feature must have EXACT alignment status")
    if len(records) != 6 or len({record["rit_column"] for record in records}) != 6:
        raise Strict6Error("STRICT6 alignment metadata is incomplete or ambiguous")
    return records


def _resolve_cic_columns(
    frame: pd.DataFrame, records: Iterable[dict[str, Any]], source_overrides: dict[str, str] | None = None,
) -> dict[str, str]:
    """Map a CIC mirror through alignment records, allowing only normalized header spelling changes."""
    by_normalized: dict[str, list[str]] = {}
    for column in frame.columns:
        by_normalized.setdefault(_normalise_name(str(column)), []).append(str(column))
    result: dict[str, str] = {}
    for record in records:
        expected = str((source_overrides or {}).get(record["canonical_name"], record["cic_column"]))
        exact = [str(column) for column in frame.columns if str(column) == expected]
        candidates = exact or by_normalized.get(_normalise_name(expected), [])
        if len(candidates) != 1:
            raise Strict6Error(
                f"CIC source cannot deterministically resolve aligned column {expected!r}: {candidates}"
            )
        result[record["canonical_name"]] = candidates[0]
    if tuple(result) != STRICT_FEATURES:
        raise Strict6Error("CIC source mapping did not preserve canonical STRICT6 order")
    return result


def _parse_numeric_strict(
    series: pd.Series, source_name: str, canonical_name: str, *, allow_invalid: bool = False,
) -> tuple[pd.Series, str | None]:
    """Use only total lexical numeric parsing; never coerce malformed values or drop rows."""
    if series.isna().any():
        message = f"{source_name} {canonical_name} contains actual NaN before parsing"
        if not allow_invalid:
            raise Strict6Error(message)
        return pd.to_numeric(series, errors="coerce").astype("float64"), message
    try:
        values = pd.to_numeric(series, errors="raise")
    except (TypeError, ValueError) as error:
        message = f"{source_name} {canonical_name} has unresolved non-numeric values"
        if not allow_invalid:
            raise Strict6Error(message) from error
        return pd.to_numeric(series, errors="coerce").astype("float64"), message
    values = pd.Series(values, index=series.index, dtype="float64")
    if values.isna().any() or not np.isfinite(values.to_numpy()).all():
        message = f"{source_name} {canonical_name} produces NaN or infinity during numeric validation"
        if not allow_invalid:
            raise Strict6Error(message)
        return values, message
    return values, None


def _safe_identifier(source_sha256: str, raw_value: Any) -> str:
    value = str(raw_value).strip()
    return hashlib.sha256(f"{source_sha256}\0{value}".encode("utf-8")).hexdigest()


def _mirror_match_identifier(raw_value: Any) -> str:
    """Redact a raw CIC identifier while retaining equality across reviewed mirrors."""
    return hashlib.sha256(f"cic-mirror-match-v1\0{str(raw_value).strip()}".encode("utf-8")).hexdigest()


def _view_checksum(features: pd.DataFrame, labels: pd.Series, identifiers: pd.Series) -> str:
    """Hash selected records, labels, canonical feature values and a stable safe order."""
    ordered = pd.DataFrame({"sample_id": identifiers.astype(str), TARGET_COLUMN: labels.astype(int)})
    for column in STRICT_FEATURES:
        ordered[column] = features[column].astype(float)
    ordered = ordered.sort_values("sample_id", kind="mergesort")
    digest = hashlib.sha256()
    digest.update(("sample_id," + TARGET_COLUMN + "," + ",".join(STRICT_FEATURES) + "\n").encode())
    for row in ordered.itertuples(index=False, name=None):
        pieces = [str(row[0]), str(int(row[1])), *(format(float(value), ".17g") for value in row[2:])]
        digest.update((",".join(pieces) + "\n").encode())
    return digest.hexdigest()


def canonicalize_cic_strict6(
    frame: pd.DataFrame,
    source_path: str | Path,
    schema_records: Sequence[dict[str, Any]],
    *,
    expected_rows: int | None = None,
    expected_counts: dict[int, int] | None = None,
    source_overrides: dict[str, str] | None = None,
    allow_invalid_strict_features: bool = False,
) -> CanonicalDatasetView:
    """Create the read-only CIC analysis view using explicit raw target semantics."""
    source = Path(source_path)
    report = validate_cic_pdfmal(frame, source)
    target = report["target"]["candidate_column"]
    if target is None:
        raise Strict6Error("CIC target could not be identified from its actual schema")
    identifiers = [name for name, role in report["column_roles"].items() if role["classification"] == "identifier"]
    if len(identifiers) != 1:
        raise Strict6Error("CIC requires exactly one safe identifier source for canonical ordering")
    source_columns = _resolve_cic_columns(frame, schema_records, source_overrides)
    for canonical, column in source_columns.items():
        role = report["column_roles"][column]["classification"]
        if role != "candidate_predictive_feature" or column == target or column in identifiers:
            raise Strict6Error(f"CIC {canonical} resolves to a non-predictive, target, or identifier field")
    raw_labels = frame[target].astype("string")
    normalized = raw_labels.str.strip().str.casefold()
    valid = normalized.isin({"benign", "malicious"})
    labels = normalized.loc[valid].map({"benign": 0, "malicious": 1}).astype(int)
    parsed = {
        canonical: _parse_numeric_strict(frame.loc[valid, column], "CIC", canonical, allow_invalid=allow_invalid_strict_features)
        for canonical, column in source_columns.items()
    }
    features = pd.DataFrame({canonical: values.to_numpy(copy=False) for canonical, (values, _) in parsed.items()}, index=labels.index)
    numeric_errors = tuple(error for _, error in parsed.values() if error is not None)
    source_sha256 = sha256_file(source)


    safe_ids = frame.loc[valid, identifiers[0]].map(_mirror_match_identifier).astype(str)
    if not safe_ids.is_unique:
        raise Strict6Error("CIC safe identifiers are not unique; refusing an ambiguous canonical view")
    view = CanonicalDatasetView(
        name="CIC-Evasive-PDFMal2022 CSV mirror", source_path=source.resolve(), source_sha256=source_sha256,
        features=features.reset_index(drop=True), labels=labels.reset_index(drop=True),
        safe_sample_ids=safe_ids.reset_index(drop=True), source_columns=source_columns,
        target_column=str(target), raw_label_mapping={"Benign": 0, "Malicious": 1},
        canonical_view_sha256="", excluded_invalid_target_rows=int((~valid).sum()),
        numeric_validation_errors=numeric_errors,
    )
    checksum = _view_checksum(view.features, view.labels, view.safe_sample_ids)
    view = CanonicalDatasetView(**{**view.__dict__, "canonical_view_sha256": checksum})
    if expected_rows is not None and len(view.labels) != expected_rows:
        raise Strict6Error(f"Canonical CIC view has {len(view.labels)} rows; expected {expected_rows}")
    if expected_counts is not None and view.counts() != expected_counts:
        raise Strict6Error(f"Canonical CIC class counts {view.counts()} differ from expected {expected_counts}")
    return view


def canonicalize_rit_strict6(
    frame: pd.DataFrame, source_path: str | Path, schema_records: Sequence[dict[str, Any]]
) -> CanonicalDatasetView:
    """Create a numeric RIT STRICT6 view from the alignment record's RIT columns."""
    source = Path(source_path)
    if TARGET_COLUMN not in frame.columns:
        raise Strict6Error(f"RIT target {TARGET_COLUMN!r} is absent")
    if not frame[TARGET_COLUMN].isin((0, 1)).all():
        raise Strict6Error("RIT STRICT6 requires Label values exactly 0 or 1")
    source_columns = {record["canonical_name"]: record["rit_column"] for record in schema_records}
    if tuple(source_columns) != STRICT_FEATURES or any(column not in frame.columns for column in source_columns.values()):
        raise Strict6Error("RIT source cannot resolve frozen STRICT6 alignment columns")
    if TARGET_COLUMN in source_columns.values():
        raise Strict6Error("RIT STRICT6 mapping contains the target field")
    parsed = {canonical: _parse_numeric_strict(frame[column], "RIT", canonical) for canonical, column in source_columns.items()}
    features = pd.DataFrame({canonical: values.to_numpy(copy=False) for canonical, (values, _) in parsed.items()})
    digest = sha256_file(source)


    identifiers = build_deterministic_sample_ids(frame).astype(str).reset_index(drop=True)
    view = CanonicalDatasetView(
        name="RIT-PDFMal-2026", source_path=source.resolve(), source_sha256=digest,
        features=features, labels=frame[TARGET_COLUMN].astype(int).reset_index(drop=True), safe_sample_ids=identifiers,
        source_columns=source_columns, target_column=TARGET_COLUMN, raw_label_mapping={"0": 0, "1": 1},
        canonical_view_sha256="",
    )
    return CanonicalDatasetView(**{**view.__dict__, "canonical_view_sha256": _view_checksum(view.features, view.labels, view.safe_sample_ids)})


def mirror_stability_report(csv_view: CanonicalDatasetView, parquet_view: CanonicalDatasetView) -> list[dict[str, Any]]:
    """Compare only STRICT6 values on identifier-matched CIC records without leaking identifiers."""
    left = pd.DataFrame({"sample_id": csv_view.safe_sample_ids, **{f"csv_{name}": csv_view.features[name] for name in STRICT_FEATURES}})
    right = pd.DataFrame({"sample_id": parquet_view.safe_sample_ids, **{f"parquet_{name}": parquet_view.features[name] for name in STRICT_FEATURES}})
    shared = left.merge(right, on="sample_id", how="inner", validate="one_to_one")
    rows: list[dict[str, Any]] = []
    for canonical in STRICT_FEATURES:
        csv_values, parquet_values = shared[f"csv_{canonical}"], shared[f"parquet_{canonical}"]
        equal = csv_values.eq(parquet_values)
        mismatch = int((~equal).sum())
        transitions = (
            pd.DataFrame({"csv_value": csv_values.loc[~equal], "parquet_value": parquet_values.loc[~equal]})
            .value_counts().head(8)
        )
        summary = [
            {"csv_value": format(float(index[0]), ".17g"), "parquet_value": format(float(index[1]), ".17g"), "count": int(count)}
            for index, count in transitions.items()
        ]
        status = "MIRROR_STABLE" if mismatch == 0 else "MIRROR_UNSTABLE"
        rows.append({
            "canonical_name": canonical, "csv_source_column": csv_view.source_columns[canonical],
            "parquet_source_column": parquet_view.source_columns[canonical], "comparable_record_count": int(len(shared)),
            "exact_equality_count": int(equal.sum()), "mismatch_count": mismatch,
            "mismatch_percentage": 0.0 if len(shared) == 0 else 100.0 * mismatch / len(shared),
            "classification": status,
            "csv_dtype": str(csv_view.features[canonical].dtype), "parquet_dtype": str(parquet_view.features[canonical].dtype),
            "representation_difference": "CSV lexical numeric values are parsed only after total validation; Parquet uses native numeric values.",
            "mismatch_value_summary": summary,
            "identifier_redaction": "Raw FileName/hash-like identifiers are never serialized; matching uses one-way research-safe identifiers.",
        })
    return rows


def _ks_statistic(left: pd.Series, right: pd.Series) -> float:
    """Small dependency-free two-sample KS statistic for descriptive use only."""
    a, b = np.sort(left.to_numpy(dtype=float)), np.sort(right.to_numpy(dtype=float))
    points = np.sort(np.concatenate([a, b]))
    return float(np.max(np.abs(np.searchsorted(a, points, side="right") / len(a) - np.searchsorted(b, points, side="right") / len(b))))


def descriptive_distribution_shift(rit: CanonicalDatasetView, cic: CanonicalDatasetView) -> list[dict[str, Any]]:
    """Calculate non-target-dependent STRICT6 distribution summaries; do not select features."""
    rows: list[dict[str, Any]] = []
    for feature in STRICT_FEATURES:
        rit_values, cic_values = rit.features[feature], cic.features[feature]
        rows.append({
            "canonical_name": feature,
            "rit_min": float(rit_values.min()), "rit_max": float(rit_values.max()), "rit_mean": float(rit_values.mean()),
            "rit_median": float(rit_values.median()), "rit_standard_deviation": float(rit_values.std(ddof=1)),
            "rit_q25": float(rit_values.quantile(.25)), "rit_q75": float(rit_values.quantile(.75)), "rit_zero_fraction": float((rit_values == 0).mean()),
            "cic_min": float(cic_values.min()), "cic_max": float(cic_values.max()), "cic_mean": float(cic_values.mean()),
            "cic_median": float(cic_values.median()), "cic_standard_deviation": float(cic_values.std(ddof=1)),
            "cic_q25": float(cic_values.quantile(.25)), "cic_q75": float(cic_values.quantile(.75)), "cic_zero_fraction": float((cic_values == 0).mean()),
            "ks_statistic_descriptive_only": _ks_statistic(rit_values, cic_values),
        })
    return rows


def deterministic_within_split(view: CanonicalDatasetView, *, seed: int = SPLIT_SEED) -> dict[str, Any]:
    """Make a row-level stratified 75/25 control split using safe IDs, not dataframe indexes."""
    if not view.safe_sample_ids.is_unique:
        raise Strict6Error("Within-domain split requires unique deterministic sample identifiers")
    identifiers = view.safe_sample_ids.to_numpy(copy=False)
    train_ids, test_ids = train_test_split(identifiers, test_size=.25, random_state=seed, shuffle=True, stratify=view.labels.to_numpy(copy=False))
    train_set = set(train_ids)
    assignment = pd.Series(np.where(view.safe_sample_ids.isin(train_set), "train", "test"))
    if int((assignment == "train").sum() + (assignment == "test").sum()) != len(view.labels):
        raise Strict6Error("Within-domain split did not assign every row exactly once")
    if set(train_ids).intersection(test_ids):
        raise Strict6Error("Within-domain train/test split overlaps")
    statistics: dict[str, dict[str, int]] = {}
    for name in ("train", "test"):
        labels = view.labels.loc[assignment == name]
        statistics[name] = {"rows": int(len(labels)), "benign": int((labels == 0).sum()), "malicious": int((labels == 1).sum())}
        if set(labels.unique()) != {0, 1}:
            raise Strict6Error("Within-domain split lost a class despite required stratification")
    return {"assignment": assignment, "seed": seed, "statistics": statistics, "row_level_stratified": True}


def _output_available(paths: Strict6Paths) -> bool:
    if paths.reports_directory.exists() or paths.artifact_directory.exists():
        return False
    forbidden = {"protocol_p", "protocol_g", "multiseed", "xgb_cv10"}
    return not (set(part.casefold() for part in paths.reports_directory.parts) & forbidden)


def _assert_training_ready(preflight: Strict6Preflight) -> None:
    if not preflight.training_ready:
        raise Strict6Error("STRICT6 training readiness failed: " + "; ".join(preflight.readiness_failures))


def preflight_cross_dataset_strict6(
    repository_root: str | Path,
    rit_path: str | Path,
    cic_csv_path: str | Path,
    cic_parquet_path: str | Path,
    config: dict[str, Any],
    *,
    run_id: str = "seed42",
    require_clean_git: bool = True,
    require_training_ready: bool = True,
) -> Strict6Preflight:
    """Validate source, schema, mirror and output invariants without fitting a classifier."""
    validate_strict6_configuration(config)
    root, rit_file, csv_file, parquet_file = (Path(repository_root).resolve(), Path(rit_path).resolve(), Path(cic_csv_path).resolve(), Path(cic_parquet_path).resolve())
    state = repository_git_state(root)
    if require_clean_git and state.get("status") != "clean":
        raise Strict6Error("Refusing official STRICT6 preflight because repository is not clean")
    paths = strict6_paths(root, run_id)
    if not _output_available(paths):
        raise Strict6Error("STRICT6 output path is unavailable or overlaps a historical experiment")
    if sha256_file(rit_file) != RIT_DATASET_SHA256:
        raise Strict6Error("RIT SHA-256 does not match the verified dataset")
    if sha256_file(csv_file) != CIC_CSV_SHA256 or sha256_file(parquet_file) != CIC_PARQUET_SHA256:
        raise Strict6Error("CIC source checksum does not match the reviewed source-fidelity candidates")
    rit_frame, csv_frame, parquet_frame = load_rit_pdfmal(rit_file), load_cic_pdfmal(csv_file), load_cic_pdfmal(parquet_file)
    schema = _strict_schema_from_report(validate_cic_pdfmal(parquet_frame, parquet_file))
    rit = canonicalize_rit_strict6(rit_frame, rit_file, schema)
    cic = canonicalize_cic_strict6(csv_frame, csv_file, schema, expected_rows=CIC_EXPECTED_ROWS, expected_counts=CIC_EXPECTED_COUNTS, source_overrides=config["cic_csv_strict6_source_columns"], allow_invalid_strict_features=True)
    cic_parquet = canonicalize_cic_strict6(parquet_frame, parquet_file, schema, allow_invalid_strict_features=True)
    stability = mirror_stability_report(cic, cic_parquet)
    failures = tuple(cic.numeric_validation_errors + cic_parquet.numeric_validation_errors) + tuple(
        f"{item['canonical_name']}={item['classification']}" for item in stability
        if item["classification"] not in {"MIRROR_STABLE", "MIRROR_DIFFERENT_BUT_EXPLAINED"}
    )
    splits = {"within_rit": deterministic_within_split(rit), "within_cic": deterministic_within_split(cic)}
    environment = collect_environment_metadata(rit_file, root)
    environment["datasets"] = {
        "rit": {"filename": rit_file.name, "sha256": rit.source_sha256, "canonical_strict6_view_sha256": rit.canonical_view_sha256},
        "cic_csv": {"filename": csv_file.name, "sha256": cic.source_sha256, "canonical_strict6_view_sha256": cic.canonical_view_sha256},
        "cic_parquet": {"filename": parquet_file.name, "sha256": cic_parquet.source_sha256, "canonical_strict6_view_sha256": cic_parquet.canonical_view_sha256},
    }
    commit = str(environment.get("git_commit_sha", "unavailable"))
    if require_clean_git and (commit == "unavailable" or len(commit) != 40):
        raise Strict6Error("Unable to record a full benchmark-generating Git commit")
    result = Strict6Preflight(
        repository_root=root, rit=rit, cic=cic, cic_parquet=cic_parquet, schema_records=schema,
        mirror_stability=tuple(stability), distribution_shift=tuple(descriptive_distribution_shift(rit, cic)) if not (rit.numeric_validation_errors or cic.numeric_validation_errors) else (),
        within_splits=splits, config=config, environment=environment, benchmark_code_commit=commit,
        paths=paths, training_ready=not failures, readiness_failures=failures,
    )
    if require_training_ready:
        _assert_training_ready(result)
    return result


def _track_frames(preflight: Strict6Preflight, track: str) -> tuple[pd.DataFrame, pd.Series, pd.DataFrame, pd.Series]:
    if track == "within_rit":
        split, view = preflight.within_splits[track], preflight.rit
    elif track == "within_cic":
        split, view = preflight.within_splits[track], preflight.cic
    elif track == "rit_to_cic":
        return preflight.rit.features, preflight.rit.labels, preflight.cic.features, preflight.cic.labels
    elif track == "cic_to_rit":
        return preflight.cic.features, preflight.cic.labels, preflight.rit.features, preflight.rit.labels
    else:
        raise Strict6Error(f"Unknown STRICT6 track: {track}")
    mask = split["assignment"] == "train"
    return view.features.loc[mask], view.labels.loc[mask], view.features.loc[~mask], view.labels.loc[~mask]


def _counts(metrics: dict[str, Any]) -> dict[str, int]:
    matrix = metrics["confusion_matrix"]
    return {"tn": int(matrix[0][0]), "fp": int(matrix[0][1]), "fn": int(matrix[1][0]), "tp": int(matrix[1][1])}


def _create_outputs(paths: Strict6Paths) -> None:
    if not _output_available(paths):
        raise FileExistsError(f"STRICT6 run already exists; refusing to overwrite: {paths.run_id}")
    paths.reports_directory.mkdir(parents=True, exist_ok=False)
    paths.artifact_directory.mkdir(parents=True, exist_ok=False)
    (paths.artifact_directory / "models").mkdir(parents=True, exist_ok=False)


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def _source_provenance(preflight: Strict6Preflight) -> dict[str, Any]:
    return {
        "rit": {"filename": preflight.rit.source_path.name, "sha256": preflight.rit.source_sha256, "rows": len(preflight.rit.labels)},
        "cic": {
            "filename": preflight.cic.source_path.name, "sha256": preflight.cic.source_sha256,
            "source_type": "third-party mirror", "fidelity_status": "TRANSFORMED",
            "pseudo_row_exclusion_rule": "Only raw Class values mapping explicitly to Benign or Malicious are selected.",
            "excluded_invalid_target_rows": preflight.cic.excluded_invalid_target_rows,
            "canonical_rows": len(preflight.cic.labels), "canonical_class_counts": preflight.cic.counts(),
            "canonical_strict6_view_sha256": preflight.cic.canonical_view_sha256,
        },
        "identifier_safety": "Raw CIC FileName/hash-like values are not serialized in tracked outputs.",
    }


def _summary(records: Sequence[dict[str, Any]], track: str) -> pd.DataFrame:
    rows = []
    for record in records:
        if record["track"] != track:
            continue
        rows.append({
            "model": record["model"], "track": track, "feature_schema": STRICT6_SCHEMA_VERSION,
            **{name: record["metrics"].get(name) for name in METRIC_NAMES}, **record["confusion_counts"],
            **{name: record["runtime"].get(name) for name in RUNTIME_NAMES}, "score_source": record["metrics"].get("score_source"),
        })
    return pd.DataFrame(rows)


def _safe_split_manifest(view: CanonicalDatasetView, split: dict[str, Any]) -> pd.DataFrame:
    """Persist reproducible assignments with one-way IDs, never raw CIC filenames."""
    return pd.DataFrame({
        "sample_id": view.safe_sample_ids.astype(str), "split": split["assignment"],
        TARGET_COLUMN: view.labels.astype(int), "seed": split["seed"],
        "canonical_strict6_view_sha256": view.canonical_view_sha256,
    })


def _comparison(records: Sequence[dict[str, Any]]) -> pd.DataFrame:
    by_key = {(record["track"], record["model"]): record for record in records}
    rows = []
    for model in MODEL_NAMES:
        for transfer, control in (("rit_to_cic", "within_rit"), ("cic_to_rit", "within_cic")):
            for metric in METRIC_NAMES:
                local, baseline = by_key[(transfer, model)]["metrics"].get(metric), by_key[(control, model)]["metrics"].get(metric)
                rows.append({"model": model, "transfer_track": transfer, "within_domain_control": control, "metric": metric,
                             "transfer_value": local, "control_value": baseline,
                             "difference_transfer_minus_control": None if local is None or baseline is None else float(local) - float(baseline),
                             "interpretation": "Performance difference across distinct test distributions; not a paired sample-level effect."})
    return pd.DataFrame(rows)


def execute_cross_dataset_strict6_from_preflight(
    preflight: Strict6Preflight, *, model_factory: Callable[[str, int], Any] = create_model
) -> tuple[Strict6Paths, list[dict[str, Any]]]:
    """Run the frozen 20-fit matrix only after explicit, successful preflight."""
    _assert_training_ready(preflight)
    _create_outputs(preflight.paths)
    records: list[dict[str, Any]] = []
    for track in TRACK_NAMES:
        train_features, train_labels, test_features, test_labels = _track_frames(preflight, track)
        for model in MODEL_NAMES:
            set_random_seed(MODEL_RANDOM_STATE)
            estimator = model_factory(model, MODEL_RANDOM_STATE)
            predictions, scores, score_source, runtime = fit_predict_and_measure(estimator, train_features, train_labels, test_features)
            metrics = evaluate_binary_predictions(test_labels, predictions, scores)
            metrics["score_source"] = score_source
            record = {
                "timestamp_utc": _timestamp(), "track": track, "model": model, "feature_schema": STRICT6_SCHEMA_VERSION,
                "feature_order": list(STRICT_FEATURES), "train_rows": len(train_labels), "test_rows": len(test_labels),
                "model_configuration": model_configurations(MODEL_RANDOM_STATE)[model], "metrics": metrics,
                "confusion_counts": _counts(metrics), "runtime": runtime, "benchmark_generating_code_commit": preflight.benchmark_code_commit,
            }
            records.append(record)
            joblib.dump(estimator, preflight.paths.artifact_directory / "models" / f"{track}__{model}.joblib")
    _write_json(preflight.paths.environment_json, preflight.environment)
    _write_json(preflight.paths.source_provenance_json, _source_provenance(preflight))
    _write_json(preflight.paths.strict_schema_json, {"version": STRICT6_SCHEMA_VERSION, "feature_order": list(STRICT_FEATURES), "alignment_records": list(preflight.schema_records)})
    _write_json(preflight.paths.experiment_config_json, {"config": preflight.config, "benchmark_generating_code_commit": preflight.benchmark_code_commit, "git_working_tree_at_start": preflight.environment["git_working_tree"], "scope": "Direct STRICT6 transfer; no domain adaptation, target-dataset fitting, tuning, or threshold selection."})
    pd.DataFrame(preflight.mirror_stability).to_csv(preflight.paths.mirror_stability_csv, index=False)
    pd.DataFrame(preflight.distribution_shift).to_csv(preflight.paths.distribution_shift_csv, index=False)
    for track in TRACK_NAMES:
        _summary(records, track).to_csv(preflight.paths.summary_csv(track), index=False)
    _safe_split_manifest(preflight.rit, preflight.within_splits["within_rit"]).to_csv(preflight.paths.split_manifest_csv("within_rit"), index=False)
    _safe_split_manifest(preflight.cic, preflight.within_splits["within_cic"]).to_csv(preflight.paths.split_manifest_csv("within_cic"), index=False)
    _comparison(records).to_csv(preflight.paths.comparison_csv, index=False)
    _write_json(preflight.paths.metrics_json, {"experiment": EXPERIMENT_NAME, "records": records})
    preflight.paths.run_summary_markdown.write_text(
        "\n".join(["# STRICT6 cross-dataset benchmark run", "", f"- Run ID: `{preflight.paths.run_id}`.", f"- Benchmark-generating code commit: `{preflight.benchmark_code_commit}`.", "- This is strict six-feature transfer, not full-detector, temporal, file-disjoint, or dynamic-analysis evidence.", "- R2C is the primary direction. No target-domain fitting or adaptation was used.", f"- Completed records: {len(records)} (four tracks × five fixed models).", ""]), encoding="utf-8")
    return preflight.paths, records


def run_cross_dataset_strict6(
    repository_root: str | Path, rit_path: str | Path, cic_csv_path: str | Path, cic_parquet_path: str | Path, config_path: str | Path,
    *, run_id: str = "seed42", execute: bool = False, require_clean_git: bool = True,
) -> tuple[Strict6Preflight, Strict6Paths | None, list[dict[str, Any]]]:
    """Dry-run by default; model fitting requires explicit future ``--execute`` use."""
    preflight = preflight_cross_dataset_strict6(repository_root, rit_path, cic_csv_path, cic_parquet_path, load_strict6_configuration(config_path), run_id=run_id, require_clean_git=require_clean_git, require_training_ready=True)
    if not execute:
        return preflight, None, []
    paths, records = execute_cross_dataset_strict6_from_preflight(preflight)
    return preflight, paths, records

"""Executable, single-seed benchmark layer for RIT-PDFMal-2026 Protocol P.

This module implements the paper-aligned 5-model by 2-feature-variant matrix.
It is deliberately not an exact reproduction: the paper does not publish its
split seed, complete preprocessing choices, or model hyperparameters. It never
regenerates a split; a previously saved Protocol P manifest is required.
"""

from __future__ import annotations

import json
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

import joblib
import pandas as pd

from malpdf.data.protocol_p import (
    DEFAULT_PROTOCOL_P_SEED,
    FEATURE_VARIANTS,
    P_ALL41,
    P_DROP3CONSTANT,
    TARGET_COLUMN,
    protocol_p_feature_view,
    validate_protocol_p_manifest,
)
from malpdf.data.rit_pdfmal import load_rit_pdfmal, sha256_file
from malpdf.data.rit_pdfmal_paper_alignment import PAPER_BASELINE_RESULTS
from malpdf.data.rit_pdfmal_split import build_deterministic_sample_ids
from malpdf.evaluation.binary import evaluate_binary_predictions, fit_predict_and_measure
from malpdf.experiments.protocol_p import collect_environment_metadata, repository_git_state
from malpdf.models.classical import MODEL_NAMES, create_model, model_configurations
from malpdf.reproducibility import set_random_seed

PROTOCOL_NAME = "P"
PAPER_MODEL_NAMES = {
    "logistic_regression": "LR",
    "random_forest": "RF",
    "decision_tree": "DT",
    "gaussian_naive_bayes": "GNB",
    "xgboost": "XGB",
}
PAPER_COMPARISON_METRICS = (
    ("accuracy", "accuracy"),
    ("precision", "precision"),
    ("recall", "recall"),
    ("f1", "f1"),
    ("test_inference_milliseconds_per_sample", "inference_time_ms"),
)


class ProtocolPBenchmarkError(RuntimeError):
    """Raised when the benchmark cannot safely execute all requested runs."""


@dataclass(frozen=True)
class BenchmarkRunSpec:
    """One model and feature-variant combination in a benchmark matrix."""

    model_name: str
    feature_variant: str

    @property
    def identifier(self) -> str:
        return f"{self.model_name}__{self.feature_variant}"


PRIMARY_BENCHMARK_MATRIX = tuple(
    BenchmarkRunSpec(model_name, feature_variant)
    for model_name in MODEL_NAMES
    for feature_variant in (P_ALL41.name, P_DROP3CONSTANT.name)
)


@dataclass(frozen=True)
class ProtocolPBenchmarkPaths:
    """Separate tracked reports and ignored binary-model locations for one run."""

    run_id: str
    reports_directory: Path
    artifact_directory: Path
    model_artifacts_directory: Path
    summary_csv: Path
    metrics_json: Path
    paper_comparison_csv: Path
    environment_json: Path
    experiment_config_json: Path
    split_summary_json: Path
    run_summary_markdown: Path


def _timestamp_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_run_id(run_id: str) -> str:
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
    if not run_id or any(character not in allowed for character in run_id):
        raise ValueError("run_id must be non-empty and contain only letters, numbers, '-', '_', or '.'")
    return run_id


def protocol_p_benchmark_paths(
    repository_root: str | Path, run_id: str
) -> ProtocolPBenchmarkPaths:
    """Return immutable locations without touching Protocol G locations."""
    root = Path(repository_root)
    safe_id = _safe_run_id(run_id)
    reports = root / "reports" / "experiments" / "protocol_p" / safe_id
    artifacts = root / "artifacts" / "protocol_p" / safe_id
    return ProtocolPBenchmarkPaths(
        run_id=safe_id,
        reports_directory=reports,
        artifact_directory=artifacts,
        model_artifacts_directory=artifacts / "models",
        summary_csv=reports / "summary.csv",
        metrics_json=reports / "metrics.json",
        paper_comparison_csv=reports / "paper_comparison.csv",
        environment_json=reports / "environment.json",
        experiment_config_json=reports / "experiment_config.json",
        split_summary_json=reports / "split_summary.json",
        run_summary_markdown=reports / "run_summary.md",
    )


def _read_manifest(path: Path) -> pd.DataFrame:
    if not path.is_file():
        raise FileNotFoundError(f"Protocol P split manifest not found: {path}")
    return pd.read_csv(path)


def _manifest_metadata_matches(
    manifest: pd.DataFrame, dataset_sha256: str, seed: int
) -> bool:
    required = {"sample_id", "split", TARGET_COLUMN, "seed", "dataset_sha256"}
    if not required.issubset(manifest.columns):
        return False
    hashes = set(manifest["dataset_sha256"].astype(str))
    try:
        seeds = {int(value) for value in manifest["seed"]}
    except (TypeError, ValueError):
        return False
    return hashes == {dataset_sha256} and seeds == {seed}


def _canonical_assignment(manifest: pd.DataFrame) -> pd.DataFrame:
    columns = ["sample_id", "split", TARGET_COLUMN, "seed", "dataset_sha256"]
    return (
        manifest.loc[:, columns]
        .assign(sample_id=lambda frame: frame["sample_id"].astype(str))
        .sort_values("sample_id", kind="stable")
        .reset_index(drop=True)
    )


def resolve_saved_protocol_p_manifest(
    repository_root: str | Path,
    dataset_sha256: str,
    seed: int,
    manifest_path: str | Path | None = None,
) -> Path:
    """Resolve an existing, matching Protocol P manifest without regenerating it.

    With no explicit path, multiple saved candidates are accepted only if their
    complete sample assignments agree. This avoids silently selecting a different
    split when future runs use the same seed.
    """
    root = Path(repository_root).resolve()
    processed_root = (root / "data" / "processed" / "protocol_p").resolve()
    if manifest_path is not None:
        selected = Path(manifest_path).resolve()
        if not selected.is_relative_to(processed_root):
            raise ProtocolPBenchmarkError(
                "Protocol P benchmark manifests must be below data/processed/protocol_p"
            )
        candidates = [selected]
    else:
        candidates = sorted(processed_root.glob("*/protocol_p_split_manifest.csv"))

    matching: list[tuple[Path, pd.DataFrame]] = []
    for candidate in candidates:
        manifest = _read_manifest(candidate)
        if _manifest_metadata_matches(manifest, dataset_sha256, seed):
            matching.append((candidate, manifest))
    if not matching:
        raise FileNotFoundError(
            "No saved Protocol P manifest matches this dataset checksum and seed; "
            "run scripts/prepare_protocol_p.py explicitly before benchmarking."
        )

    expected = _canonical_assignment(matching[0][1])
    for candidate, manifest in matching[1:]:
        if not expected.equals(_canonical_assignment(manifest)):
            raise ProtocolPBenchmarkError(
                "Multiple saved Protocol P manifests match the requested metadata but "
                f"assign rows differently; select an explicit manifest. Conflicting path: {candidate}"
            )
    return matching[0][0]


def load_saved_protocol_p_split(
    frame: pd.DataFrame,
    dataset_sha256: str,
    seed: int,
    repository_root: str | Path,
    manifest_path: str | Path | None = None,
) -> tuple[Path, pd.DataFrame, dict[str, Any]]:
    """Load, checksum-check, and validate the already persisted Protocol P split."""
    selected = resolve_saved_protocol_p_manifest(
        repository_root, dataset_sha256, seed, manifest_path
    )
    manifest = _read_manifest(selected)
    if not _manifest_metadata_matches(manifest, dataset_sha256, seed):
        raise ProtocolPBenchmarkError("Saved Protocol P manifest metadata does not match the request")
    validation = validate_protocol_p_manifest(frame, manifest)
    return selected, manifest, validation


def split_frame_from_manifest(
    frame: pd.DataFrame, manifest: pd.DataFrame
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Partition an in-memory frame using saved sample IDs, never its row index."""
    sample_ids = build_deterministic_sample_ids(frame).astype(str)
    train_ids = set(manifest.loc[manifest["split"] == "train", "sample_id"].astype(str))
    test_ids = set(manifest.loc[manifest["split"] == "test", "sample_id"].astype(str))
    train_mask = sample_ids.isin(train_ids)
    test_mask = sample_ids.isin(test_ids)
    if bool((train_mask & test_mask).any()) or int(train_mask.sum() + test_mask.sum()) != len(frame):
        raise ProtocolPBenchmarkError("Saved Protocol P manifest does not partition the dataset exactly once")
    return frame.loc[train_mask].copy(), frame.loc[test_mask].copy()


def _split_summary(
    manifest_path: Path, manifest: pd.DataFrame, validation: dict[str, Any], seed: int
) -> dict[str, Any]:
    return {
        "protocol": PROTOCOL_NAME,
        "split_manifest": str(manifest_path),
        "split_seed": seed,
        "split_sizes": validation["stratification"]["split_statistics"],
        "validation": validation,
        "manifest_row_count": int(len(manifest)),
    }


def _confusion_counts(metrics: dict[str, Any]) -> dict[str, int]:
    matrix = metrics["confusion_matrix"]
    return {
        "tn": int(matrix[0][0]),
        "fp": int(matrix[0][1]),
        "fn": int(matrix[1][0]),
        "tp": int(matrix[1][1]),
    }


def build_paper_comparison(
    run_records: Sequence[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Compare local metrics to the values verified in the paper-alignment audit."""
    published = {record["model"]: record for record in PAPER_BASELINE_RESULTS}
    rows: list[dict[str, Any]] = []
    for record in run_records:
        paper_model = PAPER_MODEL_NAMES[record["model_name"]]
        paper = published[paper_model]
        local_metrics = record["metrics"] or {}
        runtime = record["runtime"] or {}
        for local_name, paper_name in PAPER_COMPARISON_METRICS:
            local_value = (
                local_metrics.get(local_name)
                if local_name in local_metrics
                else runtime.get(local_name)
            )
            paper_value = paper[paper_name]
            rows.append(
                {
                    "model": record["model_name"],
                    "paper_model": paper_model,
                    "feature_variant": record["feature_variant"],
                    "metric": local_name,
                    "local_value": local_value,
                    "paper_value": paper_value,
                    "absolute_difference": (
                        None if local_value is None else abs(float(local_value) - float(paper_value))
                    ),
                    "comparison_note": (
                        "Both feature variants are shown because the paper does not specify "
                        "whether zero-variance features were removed in every reported fit."
                        if local_name != "test_inference_milliseconds_per_sample"
                        else "Runtime is recorded for reference only and is not directly comparable across hardware/software."
                    ),
                }
            )
    return rows


def _result_record(
    *,
    run_id: str,
    specification: BenchmarkRunSpec,
    feature_count: int,
    dataset_path: Path,
    dataset_sha256: str,
    seed: int,
    split_summary: dict[str, Any],
    model_configuration: dict[str, Any],
    environment: dict[str, Any],
) -> dict[str, Any]:
    return {
        "experiment_run_id": run_id,
        "protocol": PROTOCOL_NAME,
        "timestamp_utc": _timestamp_utc(),
        "status": "pending",
        "model_name": specification.model_name,
        "feature_variant": specification.feature_variant,
        "feature_count": feature_count,
        "dataset_filename": dataset_path.name,
        "dataset_sha256": dataset_sha256,
        "split_seed": seed,
        "split_manifest": split_summary["split_manifest"],
        "split_sizes": split_summary["split_sizes"],
        "model_configuration": model_configuration,
        "preprocessing_configuration": model_configuration["preprocessing"],
        "environment": environment,
        "metrics": None,
        "confusion_counts": None,
        "runtime": None,
        "model_artifact": None,
        "error": None,
    }


def benchmark_result_schema_is_valid(record: dict[str, Any]) -> bool:
    """Return whether a serialized result has the minimal research provenance."""
    required = {
        "experiment_run_id",
        "protocol",
        "timestamp_utc",
        "status",
        "model_name",
        "feature_variant",
        "feature_count",
        "dataset_filename",
        "dataset_sha256",
        "split_seed",
        "split_sizes",
        "model_configuration",
        "preprocessing_configuration",
        "environment",
        "metrics",
        "runtime",
        "error",
    }
    if not required.issubset(record) or record.get("protocol") != PROTOCOL_NAME:
        return False
    if record.get("status") == "completed":
        metric_names = {"accuracy", "precision", "recall", "f1", "roc_auc", "pr_auc", "mcc"}
        return (
            isinstance(record.get("metrics"), dict)
            and metric_names.issubset(record["metrics"])
            and isinstance(record.get("confusion_counts"), dict)
            and isinstance(record.get("runtime"), dict)
            and record.get("error") is None
        )
    return record.get("status") == "failed" and isinstance(record.get("error"), dict)


def _create_output_directories(paths: ProtocolPBenchmarkPaths) -> None:
    if paths.reports_directory.exists() or paths.artifact_directory.exists():
        raise FileExistsError(f"Benchmark run already exists; refusing to overwrite: {paths.run_id}")
    paths.reports_directory.mkdir(parents=True, exist_ok=False)
    paths.model_artifacts_directory.mkdir(parents=True, exist_ok=False)


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def _summary_rows(run_records: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in run_records:
        metrics = record["metrics"] or {}
        runtime = record["runtime"] or {}
        row = {
            "experiment_run_id": record["experiment_run_id"],
            "status": record["status"],
            "model_name": record["model_name"],
            "feature_variant": record["feature_variant"],
            "feature_count": record["feature_count"],
            **{name: metrics.get(name) for name in ("accuracy", "precision", "recall", "f1", "roc_auc", "pr_auc", "mcc")},
            **(record["confusion_counts"] or {"tn": None, "fp": None, "fn": None, "tp": None}),
            **{name: runtime.get(name) for name in ("training_seconds", "test_inference_total_seconds", "test_inference_milliseconds_per_sample")},
            "score_source": metrics.get("score_source"),
            "error_type": None if record["error"] is None else record["error"]["type"],
            "error_message": None if record["error"] is None else record["error"]["message"],
        }
        rows.append(row)
    return rows


def _run_summary_markdown(
    run_id: str, split_summary: dict[str, Any], records: Sequence[dict[str, Any]]
) -> str:
    completed = sum(record["status"] == "completed" for record in records)
    failed = len(records) - completed
    return "\n".join(
        [
            "# Protocol P benchmark run",
            "",
            f"- Run ID: `{run_id}`",
            "- Protocol: P, paper-aligned attempt; not an exact paper reproduction.",
            f"- Saved split manifest: `{split_summary['split_manifest']}`",
            f"- Project seed: `{split_summary['split_seed']}` (the paper does not publish a seed).",
            f"- Completed runs: {completed}; failed runs: {failed}.",
            "- Both P-all41 and P-drop3constant are reported because the paper's exact zero-variance handling is ambiguous.",
            "- Runtime values are environment-specific and are not direct comparisons to the paper.",
            "- No hyperparameter tuning, multi-seed experiment, or cross-validation is included.",
            "",
        ]
    )


def _write_benchmark_outputs(
    paths: ProtocolPBenchmarkPaths,
    environment: dict[str, Any],
    configuration: dict[str, Any],
    split_summary: dict[str, Any],
    records: Sequence[dict[str, Any]],
) -> None:
    _write_json(paths.environment_json, environment)
    _write_json(paths.experiment_config_json, configuration)
    _write_json(paths.split_summary_json, split_summary)
    _write_json(paths.metrics_json, {"experiment": configuration, "runs": list(records)})
    pd.DataFrame(_summary_rows(records)).to_csv(paths.summary_csv, index=False)
    pd.DataFrame(build_paper_comparison(records)).to_csv(paths.paper_comparison_csv, index=False)
    paths.run_summary_markdown.write_text(
        _run_summary_markdown(paths.run_id, split_summary, records), encoding="utf-8"
    )


def _validate_requested_specs(specifications: Sequence[BenchmarkRunSpec]) -> tuple[BenchmarkRunSpec, ...]:
    selected = tuple(specifications)
    if not selected:
        raise ValueError("At least one benchmark specification is required")
    supported = set(PRIMARY_BENCHMARK_MATRIX)
    invalid = [specification for specification in selected if specification not in supported]
    if invalid:
        raise ValueError(f"Unsupported Protocol P benchmark specifications: {invalid}")
    if len(set(selected)) != len(selected):
        raise ValueError("Benchmark specifications must not repeat a model/variant combination")
    return selected


def run_protocol_p_benchmark(
    repository_root: str | Path,
    dataset_path: str | Path,
    *,
    seed: int = DEFAULT_PROTOCOL_P_SEED,
    run_id: str | None = None,
    manifest_path: str | Path | None = None,
    require_clean_git: bool = True,
    specifications: Sequence[BenchmarkRunSpec] | None = None,
    model_factory: Callable[[str, int], Any] = create_model,
    environment_collector: Callable[[str | Path, str | Path], dict[str, Any]] = collect_environment_metadata,
) -> tuple[ProtocolPBenchmarkPaths, list[dict[str, Any]]]:
    """Run the frozen Protocol P benchmark using one previously saved split.

    The default matrix contains exactly ten primary runs. ``specifications`` is a
    test seam for synthetic fixtures; the command-line runner always uses all ten.
    Successful fitted models are written below ignored ``artifacts/`` while the
    JSON/CSV/Markdown research outputs are written below tracked ``reports/``.
    """
    root = Path(repository_root).resolve()
    data_path = Path(dataset_path).resolve()
    selected_specs = _validate_requested_specs(specifications or PRIMARY_BENCHMARK_MATRIX)
    git_state = repository_git_state(root)
    if require_clean_git and git_state["status"] != "clean":
        raise ProtocolPBenchmarkError(
            "Refusing benchmark execution because the repository is not clean: "
            f"{git_state['status']}"
        )

    set_random_seed(seed)
    frame = load_rit_pdfmal(data_path)
    if TARGET_COLUMN not in frame.columns:
        raise ProtocolPBenchmarkError(f"Expected target column {TARGET_COLUMN!r} is absent")
    dataset_sha256 = sha256_file(data_path)
    selected_manifest, manifest, validation = load_saved_protocol_p_split(
        frame, dataset_sha256, seed, root, manifest_path
    )
    train_frame, test_frame = split_frame_from_manifest(frame, manifest)
    split_summary = _split_summary(selected_manifest, manifest, validation, seed)

    identifier = run_id or f"p-benchmark-seed{seed}-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}"
    paths = protocol_p_benchmark_paths(root, identifier)
    _create_output_directories(paths)

    environment = environment_collector(data_path, root)
    environment["git_working_tree"] = git_state
    environment["benchmark_timestamp_utc"] = _timestamp_utc()
    configurations = model_configurations(seed)
    configuration = {
        "experiment_run_id": paths.run_id,
        "protocol": PROTOCOL_NAME,
        "purpose": "Single-seed paper-aligned reproduction attempt; not an exact paper reproduction.",
        "dataset": {"filename": data_path.name, "sha256": dataset_sha256},
        "split": split_summary,
        "benchmark_matrix": [
            {"model_name": specification.model_name, "feature_variant": specification.feature_variant}
            for specification in selected_specs
        ],
        "primary_matrix_run_count": len(PRIMARY_BENCHMARK_MATRIX),
        "model_configurations": {specification.model_name: configurations[specification.model_name] for specification in selected_specs},
        "paper_comparison_note": "Both feature variants are shown; neither is claimed to be the exact paper configuration because the paper leaves zero-variance handling ambiguous.",
        "methodological_constraints": [
            "The paper does not publish its random seed; this project uses configurable seed 42 by default.",
            "No hyperparameter tuning, test-set selection, threshold tuning, multi-seed evaluation, or cross-validation is performed.",
            "Label=1 is the malicious positive class.",
            "Special semantic values are preserved without imputation, clipping, normalization, or reinterpretation.",
        ],
        "environment": environment,
    }

    records: list[dict[str, Any]] = []
    failures: list[str] = []
    for specification in selected_specs:
        feature_columns = protocol_p_feature_view(frame, specification.feature_variant).columns.tolist()
        record = _result_record(
            run_id=paths.run_id,
            specification=specification,
            feature_count=len(feature_columns),
            dataset_path=data_path,
            dataset_sha256=dataset_sha256,
            seed=seed,
            split_summary=split_summary,
            model_configuration=configurations[specification.model_name],
            environment=environment,
        )
        try:
            train_features = protocol_p_feature_view(train_frame, specification.feature_variant)
            test_features = protocol_p_feature_view(test_frame, specification.feature_variant)
            estimator = model_factory(specification.model_name, seed)
            predictions, positive_scores, score_source, runtime = fit_predict_and_measure(
                estimator, train_features, train_frame[TARGET_COLUMN], test_features
            )
            metrics = evaluate_binary_predictions(
                test_frame[TARGET_COLUMN], predictions, positive_scores
            )
            metrics["score_source"] = score_source
            artifact = paths.model_artifacts_directory / f"{specification.identifier}.joblib"
            joblib.dump(estimator, artifact)
            record.update(
                {
                    "status": "completed",
                    "metrics": metrics,
                    "confusion_counts": _confusion_counts(metrics),
                    "runtime": runtime,
                    "model_artifact": str(artifact),
                }
            )
        except Exception as error:  # Preserve per-run evidence before failing overall.
            record.update(
                {
                    "status": "failed",
                    "error": {
                        "type": type(error).__name__,
                        "message": str(error),
                        "traceback": traceback.format_exc(),
                    },
                }
            )
            failures.append(specification.identifier)
        if not benchmark_result_schema_is_valid(record):
            raise ProtocolPBenchmarkError(
                f"Benchmark result schema is invalid for {specification.identifier}"
            )
        records.append(record)

    _write_benchmark_outputs(paths, environment, configuration, split_summary, records)
    if failures:
        raise ProtocolPBenchmarkError(
            "Protocol P benchmark has failed primary runs; partial reports preserve the errors: "
            + ", ".join(failures)
        )
    return paths, records

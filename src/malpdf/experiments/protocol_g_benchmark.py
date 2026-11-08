"""Feature-vector-disjoint baseline infrastructure for RIT-PDFMal-2026 Protocol G.

Protocol G evaluates a saved 60/20/20-style split whose feature-equivalent
groups are disjoint across train, validation, and test. Equal static feature
vectors are not claimed to be duplicate PDF files: the local CSV has no
per-PDF hash column.
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
    P_ALL41,
    P_DROP3CONSTANT,
    TARGET_COLUMN,
    protocol_p_feature_columns,
    protocol_p_feature_view,
)
from malpdf.data.rit_pdfmal import load_rit_pdfmal, sha256_file
from malpdf.data.rit_pdfmal_split import (
    DEFAULT_SPLIT_SEED,
    SPLIT_NAMES,
    build_deterministic_sample_ids,
    build_duplicate_group_ids,
    validate_split_manifest,
)
from malpdf.evaluation.binary import (
    evaluate_binary_predictions,
    fit_predict_and_measure,
    predict_and_measure,
)
from malpdf.experiments.protocol_p import collect_environment_metadata, repository_git_state
from malpdf.models.classical import MODEL_NAMES, create_model, model_configurations
from malpdf.reproducibility import set_random_seed

PROTOCOL_NAME = "G"
VERIFIED_DATASET_SHA256 = "2f270ab31fbfe8821fd7f54608cb1aa694a0a8d0bbf2ca000942a68213ef8623"
G_ALL41 = "G-all41"
G_DROP3CONSTANT = "G-drop3constant"
G_FEATURE_VARIANT_TO_PROTOCOL_P = {
    G_ALL41: P_ALL41.name,
    G_DROP3CONSTANT: P_DROP3CONSTANT.name,
}
EXPECTED_G_SPLIT = {
    "train": {"rows": 14602, "groups": 8600, "label_0": 7941, "label_1": 6661},
    "validation": {"rows": 4868, "groups": 3386, "label_0": 2647, "label_1": 2221},
    "test": {"rows": 4867, "groups": 3385, "label_0": 2647, "label_1": 2220},
    "total_rows": 24337,
    "total_groups": 15371,
}
G_COMPARISON_METRICS = ("accuracy", "precision", "recall", "f1", "roc_auc", "pr_auc", "mcc")


class ProtocolGBenchmarkError(RuntimeError):
    """Raised when Protocol G cannot run under its fixed leakage-safe policy."""


@dataclass(frozen=True)
class ProtocolGBenchmarkRunSpec:
    """One fixed model/feature-variant combination in the primary G matrix."""

    model_name: str
    feature_variant: str

    @property
    def identifier(self) -> str:
        return f"{self.model_name}__{self.feature_variant}"


PRIMARY_G_BENCHMARK_MATRIX = tuple(
    ProtocolGBenchmarkRunSpec(model_name, feature_variant)
    for model_name in MODEL_NAMES
    for feature_variant in (G_ALL41, G_DROP3CONSTANT)
)


@dataclass(frozen=True)
class ProtocolGBenchmarkPaths:
    """Tracked reports and ignored fitted-model locations for one G run."""

    run_id: str
    reports_directory: Path
    artifact_directory: Path
    model_artifacts_directory: Path
    summary_validation_csv: Path
    summary_test_csv: Path
    metrics_json: Path
    protocol_p_vs_g_csv: Path
    environment_json: Path
    experiment_config_json: Path
    split_summary_json: Path
    confusion_matrices_json: Path
    run_summary_markdown: Path


def _timestamp_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_run_id(run_id: str) -> str:
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
    if not run_id or any(character not in allowed for character in run_id):
        raise ValueError("run_id must be non-empty and contain only letters, numbers, '-', '_', or '.'")
    return run_id


def protocol_g_feature_columns(frame: pd.DataFrame, variant_name: str) -> list[str]:
    """Return a G-named feature set while reusing Protocol P's exact selection."""
    try:
        protocol_p_variant = G_FEATURE_VARIANT_TO_PROTOCOL_P[variant_name]
    except KeyError as error:
        raise ValueError(f"Unknown Protocol G feature variant: {variant_name}") from error
    return protocol_p_feature_columns(frame, protocol_p_variant)


def protocol_g_feature_view(frame: pd.DataFrame, variant_name: str) -> pd.DataFrame:
    """Select an unmodified G feature view, preserving all semantic values."""
    try:
        protocol_p_variant = G_FEATURE_VARIANT_TO_PROTOCOL_P[variant_name]
    except KeyError as error:
        raise ValueError(f"Unknown Protocol G feature variant: {variant_name}") from error
    return protocol_p_feature_view(frame, protocol_p_variant)


def protocol_g_benchmark_paths(
    repository_root: str | Path, run_id: str
) -> ProtocolGBenchmarkPaths:
    """Create only dedicated G paths; these cannot resolve inside Protocol P."""
    root = Path(repository_root)
    safe_id = _safe_run_id(run_id)
    reports = root / "reports" / "experiments" / "protocol_g" / safe_id
    artifacts = root / "artifacts" / "protocol_g" / safe_id
    return ProtocolGBenchmarkPaths(
        run_id=safe_id,
        reports_directory=reports,
        artifact_directory=artifacts,
        model_artifacts_directory=artifacts / "models",
        summary_validation_csv=reports / "summary_validation.csv",
        summary_test_csv=reports / "summary_test.csv",
        metrics_json=reports / "metrics.json",
        protocol_p_vs_g_csv=reports / "protocol_p_vs_g.csv",
        environment_json=reports / "environment.json",
        experiment_config_json=reports / "experiment_config.json",
        split_summary_json=reports / "split_summary.json",
        confusion_matrices_json=reports / "confusion_matrices.json",
        run_summary_markdown=reports / "run_summary.md",
    )


def _default_manifest_path(repository_root: Path) -> Path:
    return repository_root / "data" / "processed" / "rit-pdfmal-2026_split_manifest.csv"


def _default_split_report_path(repository_root: Path) -> Path:
    return repository_root / "reports" / "rit-pdfmal-2026_split_report.json"


def _require_g_data_path(repository_root: Path, path: str | Path, description: str) -> Path:
    selected = Path(path).resolve()
    allowed_root = (repository_root / "data" / "processed").resolve()
    if not selected.is_relative_to(allowed_root) or "protocol_p" in {
        part.casefold() for part in selected.parts
    }:
        raise ProtocolGBenchmarkError(f"{description} must be a saved Protocol G data/processed path")
    if not selected.is_file():
        raise FileNotFoundError(f"{description} not found: {selected}")
    return selected


def _read_split_report(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"Protocol G split report not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _split_counts(manifest: pd.DataFrame) -> dict[str, dict[str, int]]:
    result: dict[str, dict[str, int]] = {}
    for partition in SPLIT_NAMES:
        subset = manifest.loc[manifest["split"] == partition]
        result[partition] = {
            "rows": int(len(subset)),
            "groups": int(subset["duplicate_group_id"].nunique()),
            "label_0": int((subset[TARGET_COLUMN] == 0).sum()),
            "label_1": int((subset[TARGET_COLUMN] == 1).sum()),
        }
    return result


def _verify_expected_g_split(manifest: pd.DataFrame) -> dict[str, dict[str, int]]:
    observed = _split_counts(manifest)
    expected_partitions = {name: EXPECTED_G_SPLIT[name] for name in SPLIT_NAMES}
    total_rows = int(len(manifest))
    total_groups = int(manifest["duplicate_group_id"].nunique())
    if (
        observed != expected_partitions
        or total_rows != EXPECTED_G_SPLIT["total_rows"]
        or total_groups != EXPECTED_G_SPLIT["total_groups"]
    ):
        raise ProtocolGBenchmarkError(
            "Saved Protocol G split does not match the required invariant statistics: "
            f"observed partitions={observed}, rows={total_rows}, groups={total_groups}"
        )
    return observed


def _validate_manifest_against_frame(
    frame: pd.DataFrame, manifest: pd.DataFrame
) -> dict[str, Any]:
    """Prove manifest/sample/feature-group integrity before any G fitting."""
    required = {"sample_id", "duplicate_group_id", "split", TARGET_COLUMN}
    missing = required.difference(manifest.columns)
    if missing:
        raise ProtocolGBenchmarkError(f"Protocol G manifest is missing columns: {sorted(missing)}")
    try:
        inherited_validation = validate_split_manifest(frame, manifest)
    except Exception as error:
        raise ProtocolGBenchmarkError(f"Base Protocol G split validation failed: {error}") from error

    source = pd.DataFrame(
        {
            "sample_id": build_deterministic_sample_ids(frame).astype(str).to_numpy(copy=False),
            "raw_duplicate_group_id": build_duplicate_group_ids(frame)
            .astype(str)
            .to_numpy(copy=False),
            "raw_label": frame[TARGET_COLUMN].to_numpy(copy=False),
        }
    )
    manifest_view = manifest.loc[:, ["sample_id", "duplicate_group_id", "split", TARGET_COLUMN]].copy()
    manifest_view["sample_id"] = manifest_view["sample_id"].astype(str)
    manifest_view["duplicate_group_id"] = manifest_view["duplicate_group_id"].astype(str)
    merged = source.merge(
        manifest_view,
        on="sample_id",
        how="outer",
        validate="one_to_one",
        indicator=True,
    )
    source_matches_manifest = bool(
        (merged["_merge"] == "both").all()
        and (merged["raw_duplicate_group_id"] == merged["duplicate_group_id"]).all()
        and (merged["raw_label"] == merged[TARGET_COLUMN]).all()
    )
    group_label_counts = source.groupby("raw_duplicate_group_id", sort=False)["raw_label"].nunique(
        dropna=False
    )
    feature_equivalent_groups_have_one_label = bool((group_label_counts == 1).all())
    partition_counts_per_group = manifest_view.groupby("duplicate_group_id", sort=False)["split"].nunique()
    exact_feature_vectors_are_partition_disjoint = bool((partition_counts_per_group == 1).all())
    validation = {
        "zero_group_overlap": inherited_validation["zero_group_overlap"],
        "zero_exact_feature_vector_overlap": {
            "is_valid": exact_feature_vectors_are_partition_disjoint,
            "basis": "Feature-equivalent groups are canonical hashes of all 41 static feature values, excluding Label.",
        },
        "all_rows_assigned_exactly_once": {
            **inherited_validation["all_rows_assigned_exactly_once"],
            "raw_sample_identifier_count": int(source["sample_id"].nunique()),
        },
        "labels_and_group_ids_match_raw_dataset": {"is_valid": source_matches_manifest},
        "feature_equivalent_group_label_purity": {
            "is_valid": feature_equivalent_groups_have_one_label,
            "conflicting_group_count": int((group_label_counts > 1).sum()),
        },
    }
    if not all(section["is_valid"] for section in validation.values()):
        raise ProtocolGBenchmarkError(f"Protocol G hard leakage validation failed: {validation}")
    return validation


def load_saved_protocol_g_split(
    frame: pd.DataFrame,
    dataset_sha256: str,
    repository_root: str | Path,
    *,
    seed: int = DEFAULT_SPLIT_SEED,
    manifest_path: str | Path | None = None,
    split_report_path: str | Path | None = None,
    enforce_expected_invariants: bool = True,
) -> tuple[Path, pd.DataFrame, dict[str, Any]]:
    """Load and validate the immutable G manifest; never regenerate a split."""
    root = Path(repository_root).resolve()
    if dataset_sha256 != VERIFIED_DATASET_SHA256:
        raise ProtocolGBenchmarkError(
            f"Dataset SHA-256 does not match verified Protocol G data: {dataset_sha256}"
        )
    selected_manifest = _require_g_data_path(
        root, manifest_path or _default_manifest_path(root), "Protocol G split manifest"
    )
    report_path = Path(split_report_path or _default_split_report_path(root)).resolve()
    manifest = pd.read_csv(selected_manifest)
    report = _read_split_report(report_path)
    if report.get("seed") != seed or report.get("dataset", {}).get("sha256") != dataset_sha256:
        raise ProtocolGBenchmarkError("Protocol G split report seed or dataset checksum does not match")
    hard_validation = _validate_manifest_against_frame(frame, manifest)
    counts = _split_counts(manifest)
    if enforce_expected_invariants:
        counts = _verify_expected_g_split(manifest)
    return selected_manifest, manifest, {
        "seed": seed,
        "dataset_sha256": dataset_sha256,
        "split_manifest_sha256": sha256_file(selected_manifest),
        "split_manifest": str(selected_manifest),
        "split_report": str(report_path),
        "partition_statistics": counts,
        "total_rows": int(len(manifest)),
        "total_feature_equivalent_groups": int(manifest["duplicate_group_id"].nunique()),
        "hard_validation": hard_validation,
        "terminology": "Groups represent identical static feature vectors, not proven duplicate PDF files.",
    }


def split_frame_from_protocol_g_manifest(
    frame: pd.DataFrame, manifest: pd.DataFrame
) -> dict[str, pd.DataFrame]:
    """Partition rows solely through saved sample IDs, never DataFrame indexes."""
    sample_ids = build_deterministic_sample_ids(frame).astype(str)
    partitions: dict[str, pd.DataFrame] = {}
    covered = pd.Series(False, index=frame.index)
    for partition in SPLIT_NAMES:
        selected_ids = set(manifest.loc[manifest["split"] == partition, "sample_id"].astype(str))
        mask = sample_ids.isin(selected_ids)
        if bool((covered & mask).any()):
            raise ProtocolGBenchmarkError("Saved Protocol G partitions overlap in sample assignments")
        covered = covered | mask
        partitions[partition] = frame.loc[mask].copy()
    if int(covered.sum()) != len(frame):
        raise ProtocolGBenchmarkError("Saved Protocol G partitions do not cover every source row")
    return partitions


def _confusion_counts(metrics: dict[str, Any]) -> dict[str, int]:
    matrix = metrics["confusion_matrix"]
    return {"tn": int(matrix[0][0]), "fp": int(matrix[0][1]), "fn": int(matrix[1][0]), "tp": int(matrix[1][1])}


def _load_protocol_p_summary(
    repository_root: Path, summary_path: str | Path | None
) -> tuple[Path, pd.DataFrame]:
    selected = Path(
        summary_path
        or repository_root / "reports" / "experiments" / "protocol_p" / "seed42" / "summary.csv"
    ).resolve()
    allowed_root = (repository_root / "reports" / "experiments" / "protocol_p").resolve()
    if not selected.is_relative_to(allowed_root):
        raise ProtocolGBenchmarkError("Protocol P comparison source must remain below reports/experiments/protocol_p")
    if not selected.is_file():
        raise FileNotFoundError(f"Committed Protocol P summary not found: {selected}")
    summary = pd.read_csv(selected)
    required = {"model_name", "feature_variant", *G_COMPARISON_METRICS}
    missing = required.difference(summary.columns)
    if missing:
        raise ProtocolGBenchmarkError(f"Protocol P summary is missing comparison metrics: {sorted(missing)}")
    return selected, summary


def build_protocol_p_vs_g_comparison(
    protocol_p_summary: pd.DataFrame, run_records: Sequence[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Compare only like-for-like P/G variants; never infer an exact reproduction."""
    rows: list[dict[str, Any]] = []
    for record in run_records:
        p_variant = G_FEATURE_VARIANT_TO_PROTOCOL_P[record["feature_variant"]]
        matching = protocol_p_summary.loc[
            (protocol_p_summary["model_name"] == record["model_name"])
            & (protocol_p_summary["feature_variant"] == p_variant)
        ]
        if len(matching) != 1:
            raise ProtocolGBenchmarkError(
                "Protocol P comparison requires exactly one equivalent P result for "
                f"{record['model_name']} / {p_variant}"
            )
        p_row = matching.iloc[0]
        validation_metrics = record["validation"]["metrics"] if record["validation"] else {}
        test_metrics = record["test"]["metrics"] if record["test"] else {}
        for metric in G_COMPARISON_METRICS:
            p_value = float(p_row[metric])
            g_validation = validation_metrics.get(metric)
            g_test = test_metrics.get(metric)
            rows.append(
                {
                    "model": record["model_name"],
                    "feature_variant": record["feature_variant"],
                    "protocol_p_feature_variant": p_variant,
                    "metric": metric,
                    "protocol_p_test_value": p_value,
                    "protocol_g_validation_value": g_validation,
                    "protocol_g_test_value": g_test,
                    "protocol_g_test_minus_protocol_p": (
                        None if g_test is None else float(g_test) - p_value
                    ),
                    "absolute_difference": None if g_test is None else abs(float(g_test) - p_value),
                    "interpretation_note": (
                        "Comparison isolates saved partitioning protocols for equivalent feature variants; "
                        "feature-equivalent groups are not proven duplicate PDF files."
                    ),
                }
            )
    return rows


def _validate_requested_specs(
    specifications: Sequence[ProtocolGBenchmarkRunSpec],
) -> tuple[ProtocolGBenchmarkRunSpec, ...]:
    selected = tuple(specifications)
    if not selected:
        raise ValueError("At least one Protocol G benchmark specification is required")
    supported = set(PRIMARY_G_BENCHMARK_MATRIX)
    invalid = [specification for specification in selected if specification not in supported]
    if invalid or len(set(selected)) != len(selected):
        raise ValueError("Protocol G specifications must be unique members of the primary matrix")
    return selected


def _create_output_directories(paths: ProtocolGBenchmarkPaths) -> None:
    if paths.reports_directory.exists() or paths.artifact_directory.exists():
        raise FileExistsError(f"Protocol G run already exists; refusing to overwrite: {paths.run_id}")
    paths.reports_directory.mkdir(parents=True, exist_ok=False)
    paths.model_artifacts_directory.mkdir(parents=True, exist_ok=False)


def _result_record(
    *,
    run_id: str,
    specification: ProtocolGBenchmarkRunSpec,
    feature_count: int,
    dataset_path: Path,
    dataset_sha256: str,
    split_summary: dict[str, Any],
    configuration: dict[str, Any],
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
        "evaluated_partitions": ["validation", "test"],
        "dataset_filename": dataset_path.name,
        "dataset_sha256": dataset_sha256,
        "split_seed": split_summary["seed"],
        "split_manifest": split_summary["split_manifest"],
        "split_manifest_sha256": split_summary["split_manifest_sha256"],
        "partition_statistics": split_summary["partition_statistics"],
        "model_configuration": configuration,
        "preprocessing_configuration": configuration["preprocessing"],
        "environment": environment,
        "training": None,
        "validation": None,
        "test": None,
        "model_artifact": None,
        "error": None,
    }


def protocol_g_result_schema_is_valid(record: dict[str, Any]) -> bool:
    """Validate the minimal serialized provenance and metrics shape for G results."""
    required = {
        "experiment_run_id", "protocol", "timestamp_utc", "status", "model_name", "feature_variant",
        "feature_count", "evaluated_partitions", "dataset_filename", "dataset_sha256", "split_seed",
        "split_manifest", "split_manifest_sha256", "partition_statistics", "model_configuration",
        "preprocessing_configuration", "environment", "training", "validation", "test", "error",
    }
    if not required.issubset(record) or record.get("protocol") != PROTOCOL_NAME:
        return False
    if record.get("status") == "failed":
        return isinstance(record.get("error"), dict)
    if record.get("status") != "completed" or not isinstance(record.get("training"), dict):
        return False
    metric_names = set(G_COMPARISON_METRICS)
    for partition in ("validation", "test"):
        evaluation = record.get(partition)
        if not isinstance(evaluation, dict) or not isinstance(evaluation.get("metrics"), dict):
            return False
        if not metric_names.issubset(evaluation["metrics"]):
            return False
        if not isinstance(evaluation.get("confusion_counts"), dict):
            return False
        if not isinstance(evaluation.get("runtime"), dict):
            return False
    return record.get("error") is None


def _partition_summary_rows(
    records: Sequence[dict[str, Any]], partition: str
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in records:
        evaluation = record[partition] or {}
        metrics = evaluation.get("metrics", {})
        runtime = evaluation.get("runtime", {})
        rows.append(
            {
                "experiment_run_id": record["experiment_run_id"],
                "status": record["status"],
                "model_name": record["model_name"],
                "feature_variant": record["feature_variant"],
                "feature_count": record["feature_count"],
                **{name: metrics.get(name) for name in G_COMPARISON_METRICS},
                **(evaluation.get("confusion_counts") or {"tn": None, "fp": None, "fn": None, "tp": None}),
                "training_seconds": (record["training"] or {}).get("training_seconds"),
                "inference_total_seconds": runtime.get("inference_total_seconds"),
                "inference_milliseconds_per_sample": runtime.get("inference_milliseconds_per_sample"),
                "score_source": metrics.get("score_source"),
                "error_type": None if record["error"] is None else record["error"]["type"],
                "error_message": None if record["error"] is None else record["error"]["message"],
            }
        )
    return rows


def _confusion_matrix_document(records: Sequence[dict[str, Any]]) -> dict[str, Any]:
    return {
        record["model_name"] + "__" + record["feature_variant"]: {
            partition: None
            if record[partition] is None
            else {
                "labels": record[partition]["metrics"]["confusion_matrix_labels"],
                "matrix": record[partition]["metrics"]["confusion_matrix"],
                "counts": record[partition]["confusion_counts"],
            }
            for partition in ("validation", "test")
        }
        for record in records
    }


def _run_summary_markdown(
    run_id: str, split_summary: dict[str, Any], records: Sequence[dict[str, Any]]
) -> str:
    completed = sum(record["status"] == "completed" for record in records)
    failed = len(records) - completed
    return "\n".join(
        [
            "# Protocol G feature-vector-disjoint benchmark run",
            "",
            f"- Run ID: `{run_id}`",
            "- Research question: how does classification performance change when identical static feature representations are prevented from crossing training and evaluation partitions?",
            "- Terminology: feature-equivalent groups denote identical static feature vectors, not proven duplicate PDF files.",
            f"- Saved split manifest: `{split_summary['split_manifest']}`",
            f"- Split manifest SHA-256: `{split_summary['split_manifest_sha256']}`",
            f"- Project seed: `{split_summary['seed']}`.",
            f"- Completed runs: {completed}; failed runs: {failed}.",
            "- Models fit only on train; validation and test are each evaluated once without tuning, threshold selection, or model selection.",
            "- Runtime values are environment-specific and do not measure protocol quality.",
            "",
        ]
    )


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def _write_benchmark_outputs(
    paths: ProtocolGBenchmarkPaths,
    environment: dict[str, Any],
    configuration: dict[str, Any],
    split_summary: dict[str, Any],
    records: Sequence[dict[str, Any]],
    protocol_p_summary: pd.DataFrame,
) -> None:
    _write_json(paths.environment_json, environment)
    _write_json(paths.experiment_config_json, configuration)
    _write_json(paths.split_summary_json, split_summary)
    _write_json(paths.metrics_json, {"experiment": configuration, "runs": list(records)})
    _write_json(paths.confusion_matrices_json, _confusion_matrix_document(records))
    pd.DataFrame(_partition_summary_rows(records, "validation")).to_csv(
        paths.summary_validation_csv, index=False
    )
    pd.DataFrame(_partition_summary_rows(records, "test")).to_csv(
        paths.summary_test_csv, index=False
    )
    pd.DataFrame(build_protocol_p_vs_g_comparison(protocol_p_summary, records)).to_csv(
        paths.protocol_p_vs_g_csv, index=False
    )
    paths.run_summary_markdown.write_text(
        _run_summary_markdown(paths.run_id, split_summary, records), encoding="utf-8"
    )


def run_protocol_g_benchmark(
    repository_root: str | Path,
    dataset_path: str | Path,
    *,
    seed: int = DEFAULT_SPLIT_SEED,
    run_id: str | None = None,
    manifest_path: str | Path | None = None,
    split_report_path: str | Path | None = None,
    protocol_p_summary_path: str | Path | None = None,
    require_clean_git: bool = True,
    enforce_expected_split_invariants: bool = True,
    specifications: Sequence[ProtocolGBenchmarkRunSpec] | None = None,
    model_factory: Callable[[str, int], Any] = create_model,
    environment_collector: Callable[[str | Path, str | Path], dict[str, Any]] = collect_environment_metadata,
) -> tuple[ProtocolGBenchmarkPaths, list[dict[str, Any]]]:
    """Execute a saved-split Protocol G baseline after hard leakage validation.

    The command-line entry point always uses all ten primary configurations. The
    optional specifications argument is a synthetic-test seam only.
    """
    root = Path(repository_root).resolve()
    data_path = Path(dataset_path).resolve()
    selected_specs = _validate_requested_specs(specifications or PRIMARY_G_BENCHMARK_MATRIX)
    git_state = repository_git_state(root)
    if require_clean_git and git_state["status"] != "clean":
        raise ProtocolGBenchmarkError(
            "Refusing Protocol G benchmark because the repository is not clean: "
            f"{git_state['status']}"
        )

    set_random_seed(seed)
    frame = load_rit_pdfmal(data_path)
    if TARGET_COLUMN not in frame.columns:
        raise ProtocolGBenchmarkError(f"Expected target column {TARGET_COLUMN!r} is absent")
    dataset_sha256 = sha256_file(data_path)
    selected_manifest, manifest, split_summary = load_saved_protocol_g_split(
        frame,
        dataset_sha256,
        root,
        seed=seed,
        manifest_path=manifest_path,
        split_report_path=split_report_path,
        enforce_expected_invariants=enforce_expected_split_invariants,
    )
    partitions = split_frame_from_protocol_g_manifest(frame, manifest)
    if len(partitions["train"]) != split_summary["partition_statistics"]["train"]["rows"]:
        raise ProtocolGBenchmarkError("Protocol G train partition does not match its manifest summary")

    protocol_p_summary_path_resolved, protocol_p_summary = _load_protocol_p_summary(
        root, protocol_p_summary_path
    )
    identifier = run_id or f"g-benchmark-seed{seed}-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}"
    paths = protocol_g_benchmark_paths(root, identifier)
    _create_output_directories(paths)

    environment = environment_collector(data_path, root)
    environment["git_working_tree"] = git_state
    environment["benchmark_timestamp_utc"] = _timestamp_utc()
    configurations = model_configurations(seed)
    configuration = {
        "experiment_run_id": paths.run_id,
        "protocol": PROTOCOL_NAME,
        "purpose": "Feature-vector-disjoint generalization baseline; not a duplicate-PDF experiment.",
        "dataset": {"filename": data_path.name, "sha256": dataset_sha256},
        "split": split_summary,
        "protocol_p_comparison_source": {
            "summary_csv": str(protocol_p_summary_path_resolved),
            "sha256": sha256_file(protocol_p_summary_path_resolved),
            "comparison_policy": "Only P/G equivalent model and feature-variant pairs are compared.",
        },
        "benchmark_matrix": [
            {"model_name": specification.model_name, "feature_variant": specification.feature_variant}
            for specification in selected_specs
        ],
        "primary_matrix_run_count": len(PRIMARY_G_BENCHMARK_MATRIX),
        "model_configurations": {
            specification.model_name: configurations[specification.model_name]
            for specification in selected_specs
        },
        "methodological_constraints": [
            "Identical static feature vectors are partition-disjoint; this does not prove duplicate PDF-file removal.",
            "Models and preprocessing configurations are identical to Protocol P equivalents.",
            "Models fit only on train; validation and test are evaluated without tuning, threshold changes, or model selection.",
            "No multi-seed experiment, cross-validation, deep learning, imputation, clipping, or feature selection is performed.",
        ],
        "environment": environment,
    }

    records: list[dict[str, Any]] = []
    failures: list[str] = []
    for specification in selected_specs:
        feature_count = len(protocol_g_feature_columns(frame, specification.feature_variant))
        record = _result_record(
            run_id=paths.run_id,
            specification=specification,
            feature_count=feature_count,
            dataset_path=data_path,
            dataset_sha256=dataset_sha256,
            split_summary=split_summary,
            configuration=configurations[specification.model_name],
            environment=environment,
        )
        try:
            estimator = model_factory(specification.model_name, seed)
            train_features = protocol_g_feature_view(partitions["train"], specification.feature_variant)
            validation_features = protocol_g_feature_view(partitions["validation"], specification.feature_variant)
            test_features = protocol_g_feature_view(partitions["test"], specification.feature_variant)
            validation_predictions, validation_scores, validation_score_source, training_and_validation = (
                fit_predict_and_measure(
                    estimator,
                    train_features,
                    partitions["train"][TARGET_COLUMN],
                    validation_features,
                )
            )
            validation_metrics = evaluate_binary_predictions(
                partitions["validation"][TARGET_COLUMN], validation_predictions, validation_scores
            )
            validation_metrics["score_source"] = validation_score_source
            test_predictions, test_scores, test_score_source, test_runtime = predict_and_measure(
                estimator, test_features
            )
            test_metrics = evaluate_binary_predictions(
                partitions["test"][TARGET_COLUMN], test_predictions, test_scores
            )
            test_metrics["score_source"] = test_score_source
            artifact = paths.model_artifacts_directory / f"{specification.identifier}.joblib"
            joblib.dump(estimator, artifact)
            record.update(
                {
                    "status": "completed",
                    "training": {"training_seconds": training_and_validation["training_seconds"]},
                    "validation": {
                        "metrics": validation_metrics,
                        "confusion_counts": _confusion_counts(validation_metrics),
                        "runtime": {
                            "inference_total_seconds": training_and_validation[
                                "test_inference_total_seconds"
                            ],
                            "inference_milliseconds_per_sample": training_and_validation[
                                "test_inference_milliseconds_per_sample"
                            ],
                        },
                    },
                    "test": {
                        "metrics": test_metrics,
                        "confusion_counts": _confusion_counts(test_metrics),
                        "runtime": test_runtime,
                    },
                    "model_artifact": str(artifact),
                }
            )
        except Exception as error:
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
        if not protocol_g_result_schema_is_valid(record):
            raise ProtocolGBenchmarkError(
                f"Protocol G result schema is invalid for {specification.identifier}"
            )
        records.append(record)

    _write_benchmark_outputs(
        paths, environment, configuration, split_summary, records, protocol_p_summary
    )
    if failures:
        raise ProtocolGBenchmarkError(
            "Protocol G benchmark has failed primary runs; partial reports preserve the errors: "
            + ", ".join(failures)
        )
    return paths, records

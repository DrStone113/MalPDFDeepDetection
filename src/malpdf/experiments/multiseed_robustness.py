"""Fixed multi-seed robustness infrastructure for Protocol P versus Protocol G.

The future experiment asks whether the completed Protocol P/Protocol G
differences are stable when *split assignment* changes.  It is deliberately
not a hyperparameter search: the five official split seeds are fixed and every
stochastic model receives the separate, fixed ``model_random_state=42``.

The command-line entry point defaults to preflight-only mode.  Actual fitting
requires an explicit ``--execute`` request from a clean Git worktree.  This
module never rewrites raw data or the completed seed-42 P/G reports.
"""

from __future__ import annotations

import json
import math
import statistics
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

import joblib
import pandas as pd
import yaml

from malpdf.data.protocol_p import (
    DEFAULT_PROTOCOL_P_SEED,
    P_DROP3CONSTANT,
    TARGET_COLUMN,
    create_protocol_p_split,
    protocol_p_feature_columns,
    protocol_p_feature_view,
    validate_protocol_p_manifest,
)
from malpdf.data.rit_pdfmal import load_rit_pdfmal, sha256_file
from malpdf.data.rit_pdfmal_split import (
    DEFAULT_SPLIT_SEED,
    SPLIT_NAMES,
    create_rit_pdfmal_split,
    validate_split_manifest,
)
from malpdf.evaluation.binary import (
    evaluate_binary_predictions,
    fit_predict_and_measure,
    predict_and_measure,
)
from malpdf.experiments.protocol_g_benchmark import (
    G_DROP3CONSTANT,
    _validate_manifest_against_frame,
    load_saved_protocol_g_split,
    protocol_g_feature_columns,
    protocol_g_feature_view,
    split_frame_from_protocol_g_manifest,
)
from malpdf.experiments.protocol_p import collect_environment_metadata, repository_git_state
from malpdf.experiments.protocol_p_benchmark import (
    load_saved_protocol_p_split,
    split_frame_from_manifest,
)
from malpdf.models.classical import MODEL_NAMES, create_model, model_configurations
from malpdf.reproducibility import set_random_seed

VERIFIED_DATASET_SHA256 = "2f270ab31fbfe8821fd7f54608cb1aa694a0a8d0bbf2ca000942a68213ef8623"
OFFICIAL_SPLIT_SEEDS = (42, 43, 44, 45, 46)
FIXED_MODEL_RANDOM_STATE = 42
CANONICAL_PROTOCOLS = ("P", "G")
CANONICAL_METRICS = (
    "accuracy",
    "precision_malicious",
    "recall_malicious",
    "f1_malicious",
    "precision_macro",
    "recall_macro",
    "f1_macro",
    "roc_auc",
    "pr_auc",
    "mcc",
    "tn",
    "fp",
    "fn",
    "tp",
)


class MultiSeedRobustnessError(RuntimeError):
    """Raised when the fixed multi-seed protocol cannot be run safely."""


@dataclass(frozen=True)
class MultiSeedPaths:
    """Separate derived paths for one immutable robustness-experiment run."""

    run_id: str
    reports_directory: Path
    processed_directory: Path
    artifact_directory: Path
    configuration_directory: Path
    split_summaries_directory: Path
    per_seed_directory: Path
    aggregate_directory: Path
    environment_json: Path
    experiment_config_json: Path
    preflight_json: Path
    metrics_json: Path
    summary_csv: Path
    aggregate_metrics_csv: Path
    paired_deltas_csv: Path
    run_summary_markdown: Path
    fixed_design_yaml: Path


@dataclass(frozen=True)
class MultiSeedPreflight:
    """Validated immutable inputs needed before a future benchmark can fit."""

    dataset_path: Path
    dataset_sha256: str
    frame: pd.DataFrame
    environment: dict[str, Any]
    benchmark_code_commit: str
    baseline_references: dict[str, Any]
    protocol_p_seed42_manifest: Path
    protocol_g_seed42_manifest: Path
    protocol_p_seed42_summary: dict[str, Any]
    protocol_g_seed42_summary: dict[str, Any]


def _timestamp_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_run_id(run_id: str) -> str:
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
    if not run_id or any(character not in allowed for character in run_id):
        raise ValueError("run_id must be non-empty and contain only letters, numbers, '-', '_', or '.'")
    return run_id


def multiseed_paths(repository_root: str | Path, run_id: str) -> MultiSeedPaths:
    """Return dedicated locations that cannot resolve to Protocol P/G baselines."""
    root = Path(repository_root).resolve()
    safe_id = _safe_run_id(run_id)
    reports = root / "reports" / "experiments" / "multiseed" / safe_id
    processed = root / "data" / "processed" / "multiseed" / safe_id
    artifacts = root / "artifacts" / "multiseed" / safe_id
    return MultiSeedPaths(
        run_id=safe_id,
        reports_directory=reports,
        processed_directory=processed,
        artifact_directory=artifacts,
        configuration_directory=reports / "configs",
        split_summaries_directory=reports / "splits",
        per_seed_directory=reports / "per_seed",
        aggregate_directory=reports / "aggregate",
        environment_json=reports / "environment.json",
        experiment_config_json=reports / "experiment_config.json",
        preflight_json=reports / "preflight.json",
        metrics_json=reports / "metrics.json",
        summary_csv=reports / "summary.csv",
        aggregate_metrics_csv=reports / "aggregate" / "metric_summary.csv",
        paired_deltas_csv=reports / "aggregate" / "paired_protocol_g_minus_p.csv",
        run_summary_markdown=reports / "run_summary.md",
        fixed_design_yaml=reports / "configs" / "fixed_design.yaml",
    )


def _read_json(path: Path) -> dict[str, Any]:
    try:
        content = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise
    except json.JSONDecodeError as error:
        raise MultiSeedRobustnessError(f"Invalid JSON source: {path}") from error
    if not isinstance(content, dict):
        raise MultiSeedRobustnessError(f"JSON source must contain an object: {path}")
    return content


def load_multiseed_configuration(path: str | Path) -> dict[str, Any]:
    """Load and strictly validate the committed, fixed experiment design."""
    config_path = Path(path)
    try:
        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise
    except yaml.YAMLError as error:
        raise MultiSeedRobustnessError(f"Invalid YAML configuration: {config_path}") from error
    if not isinstance(config, dict):
        raise MultiSeedRobustnessError("Multi-seed configuration must be a mapping")
    validate_multiseed_configuration(config)
    return config


def validate_multiseed_configuration(config: dict[str, Any]) -> None:
    """Prevent a nominally official run from silently changing its frozen design."""
    dataset = config.get("dataset")
    if not isinstance(dataset, dict) or dataset.get("expected_sha256") != VERIFIED_DATASET_SHA256:
        raise MultiSeedRobustnessError("Configuration must contain the verified RIT-PDFMal SHA-256")
    if tuple(config.get("split_seeds", ())) != OFFICIAL_SPLIT_SEEDS:
        raise MultiSeedRobustnessError(f"Official split seeds must be exactly {OFFICIAL_SPLIT_SEEDS}")
    if config.get("model_random_state") != FIXED_MODEL_RANDOM_STATE:
        raise MultiSeedRobustnessError(
            "model_random_state must remain the fixed value 42, independently of split seed"
        )
    if tuple(config.get("models", ())) != MODEL_NAMES:
        raise MultiSeedRobustnessError("Configuration must list each official model exactly once")
    protocols = config.get("protocols")
    if not isinstance(protocols, dict):
        raise MultiSeedRobustnessError("Configuration must document Protocol P and Protocol G")
    if protocols.get("P", {}).get("feature_variant") != P_DROP3CONSTANT.name:
        raise MultiSeedRobustnessError("Protocol P must use P-drop3constant in this study")
    if protocols.get("P", {}).get("split") != "row_level_stratified_75_25":
        raise MultiSeedRobustnessError("Protocol P must retain its row-level stratified 75/25 split")
    if protocols.get("G", {}).get("feature_variant") != G_DROP3CONSTANT:
        raise MultiSeedRobustnessError("Protocol G must use G-drop3constant in this study")
    if protocols.get("G", {}).get("split") != "duplicate_feature_group_aware_approximately_stratified_60_20_20":
        raise MultiSeedRobustnessError("Protocol G must retain its group-aware approximately 60/20/20 split")


def validate_execution_request(
    *,
    protocols: Sequence[str] = CANONICAL_PROTOCOLS,
    split_seeds: Sequence[int] = OFFICIAL_SPLIT_SEEDS,
    models: Sequence[str] = MODEL_NAMES,
) -> dict[str, Any]:
    """Validate a requested matrix and label non-full matrices as non-official."""
    normalized_protocols = tuple(dict.fromkeys(protocol.upper() for protocol in protocols))
    normalized_seeds = tuple(dict.fromkeys(int(seed) for seed in split_seeds))
    normalized_models = tuple(dict.fromkeys(models))
    if not normalized_protocols or any(protocol not in CANONICAL_PROTOCOLS for protocol in normalized_protocols):
        raise MultiSeedRobustnessError("Protocols must be a non-empty selection of P and/or G")
    if not normalized_seeds or any(seed not in OFFICIAL_SPLIT_SEEDS for seed in normalized_seeds):
        raise MultiSeedRobustnessError(f"Split seeds must be selected from {OFFICIAL_SPLIT_SEEDS}")
    if not normalized_models or any(model not in MODEL_NAMES for model in normalized_models):
        raise MultiSeedRobustnessError(f"Models must be selected from {MODEL_NAMES}")
    official_matrix = (
        normalized_protocols == CANONICAL_PROTOCOLS
        and normalized_seeds == OFFICIAL_SPLIT_SEEDS
        and normalized_models == MODEL_NAMES
    )
    return {
        "protocols": normalized_protocols,
        "split_seeds": normalized_seeds,
        "models": normalized_models,
        "matrix_status": "official_fixed_matrix" if official_matrix else "partial_nonofficial_matrix",
        "model_random_state": FIXED_MODEL_RANDOM_STATE,
    }


def _expected_seed42_p_counts(summary: dict[str, Any]) -> None:
    expected = {
        "train": {"row_count": 18252, "benign_label_0_count": 9926, "malicious_label_1_count": 8326},
        "test": {"row_count": 6085, "benign_label_0_count": 3309, "malicious_label_1_count": 2776},
    }
    observed = summary["stratification"]["split_statistics"]
    for split_name, expected_counts in expected.items():
        actual = observed.get(split_name, {})
        if any(actual.get(key) != value for key, value in expected_counts.items()):
            raise MultiSeedRobustnessError(
                f"Protocol P seed-42 split invariant failed for {split_name}: {actual}"
            )


def _expected_seed42_g_counts(summary: dict[str, Any]) -> None:
    expected = {
        "train": {"rows": 14602, "groups": 8600, "label_0": 7941, "label_1": 6661},
        "validation": {"rows": 4868, "groups": 3386, "label_0": 2647, "label_1": 2221},
        "test": {"rows": 4867, "groups": 3385, "label_0": 2647, "label_1": 2220},
    }
    observed = summary["partition_statistics"]
    if observed != expected:
        raise MultiSeedRobustnessError(f"Protocol G seed-42 split invariants failed: {observed}")


def _baseline_reference_paths(root: Path, config: dict[str, Any]) -> dict[str, Path]:
    reuse = config.get("seed42_baseline_reuse")
    if not isinstance(reuse, dict):
        raise MultiSeedRobustnessError("Configuration lacks seed42 baseline references")
    result: dict[str, Path] = {}
    for name in ("protocol_p_metrics", "protocol_g_metrics"):
        relative = reuse.get(name)
        if not isinstance(relative, str):
            raise MultiSeedRobustnessError(f"Configuration lacks {name}")
        selected = (root / relative).resolve()
        if not selected.is_relative_to(root) or not selected.is_file():
            raise MultiSeedRobustnessError(f"Required seed-42 baseline source is unavailable: {selected}")
        result[name] = selected
    return result


def _baseline_references(root: Path, config: dict[str, Any]) -> dict[str, Any]:
    paths = _baseline_reference_paths(root, config)
    sources: dict[str, Any] = {}
    for name, path in paths.items():
        payload = _read_json(path)
        runs = payload.get("runs")
        if not isinstance(runs, list) or len(runs) != 10:
            raise MultiSeedRobustnessError(f"Seed-42 baseline matrix is incomplete: {path}")
        if any(record.get("status") != "completed" for record in runs):
            raise MultiSeedRobustnessError(f"Seed-42 baseline contains failed runs: {path}")
        sources[name] = {
            "path": str(path),
            "sha256": sha256_file(path),
            "benchmark_code_commit": runs[0].get("environment", {}).get("git_commit_sha"),
            "run_count": len(runs),
        }
    return sources


def preflight_multiseed_run(
    repository_root: str | Path,
    dataset_path: str | Path,
    config: dict[str, Any],
    *,
    require_clean_git: bool = True,
) -> MultiSeedPreflight:
    """Verify data, seed-42 sources, manifests, and Git provenance before fitting."""
    validate_multiseed_configuration(config)
    root = Path(repository_root).resolve()
    data_path = Path(dataset_path).resolve()
    git_state = repository_git_state(root)
    if require_clean_git and git_state.get("status") != "clean":
        raise MultiSeedRobustnessError(
            "Refusing official robustness execution because the repository is not clean: "
            f"{git_state.get('status')}"
        )

    frame = load_rit_pdfmal(data_path)
    if TARGET_COLUMN not in frame.columns:
        raise MultiSeedRobustnessError(f"Expected target column {TARGET_COLUMN!r} is absent")
    dataset_sha256 = sha256_file(data_path)
    if dataset_sha256 != VERIFIED_DATASET_SHA256:
        raise MultiSeedRobustnessError(
            f"Dataset SHA-256 does not match the fixed protocol: {dataset_sha256}"
        )
    environment = collect_environment_metadata(data_path, root)
    if require_clean_git and environment["git_commit_sha"] == "unavailable":
        raise MultiSeedRobustnessError("Unable to record the full benchmark-generating Git commit")
    benchmark_code_commit = str(environment["git_commit_sha"])
    if require_clean_git and len(benchmark_code_commit) != 40:
        raise MultiSeedRobustnessError("Benchmark-generating Git commit must be a full SHA")

    p_manifest, _, p_validation = load_saved_protocol_p_split(
        frame, dataset_sha256, DEFAULT_PROTOCOL_P_SEED, root
    )
    _expected_seed42_p_counts(p_validation)
    g_manifest, _, g_summary = load_saved_protocol_g_split(
        frame, dataset_sha256, root, seed=DEFAULT_SPLIT_SEED, enforce_expected_invariants=True
    )
    _expected_seed42_g_counts(g_summary)
    references = _baseline_references(root, config)
    return MultiSeedPreflight(
        dataset_path=data_path,
        dataset_sha256=dataset_sha256,
        frame=frame,
        environment=environment,
        benchmark_code_commit=benchmark_code_commit,
        baseline_references=references,
        protocol_p_seed42_manifest=p_manifest,
        protocol_g_seed42_manifest=g_manifest,
        protocol_p_seed42_summary=p_validation,
        protocol_g_seed42_summary=g_summary,
    )


def _json_safe_write(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def _create_output_directories(paths: MultiSeedPaths) -> None:
    targets = (paths.reports_directory, paths.processed_directory, paths.artifact_directory)
    if any(path.exists() for path in targets):
        raise FileExistsError(f"Robustness run already exists; refusing to overwrite: {paths.run_id}")
    paths.reports_directory.mkdir(parents=True, exist_ok=False)
    paths.configuration_directory.mkdir(parents=True, exist_ok=False)
    paths.split_summaries_directory.mkdir(parents=True, exist_ok=False)
    paths.per_seed_directory.mkdir(parents=True, exist_ok=False)
    paths.aggregate_directory.mkdir(parents=True, exist_ok=False)
    paths.processed_directory.mkdir(parents=True, exist_ok=False)
    (paths.artifact_directory / "models").mkdir(parents=True, exist_ok=False)


def _assert_multiseed_manifest_destination(path: Path, paths: MultiSeedPaths) -> None:
    resolved = path.resolve()
    if not resolved.is_relative_to(paths.processed_directory.resolve()):
        raise MultiSeedRobustnessError("Multi-seed manifests must stay inside their dedicated run path")
    components = {part.casefold() for part in resolved.parts}
    if "protocol_p" in components or "protocol_g" in components:
        raise MultiSeedRobustnessError("Refusing to write a multi-seed manifest over a P/G path")
    if resolved.exists():
        raise FileExistsError(f"Refusing to overwrite existing multi-seed manifest: {resolved}")


def create_seed_split_manifests(
    frame: pd.DataFrame,
    dataset_sha256: str,
    *,
    seed: int,
) -> dict[str, tuple[pd.DataFrame, dict[str, Any]]]:
    """Build P/G manifests in memory using their distinct documented methods."""
    protocol_p_manifest, protocol_p_result = create_protocol_p_split(
        frame, dataset_sha256, seed=seed
    )
    protocol_g_manifest, protocol_g_result = create_rit_pdfmal_split(frame, seed=seed)
    protocol_g_manifest = protocol_g_manifest.assign(seed=seed, dataset_sha256=dataset_sha256)

    validate_protocol_p_manifest(frame, protocol_p_manifest)
    validate_split_manifest(frame, protocol_g_manifest)
    _validate_manifest_against_frame(frame, protocol_g_manifest)
    return {
        "P": (protocol_p_manifest, protocol_p_result),
        "G": (protocol_g_manifest, protocol_g_result),
    }


def persist_seed_split_manifests(
    paths: MultiSeedPaths,
    split_manifests: dict[str, tuple[pd.DataFrame, dict[str, Any]]],
    *,
    seed: int,
) -> dict[str, dict[str, Any]]:
    """Persist new (non-42) derived manifests without touching P/G baseline paths."""
    persisted: dict[str, dict[str, Any]] = {}
    for protocol, (manifest, result) in split_manifests.items():
        destination = paths.processed_directory / f"protocol_{protocol.lower()}_seed{seed}_manifest.csv"
        _assert_multiseed_manifest_destination(destination, paths)
        manifest.to_csv(destination, index=False)
        persisted[protocol] = {
            "path": str(destination),
            "sha256": sha256_file(destination),
            "split_result": result,
        }
    return persisted


def _named_metrics(metrics: dict[str, Any], counts: dict[str, Any]) -> dict[str, float | int | None]:
    values: dict[str, float | int | None] = {}
    for metric in CANONICAL_METRICS[:10]:
        value = metrics.get(metric)
        values[metric] = None if value is None else float(value)
    for metric in CANONICAL_METRICS[10:]:
        value = counts.get(metric)
        values[metric] = None if value is None else int(value)
    return values


def multiseed_result_schema_is_valid(record: dict[str, Any]) -> bool:
    """Validate provenance and explicit metric semantics of one protocol/seed/model result."""
    required = {
        "protocol", "split_seed", "model_random_state", "model_name", "feature_variant",
        "status", "dataset_sha256", "split_manifest", "split_manifest_sha256", "evaluations",
        "model_configuration", "preprocessing_configuration", "benchmark_code_commit", "environment", "error",
    }
    if not required.issubset(record) or record.get("protocol") not in CANONICAL_PROTOCOLS:
        return False
    if record.get("model_random_state") != FIXED_MODEL_RANDOM_STATE:
        return False
    if record.get("status") == "failed":
        return isinstance(record.get("error"), dict)
    if record.get("status") != "completed" or record.get("error") is not None:
        return False
    evaluations = record.get("evaluations")
    required_partitions = {"test"} if record["protocol"] == "P" else {"validation", "test"}
    if not isinstance(evaluations, dict) or set(evaluations) != required_partitions:
        return False
    for evaluation in evaluations.values():
        if not isinstance(evaluation, dict):
            return False
        metrics = evaluation.get("metrics")
        if not isinstance(metrics, dict) or not set(CANONICAL_METRICS).issubset(metrics):
            return False
    return True


def _record_template(
    *,
    protocol: str,
    seed: int,
    model_name: str,
    feature_variant: str,
    feature_count: int,
    dataset_sha256: str,
    split_manifest: str,
    split_manifest_sha256: str,
    split_result: dict[str, Any],
    model_configuration: dict[str, Any],
    benchmark_code_commit: str,
    environment: dict[str, Any],
    reused_seed42_baseline: bool,
) -> dict[str, Any]:
    return {
        "protocol": protocol,
        "split_seed": seed,
        "model_random_state": FIXED_MODEL_RANDOM_STATE,
        "model_name": model_name,
        "feature_variant": feature_variant,
        "feature_count": feature_count,
        "status": "pending",
        "timestamp_utc": _timestamp_utc(),
        "dataset_sha256": dataset_sha256,
        "split_manifest": split_manifest,
        "split_manifest_sha256": split_manifest_sha256,
        "split_result": split_result,
        "model_configuration": model_configuration,
        "preprocessing_configuration": model_configuration["preprocessing"],
        "benchmark_code_commit": benchmark_code_commit,
        "environment": environment,
        "reused_seed42_baseline": reused_seed42_baseline,
        "evaluations": {},
        "training": None,
        "model_artifact": None,
        "error": None,
    }


def _evaluation_payload(
    labels: pd.Series,
    predictions: Any,
    scores: Any,
    score_source: str | None,
    runtime: dict[str, Any],
) -> dict[str, Any]:
    metrics = evaluate_binary_predictions(labels, predictions, scores)
    metrics["score_source"] = score_source
    matrix = metrics["confusion_matrix"]
    counts = {"tn": int(matrix[0][0]), "fp": int(matrix[0][1]), "fn": int(matrix[1][0]), "tp": int(matrix[1][1])}
    return {
        "metrics": _named_metrics(metrics, counts),
        "score_source": score_source,
        "runtime": runtime,
        "confusion_counts": counts,
    }


def _execute_protocol_p_record(
    frame: pd.DataFrame,
    manifest: pd.DataFrame,
    manifest_path: Path,
    split_result: dict[str, Any],
    *,
    seed: int,
    model_name: str,
    dataset_sha256: str,
    benchmark_code_commit: str,
    environment: dict[str, Any],
    artifact_directory: Path,
    model_factory: Callable[[str, int], Any],
) -> dict[str, Any]:
    configuration = model_configurations(FIXED_MODEL_RANDOM_STATE)[model_name]
    features = protocol_p_feature_columns(frame, P_DROP3CONSTANT.name)
    record = _record_template(
        protocol="P", seed=seed, model_name=model_name, feature_variant=P_DROP3CONSTANT.name,
        feature_count=len(features), dataset_sha256=dataset_sha256, split_manifest=str(manifest_path),
        split_manifest_sha256=sha256_file(manifest_path), split_result=split_result,
        model_configuration=configuration, benchmark_code_commit=benchmark_code_commit,
        environment=environment,
        reused_seed42_baseline=False,
    )
    try:
        train_frame, test_frame = split_frame_from_manifest(frame, manifest)
        set_random_seed(FIXED_MODEL_RANDOM_STATE)
        estimator = model_factory(model_name, FIXED_MODEL_RANDOM_STATE)
        predictions, scores, source, runtime = fit_predict_and_measure(
            estimator,
            protocol_p_feature_view(train_frame, P_DROP3CONSTANT.name),
            train_frame[TARGET_COLUMN],
            protocol_p_feature_view(test_frame, P_DROP3CONSTANT.name),
        )
        artifact = artifact_directory / f"p_seed{seed}_{model_name}.joblib"
        joblib.dump(estimator, artifact)
        record.update({
            "status": "completed",
            "training": {"training_seconds": runtime["training_seconds"]},
            "evaluations": {"test": _evaluation_payload(
                test_frame[TARGET_COLUMN], predictions, scores, source,
                {"inference_total_seconds": runtime["test_inference_total_seconds"], "inference_milliseconds_per_sample": runtime["test_inference_milliseconds_per_sample"]},
            )},
            "model_artifact": str(artifact),
        })
    except Exception as error:
        record.update({"status": "failed", "error": {"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()}})
    if not multiseed_result_schema_is_valid(record):
        raise MultiSeedRobustnessError(f"Invalid Protocol P result schema for seed {seed}, {model_name}")
    return record


def _execute_protocol_g_record(
    frame: pd.DataFrame,
    manifest: pd.DataFrame,
    manifest_path: Path,
    split_result: dict[str, Any],
    *,
    seed: int,
    model_name: str,
    dataset_sha256: str,
    benchmark_code_commit: str,
    environment: dict[str, Any],
    artifact_directory: Path,
    model_factory: Callable[[str, int], Any],
) -> dict[str, Any]:
    configuration = model_configurations(FIXED_MODEL_RANDOM_STATE)[model_name]
    features = protocol_g_feature_columns(frame, G_DROP3CONSTANT)
    record = _record_template(
        protocol="G", seed=seed, model_name=model_name, feature_variant=G_DROP3CONSTANT,
        feature_count=len(features), dataset_sha256=dataset_sha256, split_manifest=str(manifest_path),
        split_manifest_sha256=sha256_file(manifest_path), split_result=split_result,
        model_configuration=configuration, benchmark_code_commit=benchmark_code_commit,
        environment=environment,
        reused_seed42_baseline=False,
    )
    try:
        partitions = split_frame_from_protocol_g_manifest(frame, manifest)
        set_random_seed(FIXED_MODEL_RANDOM_STATE)
        estimator = model_factory(model_name, FIXED_MODEL_RANDOM_STATE)
        validation_predictions, validation_scores, validation_source, training_runtime = fit_predict_and_measure(
            estimator,
            protocol_g_feature_view(partitions["train"], G_DROP3CONSTANT),
            partitions["train"][TARGET_COLUMN],
            protocol_g_feature_view(partitions["validation"], G_DROP3CONSTANT),
        )
        test_predictions, test_scores, test_source, test_runtime = predict_and_measure(
            estimator, protocol_g_feature_view(partitions["test"], G_DROP3CONSTANT)
        )
        artifact = artifact_directory / f"g_seed{seed}_{model_name}.joblib"
        joblib.dump(estimator, artifact)
        record.update({
            "status": "completed",
            "training": {"training_seconds": training_runtime["training_seconds"]},
            "evaluations": {
                "validation": _evaluation_payload(
                    partitions["validation"][TARGET_COLUMN], validation_predictions, validation_scores,
                    validation_source, {"inference_total_seconds": training_runtime["test_inference_total_seconds"], "inference_milliseconds_per_sample": training_runtime["test_inference_milliseconds_per_sample"]},
                ),
                "test": _evaluation_payload(
                    partitions["test"][TARGET_COLUMN], test_predictions, test_scores, test_source, test_runtime
                ),
            },
            "model_artifact": str(artifact),
        })
    except Exception as error:
        record.update({"status": "failed", "error": {"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()}})
    if not multiseed_result_schema_is_valid(record):
        raise MultiSeedRobustnessError(f"Invalid Protocol G result schema for seed {seed}, {model_name}")
    return record


def _seed42_records(
    root: Path,
    preflight: MultiSeedPreflight,
    models: Sequence[str],
    protocols: Sequence[str],
) -> list[dict[str, Any]]:
    """Convert completed immutable baselines to the new explicit metric schema."""
    result: list[dict[str, Any]] = []
    sources = {
        "P": Path(preflight.baseline_references["protocol_p_metrics"]["path"]),
        "G": Path(preflight.baseline_references["protocol_g_metrics"]["path"]),
    }
    manifests = {
        "P": preflight.protocol_p_seed42_manifest,
        "G": preflight.protocol_g_seed42_manifest,
    }
    summaries = {"P": preflight.protocol_p_seed42_summary, "G": preflight.protocol_g_seed42_summary}
    variants = {"P": P_DROP3CONSTANT.name, "G": G_DROP3CONSTANT}
    for protocol in protocols:
        payload = _read_json(sources[protocol])
        for source in payload["runs"]:
            if source.get("model_name") not in models or source.get("feature_variant") != variants[protocol]:
                continue
            configuration = source["model_configuration"]
            record = _record_template(
                protocol=protocol, seed=42, model_name=source["model_name"], feature_variant=variants[protocol],
                feature_count=int(source["feature_count"]), dataset_sha256=preflight.dataset_sha256,
                split_manifest=str(manifests[protocol]), split_manifest_sha256=sha256_file(manifests[protocol]),
                split_result=summaries[protocol], model_configuration=configuration,
                benchmark_code_commit=str(source["environment"]["git_commit_sha"]),
                environment=source["environment"], reused_seed42_baseline=True,
            )
            if protocol == "P":
                metrics = source["metrics"]
                counts = source["confusion_counts"]
                record.update({
                    "status": "completed", "training": source["runtime"],
                    "evaluations": {"test": {
                        "metrics": _named_metrics(_derive_explicit_metrics(metrics, counts), counts),
                        "score_source": metrics.get("score_source"), "runtime": source["runtime"],
                        "confusion_counts": counts,
                    }},
                })
            else:
                evaluations: dict[str, Any] = {}
                for partition in ("validation", "test"):
                    source_evaluation = source[partition]
                    metrics = source_evaluation["metrics"]
                    counts = source_evaluation["confusion_counts"]
                    evaluations[partition] = {
                        "metrics": _named_metrics(_derive_explicit_metrics(metrics, counts), counts),
                        "score_source": metrics.get("score_source"), "runtime": source_evaluation["runtime"],
                        "confusion_counts": counts,
                    }
                record.update({"status": "completed", "training": source["training"], "evaluations": evaluations})
            if not multiseed_result_schema_is_valid(record):
                raise MultiSeedRobustnessError(f"Seed-42 baseline record is incompatible: {protocol} {source['model_name']}")
            result.append(record)
    expected = len(protocols) * len(models)
    if len(result) != expected:
        raise MultiSeedRobustnessError("Seed-42 baseline lacks the requested canonical model/variant results")
    return result


def _derive_explicit_metrics(metrics: dict[str, Any], counts: dict[str, Any]) -> dict[str, Any]:
    """Backfill named metrics from frozen historical confusion matrices only."""
    from malpdf.evaluation.binary import classification_metrics_from_confusion_counts

    explicit = classification_metrics_from_confusion_counts(
        tn=int(counts["tn"]), fp=int(counts["fp"]), fn=int(counts["fn"]), tp=int(counts["tp"])
    )
    for metric in ("accuracy", "roc_auc", "pr_auc", "mcc"):
        explicit[metric] = metrics.get(metric)
    return explicit


def _completed_metric_values(
    records: Iterable[dict[str, Any]],
    *,
    protocol: str,
    partition: str,
    model_name: str,
    expected_seeds: Sequence[int],
) -> tuple[dict[int, dict[str, float | int | None]], list[int]]:
    by_seed: dict[int, dict[str, float | int | None]] = {}
    failed_or_missing: list[int] = []
    for seed in expected_seeds:
        matching = [
            record for record in records
            if record["protocol"] == protocol and record["split_seed"] == seed and record["model_name"] == model_name
        ]
        if len(matching) != 1 or matching[0]["status"] != "completed":
            failed_or_missing.append(seed)
            continue
        evaluation = matching[0]["evaluations"].get(partition)
        if not isinstance(evaluation, dict):
            failed_or_missing.append(seed)
            continue
        by_seed[seed] = evaluation["metrics"]
    return by_seed, failed_or_missing


def aggregate_multiseed_results(
    records: Sequence[dict[str, Any]],
    *,
    split_seeds: Sequence[int] = OFFICIAL_SPLIT_SEEDS,
    models: Sequence[str] = MODEL_NAMES,
    protocols: Sequence[str] = CANONICAL_PROTOCOLS,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return sample-statistics and paired G-minus-P deltas with failure coverage."""
    aggregate_rows: list[dict[str, Any]] = []
    for protocol in protocols:
        partitions = ("test",) if protocol == "P" else ("validation", "test")
        variant = P_DROP3CONSTANT.name if protocol == "P" else G_DROP3CONSTANT
        for partition in partitions:
            for model_name in models:
                values_by_seed, failed_or_missing = _completed_metric_values(
                    records, protocol=protocol, partition=partition, model_name=model_name,
                    expected_seeds=split_seeds,
                )
                for metric in CANONICAL_METRICS:
                    values = [float(value[metric]) for value in values_by_seed.values() if value.get(metric) is not None]
                    missing_metric_seeds = [
                        seed for seed, value in values_by_seed.items() if value.get(metric) is None
                    ]
                    unavailable = sorted(set(failed_or_missing + missing_metric_seeds))
                    aggregate_rows.append({
                        "protocol": protocol, "partition": partition, "model_name": model_name,
                        "feature_variant": variant, "metric": metric,
                        "expected_seed_count": len(split_seeds), "completed_seed_count": len(values),
                        "missing_or_failed_seed_count": len(unavailable), "missing_or_failed_seeds": unavailable,
                        "n": len(values), "mean": None if not values else statistics.fmean(values),
                        "sample_standard_deviation": None if len(values) < 2 else statistics.stdev(values),
                        "minimum": None if not values else min(values), "median": None if not values else statistics.median(values),
                        "maximum": None if not values else max(values),
                    })

    paired_rows: list[dict[str, Any]] = []
    if set(protocols) == set(CANONICAL_PROTOCOLS):
        for model_name in models:
            p_values, p_missing = _completed_metric_values(
                records, protocol="P", partition="test", model_name=model_name, expected_seeds=split_seeds
            )
            g_values, g_missing = _completed_metric_values(
                records, protocol="G", partition="test", model_name=model_name, expected_seeds=split_seeds
            )
            for metric in CANONICAL_METRICS:
                deltas: list[float] = []
                unavailable = set(p_missing + g_missing)
                for seed in split_seeds:
                    p_value = p_values.get(seed, {}).get(metric)
                    g_value = g_values.get(seed, {}).get(metric)
                    if p_value is None or g_value is None:
                        unavailable.add(seed)
                        continue
                    deltas.append(float(g_value) - float(p_value))
                paired_rows.append({
                    "comparison": "Protocol G test minus Protocol P test", "model_name": model_name,
                    "metric": metric, "expected_seed_count": len(split_seeds), "paired_seed_count": len(deltas),
                    "missing_or_failed_seed_count": len(unavailable), "missing_or_failed_seeds": sorted(unavailable),
                    "mean_delta": None if not deltas else statistics.fmean(deltas),
                    "sample_standard_deviation": None if len(deltas) < 2 else statistics.stdev(deltas),
                    "minimum_delta": None if not deltas else min(deltas), "median_delta": None if not deltas else statistics.median(deltas),
                    "maximum_delta": None if not deltas else max(deltas),
                    "g_greater_count": sum(delta > 0 for delta in deltas),
                    "p_greater_count": sum(delta < 0 for delta in deltas),
                    "equal_count": sum(math.isclose(delta, 0.0, abs_tol=1e-12) for delta in deltas),
                })
    return aggregate_rows, paired_rows


def _summary_rows(records: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in records:
        for partition, evaluation in record.get("evaluations", {}).items():
            rows.append({
                "protocol": record["protocol"], "partition": partition, "split_seed": record["split_seed"],
                "model_name": record["model_name"], "feature_variant": record["feature_variant"],
                "status": record["status"], "reused_seed42_baseline": record["reused_seed42_baseline"],
                **evaluation["metrics"],
                "training_seconds": None if record.get("training") is None else record["training"].get("training_seconds"),
                "inference_total_seconds": evaluation["runtime"].get("inference_total_seconds"),
                "inference_milliseconds_per_sample": evaluation["runtime"].get("inference_milliseconds_per_sample"),
            })
    return rows


def _write_run_outputs(
    paths: MultiSeedPaths,
    *,
    configuration: dict[str, Any],
    preflight: MultiSeedPreflight,
    records: Sequence[dict[str, Any]],
    aggregate_rows: Sequence[dict[str, Any]],
    paired_rows: Sequence[dict[str, Any]],
) -> None:
    _json_safe_write(paths.environment_json, preflight.environment)
    _json_safe_write(paths.experiment_config_json, configuration)
    paths.fixed_design_yaml.write_text(
        yaml.safe_dump(configuration["fixed_design"], sort_keys=False), encoding="utf-8"
    )
    _json_safe_write(paths.preflight_json, {
        "dataset_sha256": preflight.dataset_sha256,
        "benchmark_code_commit": preflight.benchmark_code_commit,
        "baseline_references": preflight.baseline_references,
        "protocol_p_seed42_manifest": str(preflight.protocol_p_seed42_manifest),
        "protocol_g_seed42_manifest": str(preflight.protocol_g_seed42_manifest),
    })
    _json_safe_write(paths.metrics_json, {"experiment": configuration, "runs": list(records)})
    for seed in sorted({int(record["split_seed"]) for record in records}):
        seed_directory = paths.per_seed_directory / f"seed{seed}"
        seed_directory.mkdir(parents=True, exist_ok=False)
        seed_records = [record for record in records if int(record["split_seed"]) == seed]
        _json_safe_write(seed_directory / "metrics.json", {
            "experiment_run_id": paths.run_id,
            "split_seed": seed,
            "runs": seed_records,
        })
        split_sources: dict[str, Any] = {}
        for protocol in ("P", "G"):
            protocol_records = [record for record in seed_records if record["protocol"] == protocol]
            if protocol_records:
                first = protocol_records[0]
                split_sources[protocol] = {
                    "split_manifest": first["split_manifest"],
                    "split_manifest_sha256": first["split_manifest_sha256"],
                    "split_result": first["split_result"],
                    "dataset_sha256": first["dataset_sha256"],
                    "reused_seed42_baseline": first["reused_seed42_baseline"],
                }
        _json_safe_write(paths.split_summaries_directory / f"seed{seed}.json", {
            "split_seed": seed,
            "protocols": split_sources,
        })
    pd.DataFrame(_summary_rows(records)).to_csv(paths.summary_csv, index=False)
    pd.DataFrame(aggregate_rows).to_csv(paths.aggregate_metrics_csv, index=False)
    pd.DataFrame(paired_rows).to_csv(paths.paired_deltas_csv, index=False)
    completed = sum(record["status"] == "completed" for record in records)
    paths.run_summary_markdown.write_text(
        "\n".join([
            "# Protocol P versus Protocol G multi-seed robustness run", "",
            f"- Run ID: `{paths.run_id}`", f"- Benchmark-generating code commit: `{preflight.benchmark_code_commit}`",
            f"- Completed records: {completed}; failed records: {len(records) - completed}.",
            "- Split seeds vary while model_random_state remains fixed at 42.",
            "- Seed 42 is reused from immutable completed baselines; it is not regenerated.",
            "- Protocol G groups are identical static feature vectors, not proven duplicate PDF files.",
            "- This output reports split sensitivity only; no tuning, selection, or cross-validation is performed.", "",
        ]), encoding="utf-8"
    )


def run_multiseed_robustness(
    repository_root: str | Path,
    dataset_path: str | Path,
    config_path: str | Path,
    *,
    run_id: str | None = None,
    protocols: Sequence[str] = CANONICAL_PROTOCOLS,
    split_seeds: Sequence[int] = OFFICIAL_SPLIT_SEEDS,
    models: Sequence[str] = MODEL_NAMES,
    execute: bool = False,
    require_clean_git: bool = True,
    model_factory: Callable[[str, int], Any] = create_model,
) -> tuple[MultiSeedPreflight, MultiSeedPaths | None, list[dict[str, Any]]]:
    """Preflight the fixed study, or explicitly execute it in a new immutable path.

    Preflight is intentionally side-effect free.  ``execute=False`` is the CLI
    default so an official fit cannot start accidentally.  Seed 42 is always
    read from completed source reports; only seeds 43--46 create new manifests.
    """
    config = load_multiseed_configuration(config_path)
    request = validate_execution_request(protocols=protocols, split_seeds=split_seeds, models=models)
    preflight = preflight_multiseed_run(
        repository_root, dataset_path, config, require_clean_git=require_clean_git
    )
    if not execute:
        return preflight, None, []

    root = Path(repository_root).resolve()
    identifier = run_id or f"robustness-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}"
    paths = multiseed_paths(root, identifier)
    _create_output_directories(paths)
    configuration = {
        "experiment": config["experiment"], "experiment_run_id": paths.run_id,
        "dataset_sha256": preflight.dataset_sha256, "benchmark_code_commit": preflight.benchmark_code_commit,
        "git_working_tree_at_start": preflight.environment["git_working_tree"], "request": request,
        "fixed_design": config, "timestamp_utc": _timestamp_utc(),
        "methodological_note": "Protocol P is paper-aligned; Protocol G is stricter feature-vector-disjoint evaluation. They are not directly equivalent paper reproductions.",
    }
    records = _seed42_records(root, preflight, request["models"], request["protocols"])
    failures: list[str] = []
    for seed in request["split_seeds"]:
        if seed == 42:
            continue
        manifests = create_seed_split_manifests(preflight.frame, preflight.dataset_sha256, seed=seed)
        persisted = persist_seed_split_manifests(paths, manifests, seed=seed)
        for protocol in request["protocols"]:
            manifest, split_result = manifests[protocol]
            manifest_path = Path(persisted[protocol]["path"])
            for model_name in request["models"]:
                executor = _execute_protocol_p_record if protocol == "P" else _execute_protocol_g_record
                record = executor(
                    preflight.frame, manifest, manifest_path, split_result, seed=seed, model_name=model_name,
                    dataset_sha256=preflight.dataset_sha256, benchmark_code_commit=preflight.benchmark_code_commit,
                    environment=preflight.environment, artifact_directory=paths.artifact_directory / "models",
                    model_factory=model_factory,
                )
                records.append(record)
                if record["status"] == "failed":
                    failures.append(f"{protocol}:seed{seed}:{model_name}")

    aggregate_rows, paired_rows = aggregate_multiseed_results(
        records, split_seeds=request["split_seeds"], models=request["models"], protocols=request["protocols"]
    )

    for source in preflight.baseline_references.values():
        if sha256_file(source["path"]) != source["sha256"]:
            raise MultiSeedRobustnessError("A seed-42 baseline source changed during robustness execution")
    _write_run_outputs(paths, configuration=configuration, preflight=preflight, records=records,
                       aggregate_rows=aggregate_rows, paired_rows=paired_rows)
    if failures:
        raise MultiSeedRobustnessError(
            "Robustness execution has failed records; partial outputs preserve the errors: " + ", ".join(failures)
        )
    return preflight, paths, records

"""Reproducible, report-only comparison of the seed-42 Protocol P and G baselines.

This module reads committed machine-readable reports.  It never reads the raw
dataset, fits estimators, changes a split, or writes into either baseline
result directory.  Protocol G groups are identical static feature vectors;
they are not evidence of duplicate PDF files because the published CSV has no
per-PDF hash column.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


DATASET_SHA256 = "2f270ab31fbfe8821fd7f54608cb1aa694a0a8d0bbf2ca000942a68213ef8623"
SEED = 42
PROTOCOL_P_RESULT_COMMIT = "ed50bd9e4e9cd0268c9e2359a89a1867dad68095"
PROTOCOL_P_TAG = "v0.3.0-protocol-p-baseline"
PROTOCOL_P_BENCHMARK_COMMIT = "3e970ef2df0460fb4a51b10418c9af7564339419"
PROTOCOL_G_RESULT_COMMIT = "30b4e1b676a674424e004035fc8ffb8d9c615ad6"
PROTOCOL_G_TAG = "v0.4.0-protocol-g-baseline"
PROTOCOL_G_BENCHMARK_COMMIT = "c2aefaaca8cd2257ed610efeba88f24a7cbbb460"

MODEL_ORDER = (
    "logistic_regression",
    "random_forest",
    "decision_tree",
    "gaussian_naive_bayes",
    "xgboost",
)
MODEL_LABELS = {
    "logistic_regression": "Logistic Regression",
    "random_forest": "Random Forest",
    "decision_tree": "Decision Tree",
    "gaussian_naive_bayes": "GaussianNB",
    "xgboost": "XGBoost",
}
MODEL_PLOT_LABELS = {
    "logistic_regression": "LR",
    "random_forest": "RF",
    "decision_tree": "DT",
    "gaussian_naive_bayes": "GNB",
    "xgboost": "XGB",
}
METRICS = ("accuracy", "precision", "recall", "f1", "roc_auc", "pr_auc", "mcc")
VALIDATION_TEST_METRICS = ("f1", "mcc", "recall", "precision", "roc_auc", "pr_auc")
CONSTANT_FEATURE_METRICS = ("f1", "mcc", "roc_auc", "pr_auc")
CONFUSION_COLUMNS = ("tn", "fp", "fn", "tp")

EXPECTED_PAIRINGS = tuple(
    (model_name, p_variant, g_variant)
    for model_name in MODEL_ORDER
    for p_variant, g_variant in (("P-all41", "G-all41"), ("P-drop3constant", "G-drop3constant"))
)

REQUIRED_SOURCE_FILES = {
    "P": (
        "metrics.json",
        "summary.csv",
        "environment.json",
        "experiment_config.json",
        "split_summary.json",
        "run_summary.md",
    ),
    "G": (
        "metrics.json",
        "summary_validation.csv",
        "summary_test.csv",
        "confusion_matrices.json",
        "protocol_p_vs_g.csv",
        "environment.json",
        "experiment_config.json",
        "split_summary.json",
        "run_summary.md",
    ),
}


class ProtocolComparisonError(ValueError):
    """Raised when baseline reports cannot be safely compared."""


@dataclass(frozen=True)
class ProtocolResults:
    """Validated tabular views of the committed baseline metrics."""

    protocol_p_test: pd.DataFrame
    protocol_g_validation: pd.DataFrame
    protocol_g_test: pd.DataFrame
    provenance: dict[str, Any]
    pairings: tuple[tuple[str, str, str], ...]


@dataclass(frozen=True)
class AnalysisOutputPaths:
    """The tracked output locations for the formal comparative analysis."""

    tables_directory: Path
    figures_directory: Path
    markdown_analysis: Path


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ProtocolComparisonError(f"Cannot read JSON result report: {path}") from error
    if not isinstance(payload, dict):
        raise ProtocolComparisonError(f"Expected a JSON object in {path}")
    return payload


def _required_source_paths(protocol_p_directory: Path, protocol_g_directory: Path) -> list[Path]:
    paths: list[Path] = []
    for name in REQUIRED_SOURCE_FILES["P"]:
        path = protocol_p_directory / name
        if not path.is_file():
            raise FileNotFoundError(f"Required Protocol P result report is missing: {path}")
        paths.append(path)
    for name in REQUIRED_SOURCE_FILES["G"]:
        path = protocol_g_directory / name
        if not path.is_file():
            raise FileNotFoundError(f"Required Protocol G result report is missing: {path}")
        paths.append(path)
    return paths


def _expected_feature_count(variant: str) -> int:
    if variant.endswith("all41"):
        return 41
    if variant.endswith("drop3constant"):
        return 38
    raise ProtocolComparisonError(f"Unknown expected feature variant: {variant}")


def _require_metrics(metrics: Any, description: str) -> dict[str, float]:
    if not isinstance(metrics, dict):
        raise ProtocolComparisonError(f"{description} metrics are absent")
    missing = set(METRICS).difference(metrics)
    if missing:
        raise ProtocolComparisonError(f"{description} metrics are missing: {sorted(missing)}")
    if metrics.get("positive_label") != 1:
        raise ProtocolComparisonError(f"{description} must record Label=1 as the positive class")
    try:
        return {metric: float(metrics[metric]) for metric in METRICS}
    except (TypeError, ValueError) as error:
        raise ProtocolComparisonError(f"{description} contains a non-numeric metric") from error


def _require_confusion_counts(counts: Any, description: str) -> dict[str, int]:
    if not isinstance(counts, dict):
        raise ProtocolComparisonError(f"{description} confusion counts are absent")
    missing = set(CONFUSION_COLUMNS).difference(counts)
    if missing:
        raise ProtocolComparisonError(f"{description} confusion counts are missing: {sorted(missing)}")
    try:
        result = {name: int(counts[name]) for name in CONFUSION_COLUMNS}
    except (TypeError, ValueError) as error:
        raise ProtocolComparisonError(f"{description} contains non-integer confusion counts") from error
    if any(value < 0 for value in result.values()):
        raise ProtocolComparisonError(f"{description} contains negative confusion counts")
    return result


def _base_record_fields(record: dict[str, Any], protocol: str, description: str) -> dict[str, Any]:
    if record.get("protocol") != protocol:
        raise ProtocolComparisonError(f"{description} has protocol {record.get('protocol')!r}, expected {protocol!r}")
    if record.get("status") != "completed":
        raise ProtocolComparisonError(f"{description} is not a completed baseline run")
    if record.get("dataset_sha256") != DATASET_SHA256:
        raise ProtocolComparisonError(f"{description} dataset checksum does not match the verified dataset")
    if record.get("split_seed") != SEED:
        raise ProtocolComparisonError(f"{description} seed is not {SEED}")
    environment = record.get("environment")
    if not isinstance(environment, dict) or environment.get("dataset_sha256") != DATASET_SHA256:
        raise ProtocolComparisonError(f"{description} environment dataset provenance does not match")
    expected_commit = PROTOCOL_P_BENCHMARK_COMMIT if protocol == "P" else PROTOCOL_G_BENCHMARK_COMMIT
    if environment.get("git_commit_sha") != expected_commit:
        raise ProtocolComparisonError(f"{description} benchmark-generating commit does not match")
    model_name = record.get("model_name")
    feature_variant = record.get("feature_variant")
    if not isinstance(model_name, str) or not isinstance(feature_variant, str):
        raise ProtocolComparisonError(f"{description} has no model/feature-variant identity")
    if record.get("feature_count") != _expected_feature_count(feature_variant):
        raise ProtocolComparisonError(f"{description} feature count does not match {feature_variant}")
    return {"model_name": model_name, "feature_variant": feature_variant}


def _records_to_frame(document: dict[str, Any], protocol: str) -> tuple[pd.DataFrame, pd.DataFrame | None]:
    records = document.get("runs")
    if not isinstance(records, list):
        raise ProtocolComparisonError(f"Protocol {protocol} metrics report lacks a run list")
    primary_rows: list[dict[str, Any]] = []
    secondary_rows: list[dict[str, Any]] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ProtocolComparisonError(f"Protocol {protocol} run {index} is not an object")
        description = f"Protocol {protocol} run {index}"
        row = _base_record_fields(record, protocol, description)
        if protocol == "P":
            row.update(_require_metrics(record.get("metrics"), description))
            row.update(_require_confusion_counts(record.get("confusion_counts"), description))
            primary_rows.append(row)
            continue
        for partition in ("validation", "test"):
            evaluation = record.get(partition)
            if not isinstance(evaluation, dict):
                raise ProtocolComparisonError(f"{description} lacks a {partition} evaluation")
            partition_row = dict(row)
            partition_row.update(_require_metrics(evaluation.get("metrics"), f"{description} {partition}"))
            partition_row.update(
                _require_confusion_counts(evaluation.get("confusion_counts"), f"{description} {partition}")
            )
            if partition == "validation":
                primary_rows.append(partition_row)
            else:
                secondary_rows.append(partition_row)
    primary = pd.DataFrame(primary_rows)
    secondary = None if protocol == "P" else pd.DataFrame(secondary_rows)
    return primary, secondary


def _validate_pairings(
    protocol_p_test: pd.DataFrame,
    protocol_g_validation: pd.DataFrame,
    protocol_g_test: pd.DataFrame,
    expected_pairings: Sequence[tuple[str, str, str]],
) -> None:
    expected_p = {(model, p_variant) for model, p_variant, _ in expected_pairings}
    expected_g = {(model, g_variant) for model, _, g_variant in expected_pairings}
    actual_p = set(zip(protocol_p_test["model_name"], protocol_p_test["feature_variant"], strict=True))
    actual_g_validation = set(
        zip(protocol_g_validation["model_name"], protocol_g_validation["feature_variant"], strict=True)
    )
    actual_g_test = set(zip(protocol_g_test["model_name"], protocol_g_test["feature_variant"], strict=True))
    if actual_p != expected_p:
        raise ProtocolComparisonError(f"Protocol P model/variant pairs do not match: {sorted(actual_p)}")
    if actual_g_validation != expected_g or actual_g_test != expected_g:
        raise ProtocolComparisonError("Protocol G model/variant pairs do not match the expected baseline matrix")
    for name, frame in (
        ("Protocol P", protocol_p_test),
        ("Protocol G validation", protocol_g_validation),
        ("Protocol G test", protocol_g_test),
    ):
        if frame.duplicated(["model_name", "feature_variant"]).any():
            raise ProtocolComparisonError(f"{name} has repeated model/feature-variant records")


def load_protocol_baseline_reports(
    protocol_p_directory: str | Path,
    protocol_g_directory: str | Path,
    *,
    expected_pairings: Sequence[tuple[str, str, str]] = EXPECTED_PAIRINGS,
) -> ProtocolResults:
    """Load and validate report-only inputs for a P-versus-G comparison."""
    p_directory = Path(protocol_p_directory)
    g_directory = Path(protocol_g_directory)
    _required_source_paths(p_directory, g_directory)
    p_document = _read_json(p_directory / "metrics.json")
    g_document = _read_json(g_directory / "metrics.json")
    p_test, _ = _records_to_frame(p_document, "P")
    g_validation, g_test = _records_to_frame(g_document, "G")
    assert g_test is not None
    _validate_pairings(p_test, g_validation, g_test, expected_pairings)
    provenance = {
        "dataset_sha256": DATASET_SHA256,
        "seed": SEED,
        "protocol_p_benchmark_generating_commit": PROTOCOL_P_BENCHMARK_COMMIT,
        "protocol_g_benchmark_generating_commit": PROTOCOL_G_BENCHMARK_COMMIT,
        "protocol_p_result_directory": str(p_directory),
        "protocol_g_result_directory": str(g_directory),
    }
    return ProtocolResults(p_test, g_validation, g_test, provenance, tuple(expected_pairings))


def normalized_confusion_rates(*, tn: int, fp: int, fn: int, tp: int) -> dict[str, float]:
    """Compute error rates using their class-specific denominators."""
    negative_total = tn + fp
    positive_total = fn + tp
    if negative_total <= 0 or positive_total <= 0:
        raise ProtocolComparisonError("Confusion rates require both negative and positive samples")
    return {
        "false_positive_rate": fp / negative_total,
        "false_negative_rate": fn / positive_total,
        "true_positive_rate_recall": tp / positive_total,
        "true_negative_rate_specificity": tn / negative_total,
    }


def _pair_frames(results: ProtocolResults) -> pd.DataFrame:
    mapping = pd.DataFrame(
        results.pairings,
        columns=["model_name", "p_feature_variant", "g_feature_variant"],
    )
    p_frame = results.protocol_p_test.rename(columns={"feature_variant": "p_feature_variant"})
    g_frame = results.protocol_g_test.rename(columns={"feature_variant": "g_feature_variant"})
    paired = mapping.merge(
        p_frame,
        on=["model_name", "p_feature_variant"],
        how="inner",
        validate="one_to_one",
    )
    paired = paired.merge(
        g_frame,
        on=["model_name", "g_feature_variant"],
        how="inner",
        validate="one_to_one",
        suffixes=("_p", "_g_test"),
    )
    if len(paired) != len(results.pairings):
        raise ProtocolComparisonError("Could not form every expected P/G model/variant pairing")
    return paired


def build_comparison_tables(results: ProtocolResults) -> dict[str, pd.DataFrame]:
    """Derive every thesis table from validated baseline metric records."""
    paired = _pair_frames(results)
    combined_rows: list[dict[str, Any]] = []
    delta_rows: list[dict[str, Any]] = []
    for _, row in paired.iterrows():
        combined: dict[str, Any] = {
            "model_name": row["model_name"],
            "protocol_p_feature_variant": row["p_feature_variant"],
            "protocol_g_feature_variant": row["g_feature_variant"],
        }
        for metric in METRICS:
            p_value = float(row[f"{metric}_p"])
            g_value = float(row[f"{metric}_g_test"])
            delta = g_value - p_value
            combined[f"protocol_p_{metric}"] = p_value
            combined[f"protocol_g_test_{metric}"] = g_value
            combined[f"protocol_g_test_minus_protocol_p_{metric}"] = delta
            combined[f"absolute_difference_{metric}"] = abs(delta)
            delta_rows.append(
                {
                    "model_name": row["model_name"],
                    "protocol_p_feature_variant": row["p_feature_variant"],
                    "protocol_g_feature_variant": row["g_feature_variant"],
                    "metric": metric,
                    "protocol_p_test_value": p_value,
                    "protocol_g_test_value": g_value,
                    "protocol_g_test_minus_protocol_p": delta,
                    "absolute_difference": abs(delta),
                }
            )
        combined_rows.append(combined)
    combined = pd.DataFrame(combined_rows)
    metric_deltas = pd.DataFrame(delta_rows)

    validation = results.protocol_g_validation.rename(columns={"feature_variant": "g_feature_variant"})
    g_test = results.protocol_g_test.rename(columns={"feature_variant": "g_feature_variant"})
    validation_pairs = validation.merge(
        g_test,
        on=["model_name", "g_feature_variant"],
        how="inner",
        validate="one_to_one",
        suffixes=("_validation", "_test"),
    )
    validation_rows: list[dict[str, Any]] = []
    for _, row in validation_pairs.iterrows():
        for metric in VALIDATION_TEST_METRICS:
            validation_value = float(row[f"{metric}_validation"])
            test_value = float(row[f"{metric}_test"])
            validation_rows.append(
                {
                    "model_name": row["model_name"],
                    "protocol_g_feature_variant": row["g_feature_variant"],
                    "metric": metric,
                    "protocol_g_validation_value": validation_value,
                    "protocol_g_test_value": test_value,
                    "test_minus_validation": test_value - validation_value,
                    "absolute_difference": abs(test_value - validation_value),
                }
            )
    validation_test_deltas = pd.DataFrame(validation_rows)

    rate_rows: list[dict[str, Any]] = []
    for protocol, partition, frame in (
        ("P", "test", results.protocol_p_test),
        ("G", "test", results.protocol_g_test),
    ):
        for _, row in frame.iterrows():
            counts = {name: int(row[name]) for name in CONFUSION_COLUMNS}
            rates = normalized_confusion_rates(**counts)
            rate_rows.append(
                {
                    "protocol": protocol,
                    "partition": partition,
                    "model_name": row["model_name"],
                    "feature_variant": row["feature_variant"],
                    **counts,
                    "negative_total": counts["tn"] + counts["fp"],
                    "positive_total": counts["fn"] + counts["tp"],
                    **rates,
                }
            )
    normalized_error_rates = pd.DataFrame(rate_rows)

    constant_rows: list[dict[str, Any]] = []
    for protocol, frame, all_variant, drop_variant in (
        ("P", results.protocol_p_test, "P-all41", "P-drop3constant"),
        ("G", results.protocol_g_test, "G-all41", "G-drop3constant"),
    ):
        model_names = [
            model_name for model_name in MODEL_ORDER if model_name in set(frame["model_name"])
        ]
        for model_name in model_names:
            all_row = frame.loc[
                (frame["model_name"] == model_name) & (frame["feature_variant"] == all_variant)
            ].iloc[0]
            drop_row = frame.loc[
                (frame["model_name"] == model_name) & (frame["feature_variant"] == drop_variant)
            ].iloc[0]
            row: dict[str, Any] = {
                "protocol": protocol,
                "model_name": model_name,
                "all41_feature_variant": all_variant,
                "drop3constant_feature_variant": drop_variant,
            }
            for metric in CONSTANT_FEATURE_METRICS:
                all_value = float(all_row[metric])
                drop_value = float(drop_row[metric])
                row[f"all41_{metric}"] = all_value
                row[f"drop3constant_{metric}"] = drop_value
                row[f"drop3constant_minus_all41_{metric}"] = drop_value - all_value
            constant_rows.append(row)
    constant_feature_effect = pd.DataFrame(constant_rows)
    return {
        "combined_metrics": combined,
        "metric_deltas": metric_deltas,
        "validation_test_deltas": validation_test_deltas,
        "normalized_error_rates": normalized_error_rates,
        "constant_feature_effect": constant_feature_effect,
    }


def _git_stdout(repository_root: Path, arguments: Sequence[str]) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository_root), *arguments],
            capture_output=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ProtocolComparisonError("Git is required to verify committed baseline sources") from error
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ProtocolComparisonError(f"Git provenance verification failed: {' '.join(arguments)}: {stderr}")
    return completed.stdout


def verify_committed_baseline_sources(repository_root: str | Path) -> dict[str, str]:
    """Prove that the baseline reports being analysed match their result commits.

    This protects the analysis from accidentally consuming changed or uncommitted
    Protocol P/G reports. It does not write to any result directory.
    """
    root = Path(repository_root).resolve()
    source_specs = (
        ("P", PROTOCOL_P_RESULT_COMMIT, PROTOCOL_P_TAG, "reports/experiments/protocol_p/seed42"),
        ("G", PROTOCOL_G_RESULT_COMMIT, PROTOCOL_G_TAG, "reports/experiments/protocol_g/seed42"),
    )
    verified: dict[str, str] = {}
    for protocol, commit, tag, report_root in source_specs:
        resolved_commit = _git_stdout(root, ["rev-parse", commit]).decode("ascii").strip()
        if resolved_commit != commit:
            raise ProtocolComparisonError(f"Protocol {protocol} result commit does not resolve as expected")
        tag_commit = _git_stdout(root, ["rev-list", "-n", "1", tag]).decode("ascii").strip()
        if tag_commit != commit:
            raise ProtocolComparisonError(f"Protocol {protocol} tag does not identify its stated result commit")
        for filename in REQUIRED_SOURCE_FILES[protocol]:
            relative_path = f"{report_root}/{filename}"
            working_path = root / relative_path
            if not working_path.is_file():
                raise FileNotFoundError(f"Committed Protocol {protocol} report is absent from the worktree: {working_path}")
            committed_blob = _git_stdout(root, ["rev-parse", f"{commit}:{relative_path}"])
            working_blob = _git_stdout(
                root,
                ["hash-object", f"--path={relative_path}", "--", relative_path],
            )
            if working_blob != committed_blob:
                raise ProtocolComparisonError(
                    f"Protocol {protocol} report differs from its committed baseline source: {relative_path}"
                )
        verified[f"protocol_{protocol.lower()}_result_commit"] = commit
        verified[f"protocol_{protocol.lower()}_tag"] = tag
    return verified


def _variant_label(variant: str) -> str:
    if variant.endswith("all41"):
        return "all 41"
    if variant.endswith("drop3constant"):
        return "drop 3 constants"
    return variant


def _configuration_label(model_name: str, variant: str) -> str:
    return f"{MODEL_PLOT_LABELS.get(model_name, model_name)}\n{_variant_label(variant)}"


def _plot_style() -> None:
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 10,
            "axes.titlesize": 12,
            "axes.labelsize": 10,
            "legend.fontsize": 9,
        }
    )


def _save_figure(figure: plt.Figure, path: Path) -> None:
    figure.tight_layout()
    figure.savefig(path, dpi=300, bbox_inches="tight")
    plt.close(figure)


def _score_comparison_figure(paired: pd.DataFrame, metric: str, path: Path) -> None:
    _plot_style()
    labels = [
        _configuration_label(row["model_name"], row["g_feature_variant"])
        for _, row in paired.iterrows()
    ]
    positions = np.arange(len(paired))
    figure, axis = plt.subplots(figsize=(13, 5.4))
    width = 0.38
    axis.bar(
        positions - width / 2,
        paired[f"{metric}_p"],
        width,
        label="Protocol P test",
        color="#4C78A8",
    )
    axis.bar(
        positions + width / 2,
        paired[f"{metric}_g_test"],
        width,
        label="Protocol G test",
        color="#F58518",
    )
    axis.set_title(f"Protocol P vs Protocol G test {metric.upper().replace('_', '-')}")
    axis.set_ylabel(metric.upper().replace("_", "-"))
    axis.set_ylim(0.0, 1.0)
    axis.set_xticks(positions, labels, rotation=0)
    axis.grid(axis="y", alpha=0.25)
    axis.legend(loc="lower left")
    _save_figure(figure, path)


def _delta_figure(paired: pd.DataFrame, metric: str, path: Path) -> None:
    _plot_style()
    values = paired[f"{metric}_g_test"] - paired[f"{metric}_p"]
    labels = [
        _configuration_label(row["model_name"], row["g_feature_variant"])
        for _, row in paired.iterrows()
    ]
    positions = np.arange(len(paired))
    colors = np.where(values >= 0, "#54A24B", "#E45756")
    limit = max(0.05, float(np.max(np.abs(values))) * 1.2)
    figure, axis = plt.subplots(figsize=(13, 5.4))
    axis.bar(positions, values, color=colors)
    axis.axhline(0.0, color="black", linewidth=0.9)
    axis.set_title(f"Change in {metric.upper().replace('_', '-')} from Protocol P to Protocol G test")
    axis.set_ylabel("Protocol G test minus Protocol P test")
    axis.set_ylim(-limit, limit)
    axis.set_xticks(positions, labels, rotation=0)
    axis.grid(axis="y", alpha=0.25)
    _save_figure(figure, path)


def _validation_test_f1_figure(results: ProtocolResults, path: Path) -> None:
    _plot_style()
    validation = results.protocol_g_validation.sort_values(["model_name", "feature_variant"], kind="stable")
    test = results.protocol_g_test.sort_values(["model_name", "feature_variant"], kind="stable")
    expected_order = [(model, variant) for model, _, variant in results.pairings]
    validation = validation.set_index(["model_name", "feature_variant"]).loc[expected_order].reset_index()
    test = test.set_index(["model_name", "feature_variant"]).loc[expected_order].reset_index()
    labels = [_configuration_label(row["model_name"], row["feature_variant"]) for _, row in test.iterrows()]
    positions = np.arange(len(test))
    figure, axis = plt.subplots(figsize=(13, 5.4))
    width = 0.38
    axis.bar(positions - width / 2, validation["f1"], width, label="Protocol G validation", color="#54A24B")
    axis.bar(positions + width / 2, test["f1"], width, label="Protocol G test", color="#F58518")
    axis.set_title("Protocol G validation versus test F1")
    axis.set_ylabel("F1")
    axis.set_ylim(0.0, 1.0)
    axis.set_xticks(positions, labels, rotation=0)
    axis.grid(axis="y", alpha=0.25)
    axis.legend(loc="lower left")
    _save_figure(figure, path)


def _xgboost_metric_figure(paired: pd.DataFrame, path: Path) -> None:
    _plot_style()
    xgb = paired.loc[paired["model_name"] == "xgboost"].reset_index(drop=True)
    figure, axes = plt.subplots(1, len(xgb), figsize=(13, 4.8), sharey=True)
    if len(xgb) == 1:
        axes = [axes]
    metrics = ("precision", "recall", "f1", "roc_auc", "pr_auc", "mcc")
    positions = np.arange(len(metrics))
    for axis, (_, row) in zip(axes, xgb.iterrows(), strict=True):
        width = 0.38
        axis.bar(positions - width / 2, [row[f"{metric}_p"] for metric in metrics], width, label="Protocol P test", color="#4C78A8")
        axis.bar(positions + width / 2, [row[f"{metric}_g_test"] for metric in metrics], width, label="Protocol G test", color="#F58518")
        axis.set_title(f"XGBoost: {_variant_label(row['g_feature_variant'])}")
        axis.set_ylim(0.0, 1.0)
        axis.set_xticks(positions, [metric.upper().replace("_", "-") for metric in metrics], rotation=35, ha="right")
        axis.grid(axis="y", alpha=0.25)
    axes[0].set_ylabel("Score")
    axes[0].legend(loc="lower left")
    _save_figure(figure, path)


def generate_thesis_figures(
    results: ProtocolResults, tables: dict[str, pd.DataFrame], figures_directory: str | Path
) -> list[Path]:
    """Create the six non-runtime, publication-ready figures from saved metrics."""
    directory = Path(figures_directory)
    directory.mkdir(parents=True, exist_ok=True)
    paired = _pair_frames(results)
    paths = {
        "protocol_p_vs_g_test_f1.png": lambda path: _score_comparison_figure(paired, "f1", path),
        "protocol_p_vs_g_test_mcc.png": lambda path: _score_comparison_figure(paired, "mcc", path),
        "protocol_p_vs_g_delta_f1.png": lambda path: _delta_figure(paired, "f1", path),
        "protocol_p_vs_g_delta_mcc.png": lambda path: _delta_figure(paired, "mcc", path),
        "protocol_g_validation_vs_test_f1.png": lambda path: _validation_test_f1_figure(results, path),
        "xgboost_protocol_p_vs_g_metrics.png": lambda path: _xgboost_metric_figure(paired, path),
    }
    generated: list[Path] = []
    for filename, create in paths.items():
        path = directory / filename
        create(path)
        generated.append(path)
    return generated


def _format_value(value: float) -> str:
    return f"{float(value):.6f}"


def _markdown_table(headers: Sequence[str], rows: Iterable[Sequence[str]]) -> str:
    rendered_rows = list(rows)
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    lines.extend("| " + " | ".join(row) + " |" for row in rendered_rows)
    return "\n".join(lines)


def _short_model_name(model_name: str) -> str:
    return MODEL_LABELS.get(model_name, model_name)


def _comparison_summary_table(paired: pd.DataFrame) -> str:
    rows = []
    for _, row in paired.iterrows():
        rows.append(
            (
                _short_model_name(row["model_name"]),
                _variant_label(row["g_feature_variant"]),
                _format_value(row["f1_p"]),
                _format_value(row["f1_g_test"]),
                f"{float(row['f1_g_test'] - row['f1_p']):+.6f}",
                _format_value(row["mcc_p"]),
                _format_value(row["mcc_g_test"]),
                f"{float(row['mcc_g_test'] - row['mcc_p']):+.6f}",
            )
        )
    return _markdown_table(
        ("Model", "Variant", "P F1", "G test F1", "Delta F1", "P MCC", "G test MCC", "Delta MCC"),
        rows,
    )


def _sensitivity_table(metric_deltas: pd.DataFrame, metric: str) -> pd.DataFrame:
    selected = metric_deltas.loc[
        (metric_deltas["metric"] == metric)
        & (metric_deltas["model_name"] != "gaussian_naive_bayes")
    ]
    return (
        selected.groupby("model_name", as_index=False)["absolute_difference"]
        .mean()
        .rename(columns={"absolute_difference": "mean_absolute_change"})
        .sort_values("mean_absolute_change", ascending=False, kind="stable")
        .reset_index(drop=True)
    )


def _validation_highlights(validation_test_deltas: pd.DataFrame) -> dict[str, pd.Series]:
    highlights: dict[str, pd.Series] = {}
    for metric in VALIDATION_TEST_METRICS:
        selected = validation_test_deltas.loc[validation_test_deltas["metric"] == metric]
        highlights[metric] = selected.loc[selected["absolute_difference"].idxmax()]
    return highlights


def _error_comparison_table(normalized_error_rates: pd.DataFrame) -> str:
    p_rates = normalized_error_rates.loc[normalized_error_rates["protocol"] == "P"].copy()
    g_rates = normalized_error_rates.loc[normalized_error_rates["protocol"] == "G"].copy()
    p_rates["variant"] = p_rates["feature_variant"].map(_variant_label)
    g_rates["variant"] = g_rates["feature_variant"].map(_variant_label)
    merged = p_rates.merge(g_rates, on=["model_name", "variant"], suffixes=("_p", "_g"))
    rows = []
    for _, row in merged.iterrows():
        rows.append(
            (
                _short_model_name(row["model_name"]),
                row["variant"],
                _format_value(row["false_positive_rate_p"]),
                _format_value(row["false_positive_rate_g"]),
                _format_value(row["false_negative_rate_p"]),
                _format_value(row["false_negative_rate_g"]),
                _format_value(row["true_positive_rate_recall_p"]),
                _format_value(row["true_positive_rate_recall_g"]),
                _format_value(row["true_negative_rate_specificity_p"]),
                _format_value(row["true_negative_rate_specificity_g"]),
            )
        )
    return _markdown_table(
        ("Model", "Variant", "P FPR", "G FPR", "P FNR", "G FNR", "P TPR", "G TPR", "P TNR", "G TNR"),
        rows,
    )


def _constant_effect_markdown(constant_feature_effect: pd.DataFrame) -> str:
    rows = []
    for _, row in constant_feature_effect.iterrows():
        rows.append(
            (
                row["protocol"],
                _short_model_name(row["model_name"]),
                f"{float(row['drop3constant_minus_all41_f1']):+.6f}",
                f"{float(row['drop3constant_minus_all41_mcc']):+.6f}",
                f"{float(row['drop3constant_minus_all41_roc_auc']):+.6f}",
                f"{float(row['drop3constant_minus_all41_pr_auc']):+.6f}",
            )
        )
    return _markdown_table(("Protocol", "Model", "Delta F1", "Delta MCC", "Delta ROC-AUC", "Delta PR-AUC"), rows)


def _xgboost_markdown(paired: pd.DataFrame, normalized_error_rates: pd.DataFrame) -> str:
    xgb = paired.loc[paired["model_name"] == "xgboost"].copy()
    rates = normalized_error_rates.loc[normalized_error_rates["model_name"] == "xgboost"].copy()
    rows = []
    for _, row in xgb.iterrows():
        p_variant = row["p_feature_variant"]
        g_variant = row["g_feature_variant"]
        p_rate = rates.loc[(rates["protocol"] == "P") & (rates["feature_variant"] == p_variant)].iloc[0]
        g_rate = rates.loc[(rates["protocol"] == "G") & (rates["feature_variant"] == g_variant)].iloc[0]
        rows.append(
            (
                _variant_label(g_variant),
                _format_value(row["precision_p"]),
                _format_value(row["precision_g_test"]),
                _format_value(row["recall_p"]),
                _format_value(row["recall_g_test"]),
                _format_value(row["f1_p"]),
                _format_value(row["f1_g_test"]),
                _format_value(row["roc_auc_p"]),
                _format_value(row["roc_auc_g_test"]),
                _format_value(row["pr_auc_p"]),
                _format_value(row["pr_auc_g_test"]),
                _format_value(row["mcc_p"]),
                _format_value(row["mcc_g_test"]),
                str(int(p_rate["fp"])),
                str(int(g_rate["fp"])),
                str(int(p_rate["fn"])),
                str(int(g_rate["fn"])),
                _format_value(p_rate["false_positive_rate"]),
                _format_value(g_rate["false_positive_rate"]),
                _format_value(p_rate["false_negative_rate"]),
                _format_value(g_rate["false_negative_rate"]),
            )
        )
    return _markdown_table(
        (
            "Variant", "P Prec.", "G Prec.", "P Recall", "G Recall", "P F1", "G F1",
            "P ROC", "G ROC", "P PR", "G PR", "P MCC", "G MCC", "P FP", "G FP",
            "P FN", "G FN", "P FPR", "G FPR", "P FNR", "G FNR",
        ),
        rows,
    )


def build_formal_analysis_markdown(
    results: ProtocolResults,
    tables: dict[str, pd.DataFrame],
    source_verification: dict[str, str],
) -> str:
    """Render a thesis-appropriate report solely from the computed result tables."""
    paired = _pair_frames(results)
    metric_deltas = tables["metric_deltas"]
    validation_test_deltas = tables["validation_test_deltas"]
    normalized_error_rates = tables["normalized_error_rates"]
    constant_feature_effect = tables["constant_feature_effect"]
    f1_sensitivity = _sensitivity_table(metric_deltas, "f1")
    mcc_sensitivity = _sensitivity_table(metric_deltas, "mcc")
    validation_highlights = _validation_highlights(validation_test_deltas)
    f1_most = f1_sensitivity.iloc[0]
    f1_least = f1_sensitivity.iloc[-1]
    mcc_most = mcc_sensitivity.iloc[0]
    mcc_least = mcc_sensitivity.iloc[-1]
    xgb = paired.loc[paired["model_name"] == "xgboost"].iloc[0]
    gnb = paired.loc[paired["model_name"] == "gaussian_naive_bayes"].iloc[0]
    gnb_g_rate = normalized_error_rates.loc[
        (normalized_error_rates["protocol"] == "G")
        & (normalized_error_rates["model_name"] == "gaussian_naive_bayes")
        & (normalized_error_rates["feature_variant"] == "G-all41")
    ].iloc[0]
    lines = [
        "# Protocol P versus Protocol G comparative analysis",
        "",
        "## 1. Objective",
        "",
        "Research question: *How much does malicious-PDF classification performance change when identical static feature representations are prevented from appearing across training and evaluation partitions?*",
        "",
        "This report is a deterministic analysis of the committed seed-42 baseline reports. It does not train, refit, tune, threshold-adjust, or regenerate any split.",
        "",
        "## 2. Experimental protocols",
        "",
        "- **Protocol P** is a paper-aligned, stratified row-level 75/25 train/test split. Its seed 42 is a project choice, not a published paper seed.",
        "- **Protocol G** is a saved 60/20/20-style train/validation/test split whose feature-equivalent groups are partition-disjoint. It prevents identical static feature vectors from crossing partitions.",
        "- Protocol G is not file-level deduplication: the local CSV has no per-PDF SHA-256 field, so PDF-file identity cannot be established.",
        "",
        "## 3. Comparison methodology",
        "",
        f"- Dataset SHA-256: `{results.provenance['dataset_sha256']}`; seed: `{results.provenance['seed']}`.",
        f"- Protocol P result commit/tag: `{source_verification['protocol_p_result_commit']}` / `{source_verification['protocol_p_tag']}`; benchmark-generating code: `{results.provenance['protocol_p_benchmark_generating_commit']}`.",
        f"- Protocol G result commit/tag: `{source_verification['protocol_g_result_commit']}` / `{source_verification['protocol_g_tag']}`; benchmark-generating code: `{results.provenance['protocol_g_benchmark_generating_commit']}`.",
        "- Each comparison pairs P-all41 with G-all41 and P-drop3constant with G-drop3constant. Signed deltas are Protocol G test minus Protocol P test; absolute differences discard direction.",
        "- Error rates use class-specific denominators: FPR = FP / (TN + FP), FNR = FN / (FN + TP), TPR = TP / (FN + TP), and TNR = TN / (TN + FP). Raw counts are retained but are not compared alone because test-set sizes differ.",
        "",
        "### Metric-semantics note",
        "",
        "Historical local Precision, Recall, and F1 use Label=1 (malicious) as the positive class. This local P-versus-G comparison remains semantically valid because both protocols use that same convention. Paper Table 5 Precision, Recall, and F1 are compared separately against macro metrics in `reports/analysis/paper_metric_semantics_correction.md`; they must not be compared directly with malicious-positive values.",
        "",
        "## 4. Overall P versus G results",
        "",
        _comparison_summary_table(paired),
        "",
        "The complete seven-metric paired table, signed deltas, and absolute differences are in `reports/tables/protocol_p_vs_g/combined_metrics.csv` and `metric_deltas.csv`. Under this fixed seed-42 configuration, the high-performing conventional models show lower Protocol G test F1 and MCC than their paired Protocol P results; GaussianNB is addressed separately below.",
        "",
        "## 5. Model-specific behavior",
        "",
        f"For the four conventionally high-performing model families, the largest mean absolute F1 change across the two variants is {_short_model_name(f1_most['model_name'])} ({_format_value(f1_most['mean_absolute_change'])}); the smallest is {_short_model_name(f1_least['model_name'])} ({_format_value(f1_least['mean_absolute_change'])}). For MCC, the largest is {_short_model_name(mcc_most['model_name'])} ({_format_value(mcc_most['mean_absolute_change'])}) and the smallest is {_short_model_name(mcc_least['model_name'])} ({_format_value(mcc_least['mean_absolute_change'])}). GaussianNB is excluded from these degradation rankings because its P-to-G values move in the opposite direction.",
        "",
        "## 6. XGBoost analysis",
        "",
        _xgboost_markdown(paired, normalized_error_rates),
        "",
        f"For XGBoost all41, Protocol G test ROC-AUC and PR-AUC remain high ({_format_value(xgb['roc_auc_g_test'])} and {_format_value(xgb['pr_auc_g_test'])}), while recall, F1, and MCC are lower than Protocol P by {_format_value(xgb['recall_g_test'] - xgb['recall_p'])}, {_format_value(xgb['f1_g_test'] - xgb['f1_p'])}, and {_format_value(xgb['mcc_g_test'] - xgb['mcc_p'])}, respectively. The ranking metrics remain high while fixed-threshold classification performance decreases. This analysis does not measure calibration and does not tune a threshold.",
        "",
        "## 7. Error-rate analysis",
        "",
        _error_comparison_table(normalized_error_rates),
        "",
        "The machine-readable error table includes TN, FP, FN, TP and the denominators for every paired test configuration in `normalized_error_rates.csv`.",
        "",
        "## 8. Constant-feature experiment",
        "",
        "The comparison removes only Acroform, Colors, and BaseEncoding. The following values are drop3constant minus all41 within each protocol and model:",
        "",
        _constant_effect_markdown(constant_feature_effect),
        "",
        "The observed changes are negligible for several configurations, exactly zero for the recorded GaussianNB and XGBoost classification metrics, and non-zero for Random Forest and Decision Tree. These results support only a statement about this dataset and fixed experiment; they do not establish universal irrelevance of the three features.",
        "",
        "## 9. GaussianNB anomaly",
        "",
        f"GaussianNB has high recall but low precision in both protocols. For all41, Protocol P recall/precision/F1/MCC are {_format_value(gnb['recall_p'])} / {_format_value(gnb['precision_p'])} / {_format_value(gnb['f1_p'])} / {_format_value(gnb['mcc_p'])}; Protocol G test values are {_format_value(gnb['recall_g_test'])} / {_format_value(gnb['precision_g_test'])} / {_format_value(gnb['f1_g_test'])} / {_format_value(gnb['mcc_g_test'])}. The Protocol G all41 test has {int(gnb_g_rate['fp'])} false positives. Its F1 and MCC improve relative to Protocol P while most other models decline; this is an unresolved model-behavior question, not evidence of superior generalization.",
        "",
        "Hypotheses for later, separately authorized investigation (not findings): inspect class-conditional feature distributions and the Naive Bayes independence assumption; inspect score distributions under the fixed threshold; and quantify the pattern across multiple seeds without tuning against the test set.",
        "",
        "## 10. Threats to validity",
        "",
        "- Protocol P and Protocol G use different split ratios, and Protocol G has a smaller training set.",
        "- Protocol G tests feature-vector disjointness, not temporal drift, cross-dataset shift, or true PDF-file identity.",
        "- Original per-PDF hashes are unavailable in the local published CSV.",
        "- Only seed 42 has been evaluated; statistical uncertainty has not been quantified with multi-seed experiments.",
        "- Where the paper did not specify settings, model hyperparameters and preprocessing are fixed project assumptions.",
        "- These two protocols alone cannot support a claim about real-world malware robustness.",
        "",
        "## 11. Findings",
        "",
        "Under the fixed seed-42 configuration, preventing identical static feature representations from crossing training and evaluation partitions reduced the Protocol G test performance of most high-performing models. The magnitude is metric- and model-specific and is reported in the paired tables; it must not be attributed to duplicate PDF files because file-level hashes are unavailable.",
        "",
        "## 12. Questions for follow-up experiments",
        "",
        "- Does the P-to-G difference persist across preregistered additional seeds without changing configurations?",
        "- How stable are the findings under a separately designed cross-validation or external-dataset protocol?",
        "- What explains GaussianNB's contrary directional change under the two saved protocols?",
        "- Do score-distribution and calibration analyses, performed separately, clarify the high ranking metrics and lower fixed-threshold metrics for XGBoost?",
        "",
        "## Appendix: Protocol G validation versus test consistency",
        "",
        "The full six-metric validation/test delta table is in `validation_test_deltas.csv`. The largest absolute differences observed for each metric are listed below without assigning a statistical-significance threshold.",
        "",
    ]
    highlight_rows = []
    for metric in VALIDATION_TEST_METRICS:
        row = validation_highlights[metric]
        highlight_rows.append(
            (
                metric.upper().replace("_", "-"),
                _short_model_name(row["model_name"]),
                _variant_label(row["protocol_g_feature_variant"]),
                _format_value(row["protocol_g_validation_value"]),
                _format_value(row["protocol_g_test_value"]),
                f"{float(row['test_minus_validation']):+.6f}",
            )
        )
    lines.append(
        _markdown_table(
            ("Metric", "Model", "Variant", "G validation", "G test", "Test minus validation"),
            highlight_rows,
        )
    )
    lines.append("")
    return "\n".join(lines)


def analysis_output_paths(repository_root: str | Path) -> AnalysisOutputPaths:
    """Return dedicated tracked locations for the thesis comparison outputs."""
    root = Path(repository_root).resolve()
    return AnalysisOutputPaths(
        tables_directory=root / "reports" / "tables" / "protocol_p_vs_g",
        figures_directory=root / "reports" / "figures" / "protocol_p_vs_g",
        markdown_analysis=root / "reports" / "analysis" / "protocol_p_vs_g_analysis.md",
    )


def _output_exists(paths: AnalysisOutputPaths) -> bool:
    tables_exist = paths.tables_directory.is_dir() and any(paths.tables_directory.iterdir())
    figures_exist = paths.figures_directory.is_dir() and any(paths.figures_directory.iterdir())
    return paths.markdown_analysis.exists() or tables_exist or figures_exist


def write_analysis_outputs(
    results: ProtocolResults,
    tables: dict[str, pd.DataFrame],
    output_paths: AnalysisOutputPaths,
    source_verification: dict[str, str],
    *,
    overwrite: bool = False,
) -> list[Path]:
    """Write analysis-only tables, figures, and Markdown without touching baselines."""
    if _output_exists(output_paths) and not overwrite:
        raise FileExistsError(
            "Comparative analysis output already exists; use explicit overwrite only for analysis outputs"
        )
    output_paths.tables_directory.mkdir(parents=True, exist_ok=True)
    output_paths.figures_directory.mkdir(parents=True, exist_ok=True)
    output_paths.markdown_analysis.parent.mkdir(parents=True, exist_ok=True)
    table_paths: list[Path] = []
    for name, table in tables.items():
        path = output_paths.tables_directory / f"{name}.csv"
        table.to_csv(path, index=False, float_format="%.12g")
        table_paths.append(path)
    figure_paths = generate_thesis_figures(results, tables, output_paths.figures_directory)
    output_paths.markdown_analysis.write_text(
        build_formal_analysis_markdown(results, tables, source_verification),
        encoding="utf-8",
    )
    return [*table_paths, *figure_paths, output_paths.markdown_analysis]


def run_protocol_p_vs_g_analysis(
    repository_root: str | Path,
    *,
    protocol_p_directory: str | Path | None = None,
    protocol_g_directory: str | Path | None = None,
    overwrite: bool = False,
) -> tuple[AnalysisOutputPaths, dict[str, pd.DataFrame], dict[str, str]]:
    """Verify committed inputs then render the formal comparative analysis."""
    root = Path(repository_root).resolve()
    p_directory = Path(
        protocol_p_directory or root / "reports" / "experiments" / "protocol_p" / "seed42"
    ).resolve()
    g_directory = Path(
        protocol_g_directory or root / "reports" / "experiments" / "protocol_g" / "seed42"
    ).resolve()
    source_verification = verify_committed_baseline_sources(root)
    source_paths = _required_source_paths(p_directory, g_directory)
    source_bytes_before = {path: path.read_bytes() for path in source_paths}
    results = load_protocol_baseline_reports(p_directory, g_directory)
    tables = build_comparison_tables(results)
    output_paths = analysis_output_paths(root)
    write_analysis_outputs(
        results,
        tables,
        output_paths,
        source_verification,
        overwrite=overwrite,
    )
    changed_sources = [path for path, content in source_bytes_before.items() if path.read_bytes() != content]
    if changed_sources:
        raise ProtocolComparisonError(
            f"Analysis must not modify committed Protocol P/G reports: {changed_sources}"
        )
    return output_paths, tables, source_verification

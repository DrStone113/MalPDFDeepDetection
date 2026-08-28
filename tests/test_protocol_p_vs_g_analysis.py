"""Synthetic tests for report-only Protocol P/G comparative analysis."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from malpdf.analysis.protocol_p_vs_g import (
    DATASET_SHA256,
    PROTOCOL_G_BENCHMARK_COMMIT,
    PROTOCOL_P_BENCHMARK_COMMIT,
    ProtocolComparisonError,
    build_comparison_tables,
    load_protocol_baseline_reports,
    normalized_confusion_rates,
)


PAIRINGS = (
    ("logistic_regression", "P-all41", "G-all41"),
    ("logistic_regression", "P-drop3constant", "G-drop3constant"),
)


def _metrics(value: float) -> dict[str, float | int]:
    return {
        "positive_label": 1,
        "accuracy": value,
        "precision": value,
        "recall": value,
        "f1": value,
        "roc_auc": value,
        "pr_auc": value,
        "mcc": value,
    }


def _counts() -> dict[str, int]:
    return {"tn": 90, "fp": 10, "fn": 5, "tp": 95}


def _record(protocol: str, model_name: str, feature_variant: str, value: float) -> dict:
    benchmark_commit = PROTOCOL_P_BENCHMARK_COMMIT if protocol == "P" else PROTOCOL_G_BENCHMARK_COMMIT
    common = {
        "protocol": protocol,
        "status": "completed",
        "model_name": model_name,
        "feature_variant": feature_variant,
        "feature_count": 41 if feature_variant.endswith("all41") else 38,
        "dataset_sha256": DATASET_SHA256,
        "split_seed": 42,
        "environment": {
            "dataset_sha256": DATASET_SHA256,
            "git_commit_sha": benchmark_commit,
        },
    }
    if protocol == "P":
        return {**common, "metrics": _metrics(value), "confusion_counts": _counts()}
    return {
        **common,
        "validation": {"metrics": _metrics(value - 0.02), "confusion_counts": _counts()},
        "test": {"metrics": _metrics(value), "confusion_counts": _counts()},
    }


def _write_source_tree(root: Path, protocol: str, runs: list[dict]) -> Path:
    directory = root / "reports" / "experiments" / f"protocol_{protocol.lower()}" / "seed42"
    directory.mkdir(parents=True)
    (directory / "metrics.json").write_text(json.dumps({"runs": runs}), encoding="utf-8")
    filenames = (
        ("summary.csv", "environment.json", "experiment_config.json", "split_summary.json", "run_summary.md")
        if protocol == "P"
        else (
            "summary_validation.csv",
            "summary_test.csv",
            "confusion_matrices.json",
            "protocol_p_vs_g.csv",
            "environment.json",
            "experiment_config.json",
            "split_summary.json",
            "run_summary.md",
        )
    )
    for filename in filenames:
        (directory / filename).write_text("synthetic source report\n", encoding="utf-8")
    return directory


def _synthetic_results(tmp_path: Path):
    p_runs = [
        _record("P", "logistic_regression", "P-all41", 0.90),
        _record("P", "logistic_regression", "P-drop3constant", 0.80),
    ]
    g_runs = [
        _record("G", "logistic_regression", "G-all41", 0.75),
        _record("G", "logistic_regression", "G-drop3constant", 0.82),
    ]
    return _write_source_tree(tmp_path, "P", p_runs), _write_source_tree(tmp_path, "G", g_runs)


def test_protocol_result_pairing_and_metric_delta_calculations(tmp_path):
    p_directory, g_directory = _synthetic_results(tmp_path)

    results = load_protocol_baseline_reports(
        p_directory, g_directory, expected_pairings=PAIRINGS
    )
    tables = build_comparison_tables(results)

    combined = tables["combined_metrics"]
    assert len(combined) == 2
    all41 = combined.loc[combined["protocol_g_feature_variant"] == "G-all41"].iloc[0]
    assert all41["protocol_p_f1"] == pytest.approx(0.90)
    assert all41["protocol_g_test_f1"] == pytest.approx(0.75)
    assert all41["protocol_g_test_minus_protocol_p_f1"] == pytest.approx(-0.15)
    assert all41["absolute_difference_f1"] == pytest.approx(0.15)

    validation = tables["validation_test_deltas"]
    f1 = validation.loc[
        (validation["protocol_g_feature_variant"] == "G-all41")
        & (validation["metric"] == "f1")
    ].iloc[0]
    assert f1["test_minus_validation"] == pytest.approx(0.02)


def test_normalized_confusion_rates_use_correct_denominators():
    rates = normalized_confusion_rates(tn=90, fp=10, fn=5, tp=95)

    assert rates["false_positive_rate"] == pytest.approx(0.10)
    assert rates["false_negative_rate"] == pytest.approx(0.05)
    assert rates["true_positive_rate_recall"] == pytest.approx(0.95)
    assert rates["true_negative_rate_specificity"] == pytest.approx(0.90)


def test_loader_rejects_mismatched_experiment_metadata(tmp_path):
    p_directory, g_directory = _synthetic_results(tmp_path)
    payload = json.loads((p_directory / "metrics.json").read_text(encoding="utf-8"))
    payload["runs"][0]["split_seed"] = 7
    (p_directory / "metrics.json").write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ProtocolComparisonError, match="seed is not 42"):
        load_protocol_baseline_reports(p_directory, g_directory, expected_pairings=PAIRINGS)


def test_loader_rejects_incorrect_feature_variant_pairing(tmp_path):
    p_directory, g_directory = _synthetic_results(tmp_path)
    payload = json.loads((g_directory / "metrics.json").read_text(encoding="utf-8"))
    payload["runs"][0]["feature_variant"] = "G-drop3constant"
    payload["runs"][0]["feature_count"] = 38
    (g_directory / "metrics.json").write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ProtocolComparisonError, match="model/variant pairs"):
        load_protocol_baseline_reports(p_directory, g_directory, expected_pairings=PAIRINGS)

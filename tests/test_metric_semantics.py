"""Synthetic tests for the non-destructive paper metric-semantics correction."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from sklearn.metrics import f1_score, precision_score, recall_score

from malpdf.analysis.metric_semantics import (
    PAPER_GNB_CONFUSION_COUNTS,
    PAPER_ROUNDING_TOLERANCE,
    corrected_paper_comparison,
    derive_named_metrics_from_results,
    reconstruct_paper_gnb_metrics,
    write_metric_semantics_outputs,
    MetricSemanticsPaths,
)
from malpdf.evaluation.binary import (
    classification_metrics_from_confusion_counts,
    evaluate_binary_predictions,
)


def _reconstructed_arrays(tn: int, fp: int, fn: int, tp: int) -> tuple[np.ndarray, np.ndarray]:
    truth = np.array([0] * (tn + fp) + [1] * (fn + tp))
    predicted = np.array([0] * tn + [1] * fp + [0] * fn + [1] * tp)
    return truth, predicted


def test_macro_metrics_from_confusion_counts_match_sklearn():
    truth, predicted = _reconstructed_arrays(tn=1052, fp=2257, fn=44, tp=2732)
    derived = classification_metrics_from_confusion_counts(tn=1052, fp=2257, fn=44, tp=2732)

    assert derived["precision_macro"] == pytest.approx(
        precision_score(truth, predicted, labels=[0, 1], average="macro", zero_division=0)
    )
    assert derived["recall_macro"] == pytest.approx(
        recall_score(truth, predicted, labels=[0, 1], average="macro", zero_division=0)
    )
    assert derived["f1_macro"] == pytest.approx(
        f1_score(truth, predicted, labels=[0, 1], average="macro", zero_division=0)
    )


def test_malicious_positive_aliases_remain_unchanged_and_named():
    truth, predicted = _reconstructed_arrays(tn=1, fp=1, fn=0, tp=2)

    metrics = evaluate_binary_predictions(truth, predicted)

    assert metrics["positive_label"] == 1
    assert metrics["precision"] == metrics["precision_malicious"] == pytest.approx(2 / 3)
    assert metrics["recall"] == metrics["recall_malicious"] == pytest.approx(1.0)
    assert metrics["f1"] == metrics["f1_malicious"] == pytest.approx(0.8)
    assert metrics["accuracy"] == pytest.approx(0.75)
    assert metrics["precision_macro"] != metrics["precision_malicious"]


def test_paper_gnb_reconstruction_matches_macro_table5_not_malicious_metrics():
    reconstruction = reconstruct_paper_gnb_metrics()

    assert reconstruction["confusion_counts"] == PAPER_GNB_CONFUSION_COUNTS
    assert all(reconstruction["macro_matches_table5"].values())
    assert not any(reconstruction["malicious_matches_table5"].values())
    assert reconstruction["metrics"]["precision_macro"] == pytest.approx(
        reconstruction["paper_table5"]["precision"], abs=PAPER_ROUNDING_TOLERANCE
    )
    assert reconstruction["metrics"]["recall_macro"] == pytest.approx(
        reconstruction["paper_table5"]["recall"], abs=PAPER_ROUNDING_TOLERANCE
    )
    assert reconstruction["metrics"]["f1_macro"] == pytest.approx(
        reconstruction["paper_table5"]["f1"], abs=PAPER_ROUNDING_TOLERANCE
    )


def test_corrected_paper_comparison_maps_paper_prf_to_local_macro_fields():
    local = pd.DataFrame(
        [
            {
                "model_name": "gaussian_naive_bayes",
                "feature_variant": "P-all41",
                "accuracy": 0.6,
                "precision_malicious": 0.5,
                "recall_malicious": 0.99,
                "f1_malicious": 0.66,
                "precision_macro": 0.75,
                "recall_macro": 0.65,
                "f1_macro": 0.59,
            }
        ]
    )

    comparison = corrected_paper_comparison(local).iloc[0]

    assert comparison["local_accuracy"] == pytest.approx(0.6)
    assert comparison["local_precision_macro"] == pytest.approx(0.75)
    assert comparison["local_recall_macro"] == pytest.approx(0.65)
    assert comparison["local_f1_macro"] == pytest.approx(0.59)
    assert comparison["local_precision_malicious"] == pytest.approx(0.5)
    assert comparison["local_recall_malicious"] == pytest.approx(0.99)


def test_local_p_vs_g_operational_precision_delta_retains_same_semantics():
    p_frame = pd.DataFrame(
        [{"model_name": "xgboost", "feature_variant": "P-all41", "accuracy": 0.8, "precision": 0.8, "recall": 0.8, "f1": 0.8, "roc_auc": 0.9, "pr_auc": 0.9, "mcc": 0.8, "tn": 8, "fp": 2, "fn": 2, "tp": 8}]
    )
    g_frame = pd.DataFrame(
        [{"model_name": "xgboost", "feature_variant": "G-all41", "accuracy": 0.7, "precision": 0.7, "recall": 0.7, "f1": 0.7, "roc_auc": 0.8, "pr_auc": 0.8, "mcc": 0.6, "tn": 7, "fp": 3, "fn": 3, "tp": 7}]
    )

    p_named = derive_named_metrics_from_results(p_frame, protocol="P", partition="test")
    g_named = derive_named_metrics_from_results(g_frame, protocol="G", partition="test")

    assert g_frame.loc[0, "precision"] - p_frame.loc[0, "precision"] == pytest.approx(
        g_named.loc[0, "precision_malicious"] - p_named.loc[0, "precision_malicious"]
    )


def test_writing_supplementary_outputs_does_not_change_historical_protocol_p_or_g_files(tmp_path, monkeypatch):
    historical_p = tmp_path / "protocol_p_metrics.json"
    historical_g = tmp_path / "protocol_g_metrics.json"
    historical_p.write_text('{"historical": "P"}\n', encoding="utf-8")
    historical_g.write_text('{"historical": "G"}\n', encoding="utf-8")
    before = {historical_p: historical_p.read_bytes(), historical_g: historical_g.read_bytes()}
    paths = MetricSemanticsPaths(
        tables_directory=tmp_path / "tables",
        markdown_analysis=tmp_path / "analysis" / "correction.md",
    )
    tables = {
        "paper_metric_semantics_evidence": pd.DataFrame([{"metric": "precision", "value": 0.7}]),
        "protocol_p_macro_metrics": pd.DataFrame(),
        "protocol_g_macro_metrics": pd.DataFrame(),
        "paper_comparison_corrected": pd.DataFrame(),
        "metric_definition_map": pd.DataFrame(),
    }

    monkeypatch.setattr(
        "malpdf.analysis.metric_semantics.build_metric_semantics_markdown",
        lambda values: "synthetic correction\n",
    )

    write_metric_semantics_outputs(tables, paths)

    assert {path: path.read_bytes() for path in before} == before
    assert paths.markdown_analysis.is_file()

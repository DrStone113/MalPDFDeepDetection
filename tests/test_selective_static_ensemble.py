"""Synthetic-only tests for validation-locked static fusion and referral."""

from __future__ import annotations

import inspect
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
import yaml

from malpdf.dynamic.routing import EnsembleRoutingContext
from malpdf.evaluation.selective import (
    apply_probability_calibrator,
    binary_disagreement,
    binary_entropy,
    calibration_metrics,
    continuous_disagreement,
    expected_calibration_error,
    fit_probability_calibrator,
    fuse_probabilities,
    referral_by_uncertainty,
    selective_metrics,
)
from malpdf.experiments.selective_static_ensemble import (
    EXPECTED_PARTITION_ROWS,
    EXPECTED_SPLIT_MANIFEST_SHA256,
    RUN_ID,
    _prediction_table,
    _write_json,
    ensemble_paths,
    preflight_selective_ensemble,
    routing_analysis,
    select_validation_fusion,
    validation_calibration_split,
)
from malpdf.static.schema import PROTOCOL_G_REQUIRED_FEATURES


LABELS = np.array([0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1])
XGB = np.array([0.05, 0.95, 0.20, 0.80, 0.10, 0.72, 0.35, 0.65, 0.45, 0.55, 0.15, 0.85])
FT = np.array([0.10, 0.85, 0.30, 0.90, 0.20, 0.60, 0.40, 0.70, 0.55, 0.65, 0.25, 0.80])


def test_probability_fusion_calibration_and_uncertainty_are_well_defined() -> None:
    fused = fuse_probabilities(XGB, FT, xgb_weight=0.5)
    assert np.allclose(fused, (XGB + FT) / 2)
    assert binary_disagreement(XGB, FT).tolist() == [False, False, False, False, False, False, False, False, True, False, False, False]
    assert np.allclose(continuous_disagreement(XGB, FT), np.abs(XGB - FT))
    entropy = binary_entropy(fused)
    assert entropy.shape == fused.shape and entropy[8] > entropy[0]
    assert expected_calibration_error(LABELS, fused, n_bins=10) >= 0.0
    metrics = calibration_metrics(LABELS, fused, n_bins=10)
    assert {"brier", "log_loss", "ece", "roc_auc", "pr_auc", "mcc"}.issubset(metrics)
    platt = fit_probability_calibrator("platt", XGB, LABELS)
    calibrated = apply_probability_calibrator("platt", platt, XGB)
    assert np.isfinite(calibrated).all() and ((0 <= calibrated) & (calibrated <= 1)).all()


def test_validation_selection_is_deterministic_and_cannot_accept_test_scores() -> None:
    calibration, selection = validation_calibration_split(LABELS, fraction=0.5, seed=42)
    repeat = validation_calibration_split(LABELS, fraction=0.5, seed=42)
    assert np.array_equal(calibration, repeat[0]) and np.array_equal(selection, repeat[1])
    assert not set(calibration) & set(selection) and len(calibration) + len(selection) == len(LABELS)
    results, chosen = select_validation_fusion(
        LABELS, XGB, FT, calibration_positions=calibration, selection_positions=selection,
        calibration_methods=("none", "platt", "isotonic"), weights=(0.0, 0.5, 1.0), ece_bins=10,
    )
    assert len(results) == 18
    assert chosen["test_used_for_selection"] is False and chosen["selection_metric"] == "mcc"
    assert "test" not in inspect.signature(select_validation_fusion).parameters


def test_referral_budget_selective_metrics_and_error_capture_are_explicit() -> None:
    probabilities = np.array([0.05, 0.95, 0.49, 0.51, 0.10, 0.90, 0.20, 0.80, 0.45, 0.55, 0.15, 0.85])
    uncertainty = binary_entropy(probabilities)
    result = referral_by_uncertainty(uncertainty, referral_rate=0.25)
    assert result.referral_rate == pytest.approx(0.25) and result.coverage == pytest.approx(0.75)
    metrics = selective_metrics(LABELS, probabilities, result.referred)
    assert metrics["coverage"] == pytest.approx(0.75)
    assert metrics["errors_referred"] == metrics["fp_referred"] + metrics["fn_referred"]
    assert 0.0 <= metrics["error_capture_rate"] <= 1.0
    forced = referral_by_uncertainty(uncertainty, referral_rate=0.0, always_refer=np.array([True] + [False] * 11))
    assert forced.referral_rate == pytest.approx(1 / 12)


def test_routing_table_and_safe_prediction_ids_do_not_fabricate_dynamic_values(tmp_path) -> None:
    routing = routing_analysis(LABELS, fuse_probabilities(XGB, FT, xgb_weight=0.5), binary_disagreement(XGB, FT), (0.0, 0.10, 0.30))
    assert len(routing) == 9
    assert set(routing["policy"]) == {"uncertainty_only", "disagreement_always_then_uncertainty", "unavailable_always_referral_capable"}
    assert (routing["static_prediction_unavailable_rows"] == 0).all()
    table = _prediction_table(pd.Series([f"raw-source-{index}" for index in range(len(LABELS))]), LABELS, XGB, FT, selected_xgb=XGB, selected_ft=FT, ensemble=fuse_probabilities(XGB, FT, xgb_weight=0.5))
    assert table["sample_id"].str.startswith("ensemble-").all()
    assert not table.astype(str).apply(lambda column: column.str.contains("raw-source")).any().any()
    context = EnsembleRoutingContext("static-model-v1", 0.2, 0.3, 0.25, False, 0.56, "STATIC_UNCERTAIN")
    assert set(context.to_dict()) == {"static_model_version", "xgb_probability", "ft_probability", "ensemble_probability", "model_disagreement", "uncertainty_score", "routing_reason"}
    assert "dynamic" not in context.to_dict()
    assert ensemble_paths(tmp_path, RUN_ID).reports_directory.name == RUN_ID


def test_provenance_json_serializes_numpy_selection_scalars(tmp_path: Path) -> None:
    target = tmp_path / "lock.json"
    _write_json(target, {"candidate_order": np.int64(3), "mcc": np.float64(0.9), "positions": np.array([1, 2])})
    assert json.loads(target.read_text(encoding="utf-8")) == {"candidate_order": 3, "mcc": 0.9, "positions": [1, 2]}


def test_frozen_base_configurations_and_protocol_g_manifest_reuse_are_checked(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    ensemble_config = yaml.safe_load((root / "configs" / "selective_static_ensemble.yaml").read_text(encoding="utf-8"))
    ft_config = yaml.safe_load((root / "configs" / "deep_learning_protocol_g.yaml").read_text(encoding="utf-8"))
    assert ensemble_config["feature_variant"] == "G-drop3constant"
    assert ensemble_config["expected_feature_count"] == 38
    assert ensemble_config["base_models"]["ft_transformer"]["configuration_source"].endswith("models.ft_transformer")
    assert ft_config["training"]["threshold"] == 0.5

    import malpdf.experiments.selective_static_ensemble as module

    rows = sum(EXPECTED_PARTITION_ROWS[name] for name in ("train", "validation", "test"))
    frame = pd.DataFrame(0.0, index=np.arange(rows), columns=list(PROTOCOL_G_REQUIRED_FEATURES))
    frame["Label"] = np.resize(np.array([0, 1]), rows)
    partitions, start = {}, 0
    for name in ("train", "validation", "test"):
        stop = start + EXPECTED_PARTITION_ROWS[name]
        partitions[name] = frame.iloc[start:stop].copy()
        start = stop
    summary = {"split_manifest_sha256": EXPECTED_SPLIT_MANIFEST_SHA256, "partition_statistics": EXPECTED_PARTITION_ROWS}
    monkeypatch.setattr(module, "repository_git_state", lambda _root: {"status": "clean"})
    monkeypatch.setattr(module, "load_rit_pdfmal", lambda _path: frame)
    monkeypatch.setattr(module, "sha256_file", lambda _path: module.EXPECTED_DATASET_SHA256)
    monkeypatch.setattr(module, "load_saved_protocol_g_split", lambda *_args, **_kwargs: (tmp_path / "manifest.csv", pd.DataFrame(), summary))
    monkeypatch.setattr(module, "split_frame_from_protocol_g_manifest", lambda *_args: partitions)
    monkeypatch.setattr(module, "protocol_g_feature_columns", lambda *_args: list(PROTOCOL_G_REQUIRED_FEATURES))
    monkeypatch.setattr(module, "collect_environment_metadata", lambda *_args: {"git_commit_sha": "a" * 40})
    monkeypatch.setattr(module, "_torch_environment", lambda: (module.torch.device("cpu"), {"device_used": "cpu"}))
    monkeypatch.setattr(module, "_assert_outputs_available", lambda _paths: None)
    preflight = preflight_selective_ensemble(root, tmp_path / "synthetic.csv")
    assert preflight.split_summary["split_manifest_sha256"] == EXPECTED_SPLIT_MANIFEST_SHA256
    assert tuple(preflight.feature_order) == PROTOCOL_G_REQUIRED_FEATURES

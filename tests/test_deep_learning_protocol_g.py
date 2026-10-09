"""Synthetic tests for the fixed Protocol G tabular neural comparison."""

from __future__ import annotations

import inspect
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
import torch

from malpdf.data.rit_pdfmal_paper_alignment import TARGET_COLUMN
from malpdf.deep_learning.models import build_tabular_model, count_trainable_parameters
from malpdf.deep_learning.training import (
    EarlyStopping,
    binary_predictions_from_probabilities,
    probabilities_from_logits,
    set_deep_learning_seed,
    train_with_validation,
)
from malpdf.evaluation.binary import evaluate_binary_predictions
from malpdf.experiments import deep_learning_protocol_g as experiment
from malpdf.static.schema import PROTOCOL_G_DROPPED_CONSTANT_FEATURES, PROTOCOL_G_REQUIRED_FEATURES, RIT_FEATURES


def _configuration() -> dict:
    return {
        "mlp": {"input_features": 38, "hidden_features": [128, 64, 32], "dropout": [0.2, 0.1, 0.0]},
        "ft_transformer": {"input_features": 38, "d_token": 32, "n_blocks": 2, "n_heads": 4, "d_ffn": 128, "attention_dropout": 0.1, "ffn_dropout": 0.1},
    }


def _frame(rows: int, offset: float = 0.0) -> pd.DataFrame:
    values = np.arange(rows * len(RIT_FEATURES), dtype=float).reshape(rows, len(RIT_FEATURES)) + offset
    frame = pd.DataFrame(values, columns=RIT_FEATURES)
    for constant in PROTOCOL_G_DROPPED_CONSTANT_FEATURES:
        frame[constant] = 0.0
    frame[TARGET_COLUMN] = np.arange(rows) % 2
    return frame


def _historical_record() -> dict:
    return {
        "status": "completed",
        "model_name": "xgboost",
        "feature_variant": "G-drop3constant",
        "dataset_sha256": experiment.EXPECTED_DATASET_SHA256,
        "split_manifest_sha256": experiment.EXPECTED_SPLIT_MANIFEST_SHA256,
        "training": {"training_seconds": 0.5},
        "test": {
            "metrics": {"accuracy": 0.9, "roc_auc": 0.95, "pr_auc": 0.96, "mcc": 0.8},
            "confusion_counts": {"tn": 8, "fp": 1, "fn": 1, "tp": 10},
        },
    }


def test_feature_contract_is_exact_protocol_g_drop3constant() -> None:
    assert len(PROTOCOL_G_REQUIRED_FEATURES) == 38
    assert PROTOCOL_G_DROPPED_CONSTANT_FEATURES == ("Acroform", "Colors", "BaseEncoding")
    assert not set(PROTOCOL_G_REQUIRED_FEATURES) & set(PROTOCOL_G_DROPPED_CONSTANT_FEATURES)


def test_train_only_scaler_does_not_fit_validation_or_test() -> None:
    partitions = {"train": _frame(6, 0.0), "validation": _frame(4, 1000.0), "test": _frame(4, -1000.0)}
    scaler = experiment._fit_train_only_scaler(partitions, PROTOCOL_G_REQUIRED_FEATURES)
    expected_train_mean = partitions["train"].loc[:, PROTOCOL_G_REQUIRED_FEATURES].to_numpy().mean(axis=0)
    assert np.allclose(scaler.mean_, expected_train_mean)
    experiment.transform_partition(scaler, partitions["validation"], PROTOCOL_G_REQUIRED_FEATURES)
    experiment.transform_partition(scaler, partitions["test"], PROTOCOL_G_REQUIRED_FEATURES)
    assert scaler.n_samples_seen_ == len(partitions["train"])
    assert not np.allclose(scaler.mean_, partitions["validation"].loc[:, PROTOCOL_G_REQUIRED_FEATURES].to_numpy().mean(axis=0))


def test_mlp_and_ft_transformer_return_one_binary_logit_per_row() -> None:
    features = torch.zeros((5, 38), dtype=torch.float32)
    configurations = _configuration()
    for model_name in ("mlp", "ft_transformer"):
        model = build_tabular_model(model_name, configurations[model_name])
        assert tuple(model(features).shape) == (5, 1)
        assert count_trainable_parameters(model) > 0


def test_probability_conversion_and_fixed_threshold_are_malicious_positive() -> None:
    probabilities = probabilities_from_logits(torch.tensor([[-2.0], [0.0], [2.0]]))
    assert np.allclose(probabilities, [0.11920292, 0.5, 0.88079708])
    assert binary_predictions_from_probabilities(np.array([0.499999, 0.5, 1.0])).tolist() == [0, 1, 1]
    metrics = evaluate_binary_predictions([0, 1, 1, 0], [0, 1, 0, 0], [0.1, 0.9, 0.2, 0.3])
    assert metrics["positive_label"] == 1
    assert metrics["precision_malicious"] == 1.0
    assert metrics["recall_malicious"] == 0.5


def test_seed_requests_determinism_and_repeats_torch_random_values() -> None:
    first = set_deep_learning_seed(42)
    values_first = torch.rand(5)
    second = set_deep_learning_seed(42)
    values_second = torch.rand(5)
    assert first["seed"] == second["seed"] == 42
    assert first["torch_deterministic_algorithms_requested"]
    assert torch.equal(values_first, values_second)


def test_early_stopping_selects_lowest_validation_loss_and_patience() -> None:
    stopper = EarlyStopping(patience=2)
    assert not stopper.update(1, 0.8)
    assert not stopper.update(2, 0.5)
    assert not stopper.update(3, 0.6)
    assert stopper.update(4, 0.7)
    assert stopper.best_epoch == 2
    assert stopper.best_loss == 0.5


def test_training_api_uses_bce_logits_and_has_no_test_loader_argument() -> None:
    signature = inspect.signature(train_with_validation)
    assert "validation_loader" in signature.parameters
    assert "test_loader" not in signature.parameters
    source = inspect.getsource(train_with_validation)
    assert "nn.BCEWithLogitsLoss" in source
    assert "AdamW" in source


def test_fp16_refuses_cpu_and_nonfinite_gradients_still_fail_closed() -> None:
    from torch.utils.data import DataLoader, TensorDataset
    loader = DataLoader(TensorDataset(torch.ones(2, 2), torch.zeros(2)), batch_size=2)
    arguments = dict(device=torch.device('cpu'), learning_rate=0.001, weight_decay=0.0,
                     max_epochs=1, patience=1, min_delta=0.0)
    with pytest.raises(ValueError, match='CUDA'):
        train_with_validation(torch.nn.Linear(2, 1), loader, loader, mixed_precision=True, **arguments)
    model = torch.nn.Linear(2, 1)
    model.weight.register_hook(lambda gradient: torch.full_like(gradient, float('inf')))
    with pytest.raises(RuntimeError, match='gradient is non-finite'):
        train_with_validation(model, loader, loader, **arguments)


def test_synthetic_run_saves_only_best_checkpoint_then_evaluates_test_once(tmp_path: Path) -> None:
    partitions = {"train": _frame(12), "validation": _frame(8, 2.0), "test": _frame(8, 4.0)}
    scaler = experiment._fit_train_only_scaler(partitions, PROTOCOL_G_REQUIRED_FEATURES)
    configuration = {
        "model_seed": 42,
        "models": _configuration(),
        "training": {
            "batch_size": 4,
            "learning_rate": 0.001,
            "weight_decay": 0.0001,
            "max_epochs": 2,
            "early_stopping_patience": 1,
            "early_stopping_min_delta": 0.0,
            "threshold": 0.5,
        },
    }
    preflight = experiment.DeepLearningPreflight(
        repository_root=tmp_path,
        dataset_path=tmp_path / "synthetic.csv",
        frame=pd.concat(partitions.values(), ignore_index=True),
        partitions=partitions,
        split_summary={"split_manifest_sha256": experiment.EXPECTED_SPLIT_MANIFEST_SHA256},
        feature_order=PROTOCOL_G_REQUIRED_FEATURES,
        scaler=scaler,
        configuration=configuration,
        historical_xgboost={},
        environment={"deep_learning": {"device_used": "cpu"}},
        code_commit_sha="a" * 40,
        device=torch.device("cpu"),
        paths=experiment.deep_learning_paths(tmp_path, "tiny"),
    )
    record = experiment._run_model(preflight, "mlp")
    checkpoint = torch.load(record["paths"].checkpoint_path, map_location="cpu", weights_only=True)
    assert checkpoint["best_epoch"] == record["best_epoch"]
    assert record["paths"].checkpoint_path.is_file()
    assert record["test_metrics"]["positive_label"] == 1
    payload = json.loads(record["paths"].metrics_json.read_text(encoding="utf-8"))
    assert payload["test_evaluation"]["evaluation_count"] == 1


def test_historical_xgboost_reference_loading_from_machine_readable_record(tmp_path: Path) -> None:
    path = tmp_path / "reports" / "experiments" / "protocol_g" / "seed42"
    path.mkdir(parents=True)
    (path / "metrics.json").write_text(json.dumps({"runs": [_historical_record()]}), encoding="utf-8")
    reference = experiment.load_historical_xgboost_reference(tmp_path)
    assert reference["test_metrics"]["f1_malicious"] == pytest.approx(20 / 22)
    assert reference["confusion_counts"] == {"tn": 8, "fp": 1, "fn": 1, "tp": 10}


def test_preflight_reuses_saved_manifest_with_synthetic_tabular_frame(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_source = Path(__file__).resolve().parents[1] / "configs" / "deep_learning_protocol_g.yaml"
    destination = tmp_path / "configs"
    destination.mkdir()
    (destination / "deep_learning_protocol_g.yaml").write_text(config_source.read_text(encoding="utf-8"), encoding="utf-8")
    partitions = {"train": _frame(14_602), "validation": _frame(4_868, 1.0), "test": _frame(4_867, 2.0)}
    full_frame = pd.concat(partitions.values(), ignore_index=True)
    summary = {"split_manifest_sha256": experiment.EXPECTED_SPLIT_MANIFEST_SHA256}
    calls: list[str] = []
    monkeypatch.setattr(experiment, "load_rit_pdfmal", lambda _path: full_frame)
    monkeypatch.setattr(experiment, "sha256_file", lambda _path: experiment.EXPECTED_DATASET_SHA256)
    monkeypatch.setattr(experiment, "repository_git_state", lambda _root: {"status": "clean", "porcelain_entries": []})
    monkeypatch.setattr(experiment, "collect_environment_metadata", lambda _path, _root: {"dataset_sha256": experiment.EXPECTED_DATASET_SHA256, "git_commit_sha": "a" * 40})
    monkeypatch.setattr(experiment, "load_saved_protocol_g_split", lambda *args, **kwargs: (calls.append("manifest") or (tmp_path / "manifest.csv", pd.DataFrame(), summary)))
    monkeypatch.setattr(experiment, "split_frame_from_protocol_g_manifest", lambda _frame, _manifest: partitions)
    historical_path = tmp_path / "reports" / "experiments" / "protocol_g" / "seed42"
    historical_path.mkdir(parents=True)
    (historical_path / "metrics.json").write_text(json.dumps({"runs": [_historical_record()]}), encoding="utf-8")
    preflight = experiment.preflight_deep_learning_protocol_g(tmp_path, tmp_path / "rit.csv")
    assert calls == ["manifest"]
    assert preflight.feature_order == PROTOCOL_G_REQUIRED_FEATURES
    assert preflight.split_summary == summary
    assert preflight.scaler.n_samples_seen_ == 14_602


def test_gitignore_keeps_raw_data_and_torch_checkpoints_out_of_git() -> None:
    gitignore = (Path(__file__).resolve().parents[1] / ".gitignore").read_text(encoding="utf-8")
    assert "data/raw/**" in gitignore
    assert "artifacts/**" in gitignore
    assert "*.pt" in gitignore

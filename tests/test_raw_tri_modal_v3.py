"""Offline missing-data and validation-lock checks for the acquired raw cohort."""

from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from sklearn.impute import SimpleImputer
import torch
import yaml

from malpdf.data.raw_cohort import RAW_FEATURES
from malpdf.experiments.raw_tri_modal_v3 import BRANCHES, fail_closed_routing, group_folds, safety_feature_order, validate_configuration, validation_roles
from malpdf.models.safe_stacking import fit_validation_v3
from malpdf.models.v3_base_learners import FoldImputer, NativeMissingIndicators, fit_v3_fold
from malpdf.experiments import raw_tri_modal_v3 as runner
from malpdf.data.vision_dataset import VisionSample


def features(rows=40):
    frame = pd.DataFrame({name: np.arange(rows, dtype=float) + 1 for name in RAW_FEATURES})
    frame.loc[:, ["Acroform", "Colors", "BaseEncoding"]] = 0
    frame["script_ratio"] = (frame.JS + frame.JavaScript) / (1 + frame.obj)
    frame["ObfuscationCount"] = np.arange(rows) % 3
    return frame


def test_native_tree_nans_are_preserved_and_security_missing_is_rejected():
    frame = features()
    order, _ = safety_feature_order(frame)
    raw = frame.loc[:, list(order)].to_numpy()
    raw[0, order.index("title length")] = np.nan
    processor = NativeMissingIndicators(order)
    transformed = processor.transform(raw)
    assert np.isnan(transformed[0, order.index("title length")])
    assert transformed[0, processor.expanded_order.index("title length__missing")] == 1
    assert np.array_equal(transformed[:, order.index("ObfuscationCount")], raw[:, order.index("ObfuscationCount")])
    raw[1, order.index("JS")] = np.nan
    with pytest.raises(ValueError, match="metadata"):
        processor.transform(raw)


def test_median_is_learned_on_train_and_missing_flags_survive_transform():
    frame = features()
    order, _ = safety_feature_order(frame)
    train = frame.iloc[:3].loc[:, list(order)].to_numpy()
    column = order.index("title length")
    train[:, column] = [10, 20, np.nan]
    processor = FoldImputer(SimpleImputer(strategy="median", keep_empty_features=True).fit(train), order)
    future = train.copy()
    future[:, column] = [9000, np.nan, -999]
    output = processor.transform(future)
    assert output[1, column] == 15
    assert output[1, processor.expanded_order.index("title length__missing")] == 1
    assert output[2, column] == -999
    assert np.isnan(train[2, column])
    assert processor.imputer.statistics_[column] == 15


def test_only_allowed_train_constants_are_dropped_and_variable_acroform_stays():
    train = features()
    train.loc[1, "Acroform"] = 1
    train["RichMedia"] = 0
    order, removed = safety_feature_order(train)
    assert removed == ("Colors", "BaseEncoding")
    assert "Acroform" in order and "RichMedia" in order
    assert "script_ratio" in order and "ObfuscationCount" in order


def manifest(partition="validation"):
    return pd.DataFrame({"sample_id": [f"benign_fixture:{i}" for i in range(160)],
                         "duplicate_group_id": [f"g{i // 2}" for i in range(160)],
                         "Label": np.arange(160) % 2, "split": partition})


def test_six_branch_meta_fit_accepts_disjoint_mixed_label_groups_and_rejects_leaks():
    saved = manifest()
    roles = validation_roles(saved)
    scores = np.tile(np.where(saved.Label, 0.8, 0.2)[:, None], (1, 6))
    model, candidates = fit_validation_v3(saved, scores, [0.1, 1.0], branches=BRANCHES, roles=roles)
    assert model.branches == BRANCHES and len(model.meta.coef_[0]) == 6
    assert model.lock_metadata()["test_used_for_fitting_or_selection"] is False
    assert len(candidates) == 2 and np.isfinite(model.predict_proba(scores)).all()
    with pytest.raises(ValueError, match="validation-only"):
        fit_validation_v3(saved.assign(split="test"), scores, [1.0], branches=BRANCHES, roles=roles)
    leaked = dict(roles)
    leaked["calibration_fit"] = roles["meta_fit"]
    with pytest.raises(ValueError, match="preserve components"):
        fit_validation_v3(saved, scores, [1.0], branches=BRANCHES, roles=leaked)
    folds = group_folds(saved.assign(split="train"), partition="train", count=5)
    assert np.all(np.bincount(np.concatenate([held for _, held in folds]), minlength=len(saved)) == 1)


def test_parser_failures_override_entropy_budget_without_label_driven_routing():
    p = np.linspace(0.01, 0.99, 40)
    y = np.arange(40) % 2
    forced = np.zeros(40, bool)
    forced[[0, 1, 2, 3, 4, 5]] = True
    ids = [f"fixture:{i:03}" for i in range(40)]
    summary, referred = fail_closed_routing(y, p, ids, forced, threshold=0.5)
    _, flipped = fail_closed_routing(1 - y, p, ids, forced, threshold=0.5)
    assert np.array_equal(referred, flipped)
    assert referred[forced].all() and referred.sum() == 6
    assert summary["coverage"] == pytest.approx(0.85)
    assert summary["dynamic_samples_executed"] == 0


@pytest.mark.parametrize("name", ["xgboost", "lightgbm", "catboost", "random_forest", "ft_transformer"])
def test_each_real_base_learner_handles_nullable_metadata_in_its_own_training_fold(tmp_path, name):
    cfg = yaml.safe_load((Path(__file__).resolve().parents[1] / "configs/raw_tri_modal_v3.yaml").read_text())
    validate_configuration(cfg)
    cfg["cpu_threads"] = 1
    cfg["training"].update(max_epochs=1, patience=1, batch_size=16)
    cfg["models"]["xgboost"].update(n_estimators=3, max_depth=2)
    cfg["models"]["lightgbm"].update(n_estimators=3, num_leaves=4, min_child_samples=2)
    cfg["models"]["catboost"].update(iterations=3, depth=2)
    cfg["models"]["random_forest"].update(n_estimators=3, max_depth=2)
    cfg["models"]["ft_transformer"].update(d_token=8, n_blocks=1, n_heads=2, d_ffn=16)
    torch.set_num_threads(1)
    frame = features(40)
    order, _ = safety_feature_order(frame)
    frame.loc[::3, "title length"] = np.nan
    model, info = fit_v3_fold(name, cfg, frame.iloc[:30].loc[:, list(order)], np.arange(30) % 2,
        frame.iloc[30:].loc[:, list(order)], np.arange(10) % 2, tmp_path / name, feature_order=order, impute_metadata=True)
    assert np.isfinite(model.predict_proba(frame.loc[:, list(order)])).all()
    if name in {"xgboost", "lightgbm", "catboost"}:
        assert isinstance(model.preprocessor, NativeMissingIndicators)
        assert not (tmp_path / name / "imputation.json").exists()
    else:
        assert isinstance(model.preprocessor, FoldImputer)
        assert (tmp_path / name / "imputation.json").is_file()
    assert info["fit_rows"] == 30
    assert frame["title length"].isna().any()


def test_pipeline_fits_no_test_rows_locks_before_test_and_keeps_unknown_labels(tmp_path, monkeypatch):
    cfg = yaml.safe_load((Path(__file__).resolve().parents[1] / "configs/raw_tri_modal_v3.yaml").read_text())
    cfg["vision"].update(max_epochs=1, batch_size=16)
    cfg["training"]["max_epochs"] = 1
    records = []
    for partition, first, count in (("train", 1, 80), ("validation", 81, 80), ("test", 161, 20), ("unknown", 181, 4)):
        frame = features(count)
        frame["JS"] = np.arange(first, first + count)
        frame["sample_id"] = [f"fixture:{value}" for value in frame.JS]
        frame["Label"] = (frame.JS - 1) % 2 if partition != "unknown" else np.nan
        frame["parser_failed"] = False
        frame["split"] = partition
        frame["duplicate_group_id"] = [f"{partition}_group_{i // 2}" for i in range(count)]
        records.append(frame)
    table = pd.concat(records[:3], ignore_index=True)
    saved = table.loc[:, ["sample_id", "Label", "split", "duplicate_group_id"]]
    labeled = table.drop(columns=["split", "duplicate_group_id"])
    unknown = records[-1].drop(columns=["split", "duplicate_group_id"])
    sources = pd.DataFrame({"sample_id": pd.concat((labeled, unknown)).sample_id, "pdf_sha256": "0" * 64}).set_index("sample_id")
    monkeypatch.setattr(runner, "load_locked_cohort", lambda root, config: (labeled, saved, sources, unknown))

    class Run:
        def __init__(self, *args, **kwargs):
            self.report, self.artifacts = tmp_path / "report", tmp_path / "artifacts"
            self.report.mkdir()
            self.artifacts.mkdir()
            self.commit = "a" * 40
            self.state = {"code_worktree": {"status": "clean"}, "metrics": {}, "status": "started"}
        def __enter__(self): return self
        def __exit__(self, *args): self.state["status"] = "completed"
        def progress(self, *args, **kwargs): pass
    monkeypatch.setattr(runner, "ResearchRun", Run)
    fitted, test_calls, vision_tests = [], [], []
    class Model:
        def predict_proba(self, frame):
            if frame.JS.min() >= 161 and frame.JS.max() <= 180:
                assert (tmp_path / "report/validation_lock.json").is_file()
                assert (tmp_path / "report/test_evaluation_started.json").is_file()
                test_calls.append(1)
            return np.where((frame.JS - 1) % 2, 0.8, 0.2)
    def fit(name, config, train_x, train_y, selection_x, selection_y, path, **kwargs):
        assert train_x.JS.between(1, 80).all()
        assert selection_x.JS.between(81, 160).all()
        fitted.append(name)
        return Model(), {"model": name, "fit_rows": len(train_x)}
    monkeypatch.setattr(runner, "fit_v3_fold", fit)
    monkeypatch.setattr(runner, "verify_vision_caches", lambda samples, cache: samples)
    def loader(samples, cache, batch_size, *, shuffle=False, include_labels=True):
        values = torch.tensor([int(s.sample_id.split(":")[-1]) for s in samples], dtype=torch.float32).reshape(-1, 1)
        if values.min() >= 161 and values.max() <= 180:
            assert (tmp_path / "report/validation_lock.json").is_file()
            vision_tests.append(1)
        if include_labels:
            assert all(s.label in (0, 1) for s in samples)
            data = torch.utils.data.TensorDataset(values, torch.tensor([s.label for s in samples], dtype=torch.float32))
        else:
            assert all(s.label is None for s in samples)
            data = values
        return torch.utils.data.DataLoader(data, batch_size=batch_size, shuffle=shuffle)
    monkeypatch.setattr(runner, "_vision_loader", loader)
    class Tiny(torch.nn.Module):
        def __init__(self):
            super().__init__()
            self.weight = torch.nn.Parameter(torch.tensor(1.0))
        def forward(self, x): return (((x - 1) % 2) * 2 - 1) * self.weight
    monkeypatch.setattr(runner, "VisionResNet18", Tiny)
    result = runner.run_raw_tri_modal(tmp_path, tmp_path, cfg, execute=True)
    assert len(fitted) == 25 and len(test_calls) == 25 and len(vision_tests) == 1
    assert result["test_evaluation_count"] == 1
    prediction = pd.read_csv(tmp_path / "artifacts/unlabeled_predictions.csv")
    assert len(prediction) == 4 and prediction.Label.isna().all()
    assert result["metrics"]["stacking_v3/unlabeled_prediction"] == {}

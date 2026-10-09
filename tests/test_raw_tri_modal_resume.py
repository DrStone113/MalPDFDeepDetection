"""Offline import, saved-fold restoration, and one-time Test continuation guards."""

import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
import torch
import yaml

from malpdf.experiments import raw_tri_modal_resume as runner
from malpdf.experiments.raw_tri_modal_v3 import BRANCHES, group_folds, safety_feature_order, validation_roles
from malpdf.models.safe_stacking import V3_BRANCHES
from malpdf.models.v3_base_learners import fit_v3_fold, load_v3_fold
from test_raw_tri_modal_v3 import features


def configuration():
    config = yaml.safe_load((Path(__file__).resolve().parents[1] / "configs/raw_tri_modal_v3.yaml").read_text())
    for name in ("xgboost", "lightgbm", "random_forest"):
        config["models"][name]["n_estimators"] = 3
    config["models"]["catboost"]["iterations"] = 3
    config["training"].update(max_epochs=1, batch_size=16)
    return config


@pytest.mark.parametrize("name", V3_BRANCHES)
def test_saved_fold_roundtrip_restores_train_only_state_and_rejects_changes(tmp_path, name, monkeypatch):
    torch.set_num_threads(1)
    config, frame = configuration(), features()
    order, _ = safety_feature_order(frame)
    frame.loc[::3, "title length"] = np.nan
    train, future = frame.iloc[:30].loc[:, list(order)], frame.iloc[30:].loc[:, list(order)]
    folder = tmp_path / name / "fold_1"
    fitted, info = fit_v3_fold(name, config, train, np.arange(30) % 2,
        future, np.arange(10) % 2, folder, feature_order=order, impute_metadata=True)
    expected = fitted.predict_proba(future)
    def forbidden(*args, **kwargs):
        raise AssertionError("Continuation must not fit models or preprocessing")
    monkeypatch.setattr(type(fitted.model), "fit", forbidden, raising=False)
    checkpoint = Path(info["checkpoint"])
    restored, _ = load_v3_fold(checkpoint, info["checkpoint_sha256"], train,
        config, boundary=tmp_path, base_selection_rows=10)
    np.testing.assert_allclose(restored.predict_proba(future), expected, rtol=1e-7, atol=1e-8)
    with pytest.raises(ValueError, match="checksum"):
        load_v3_fold(checkpoint, "0" * 64, train, config, boundary=tmp_path, base_selection_rows=10)
    if name in {"random_forest", "ft_transformer"}:
        changed = train.copy()
        changed["title length"] = 999999
        with pytest.raises(ValueError, match="Train-only medians"):
            load_v3_fold(checkpoint, info["checkpoint_sha256"], changed, config, boundary=tmp_path, base_selection_rows=10)


def probability_inputs():
    portable = pd.DataFrame({"sample_id": ["sample_000001", "sample_000002", "sample_000003"],
                             "split": ["validation", "validation", "test"]})
    manifest = pd.DataFrame({"sample_id": ["local:b", "local:a", "local:c"],
                             "split": ["validation", "validation", "test"]})
    mapping = pd.DataFrame({"sample_id": ["local:a", "local:b", "local:c"],
                            "export_sample_id": portable.sample_id})
    frame = pd.DataFrame({"sample_id": ["sample_000002", "sample_000001"], "p_malicious": [0.8, 0.2]})
    return frame, portable, manifest, mapping


def test_vision_join_uses_exact_partition_id_mapping_not_row_order():
    frame, portable, manifest, mapping = probability_inputs()
    result = runner.aligned_vision_probabilities(frame, portable, manifest, mapping, partition="validation")
    np.testing.assert_array_equal(result, [0.8, 0.2])


@pytest.mark.parametrize("fault", ["duplicate", "missing", "test_id", "extra", "nan", "inf", "negative", "large", "label_column"])
def test_bad_vision_import_is_rejected(fault):
    frame, portable, manifest, mapping = probability_inputs()
    if fault == "duplicate": frame.loc[1, "sample_id"] = frame.loc[0, "sample_id"]
    elif fault == "missing": frame = frame.iloc[:1]
    elif fault == "test_id": frame.loc[1, "sample_id"] = "sample_000003"
    elif fault == "extra": frame.loc[2] = ["sample_000004", 0.5]
    elif fault == "label_column": frame["Label"] = 1
    else: frame.loc[0, "p_malicious"] = {"nan": np.nan, "inf": np.inf, "negative": -0.1, "large": 1.1}[fault]
    with pytest.raises(ValueError):
        runner.aligned_vision_probabilities(frame, portable, manifest, mapping, partition="validation")


def save_json(path, obj):
    path.write_text(json.dumps(obj))


def vision_evidence(tmp_path):
    directory = tmp_path / "checkpoints"
    directory.mkdir()
    inventory = {"code_commit": "a" * 40, "metadata_sha256": "b" * 64, "validation_roles": {"base_selection": 10}}
    csv_hashes = {"vision_probs_val.csv": "c" * 64, "vision_probs_test.csv": "d" * 64}
    lock = {"run_id": "run_fixture", "code_commit": "a" * 40, "seed": 42,
            "selected_role": "validation_base_selection", "selection_rows": 10,
            "bundle_metadata_sha256": "b" * 64, "test_metrics_computed": False, "test_prediction_passes": 0,
            "checkpoint_sha256": "e" * 64, "best_epoch": 1, "configuration": {"max_epochs": 2}}
    summary = {**lock, "status": "completed", "test_prediction_passes": 1}
    save_json(directory / "vision_selection_lock.json", lock)
    checks = {**csv_hashes, "vision_resnet_best.pt": "e" * 64,
              "vision_selection_lock.json": hashlib.sha256((directory / "vision_selection_lock.json").read_bytes()).hexdigest()}
    save_json(directory / "output_checksums.json", checks)
    save_json(directory / "run_summary.json", summary)
    return directory, inventory, csv_hashes, lock, summary


def test_original_sealed_vision_provenance_is_accepted(tmp_path):
    directory, inventory, csv_hashes, *_ = vision_evidence(tmp_path)
    result = runner.validate_vision_evidence(directory, tmp_path, inventory, csv_hashes)
    assert result["selected_role"] == "validation_base_selection"


@pytest.mark.parametrize("fault", ["missing", "wrong_csv", "wrong_role", "wrong_rows", "wrong_bundle", "test_metrics", "double_test", "unsealed_code"])
def test_vision_provenance_failure_stops_before_test(fault, tmp_path):
    directory, inventory, csv_hashes, lock, summary = vision_evidence(tmp_path)
    if fault == "missing":
        (directory / "vision_selection_lock.json").unlink()
        with pytest.raises(FileNotFoundError, match="vision_selection_lock"):
            runner.validate_vision_evidence(directory, tmp_path, inventory, csv_hashes)
        return
    if fault == "wrong_csv": csv_hashes["vision_probs_test.csv"] = "f" * 64
    elif fault == "wrong_role": lock["selected_role"] = "full_validation"
    elif fault == "wrong_rows": lock["selection_rows"] = 40
    elif fault == "wrong_bundle": lock["bundle_metadata_sha256"] = "f" * 64
    elif fault == "test_metrics": summary["test_metrics_computed"] = True
    elif fault == "double_test": summary["test_prediction_passes"] = 2
    elif fault == "unsealed_code": lock["code_commit"] = summary["code_commit"] = "f" * 40
    save_json(directory / "vision_selection_lock.json", lock)
    checks = json.loads((directory / "output_checksums.json").read_text())
    checks["vision_selection_lock.json"] = hashlib.sha256((directory / "vision_selection_lock.json").read_bytes()).hexdigest()
    save_json(directory / "output_checksums.json", checks)
    save_json(directory / "run_summary.json", summary)
    with pytest.raises(ValueError):
        runner.validate_vision_evidence(directory, tmp_path, inventory, csv_hashes)


def test_exclusive_test_claim_blocks_repeat_and_preserves_marker(tmp_path):
    report = tmp_path / "reports/experiments/resume/run_fixture"
    report.mkdir(parents=True)
    locks = {"split_manifest": {"sha256": "a" * 64}}
    runner.claim_test_evaluation(tmp_path, locks, report, "b" * 64)
    marker = (report / "test_evaluation_started.json").read_bytes()
    with pytest.raises(FileExistsError):
        runner.claim_test_evaluation(tmp_path, locks, report, "c" * 64)
    assert (report / "test_evaluation_started.json").read_bytes() == marker


def test_historical_raw_cohort_test_evaluation_also_blocks_resume(tmp_path):
    folder = tmp_path / "reports/experiments/raw_tri_modal_v3/run_prior"
    folder.mkdir(parents=True)
    locks = {"split_manifest": {"sha256": "a" * 64}}
    save_json(folder / "locked_methodology.json", {"configuration": {"inputs": locks}})
    save_json(folder / "test_evaluation_started.json", {})
    with pytest.raises(ValueError, match="already been evaluated"):
        runner.claim_test_evaluation(tmp_path, locks, tmp_path, "b" * 64)


def test_resume_reuses_all_models_and_evaluates_after_validation_lock(tmp_path, monkeypatch):
    config = configuration()
    frames = []
    for split, start, count in (("train", 1, 80), ("validation", 81, 80), ("test", 161, 20)):
        frame = features(count)
        frame["JS"] = np.arange(start, start + count)
        frame["sample_id"] = [f"fixture_{i}" for i in frame.JS]
        frame["Label"] = (frame.JS - 1) % 2
        frame["parser_failed"] = False
        frame["split"] = split
        frame["duplicate_group_id"] = [f"{split}_{i // 2}" for i in range(count)]
        frames.append(frame)
    table = pd.concat(frames, ignore_index=True)
    manifest = table.loc[:, ["sample_id", "Label", "split", "duplicate_group_id"]]
    labeled = table.drop(columns=["split", "duplicate_group_id"])
    role_indices = validation_roles(manifest.loc[manifest.split.eq("validation")].reset_index(drop=True))
    probabilities = {split: np.where(frames[i].Label, 0.8, 0.2) for i, split in ((1, "validation"), (2, "test"))}
    filenames = ("model.ubj", "model.txt", "model.cbm", "model.joblib", "model.pt")
    plan = {"prior_run": "run_fixture", "checkpoints": [{"path": f"artifacts/raw_tri_modal_v3/run_fixture/tabular/{name}/fold_{i}/{filename}", "sha256": "a" * 64}
              for name, filename in zip(V3_BRANCHES, filenames) for i in range(1, 6)]}
    class Run:
        def __init__(self, *args, **kwargs):
            self.report, self.artifacts = tmp_path / "report", tmp_path / "private"
            self.report.mkdir()
            self.artifacts.mkdir()
            self.commit = "a" * 40
            self.state = {"code_worktree": {"status": "clean"}, "metrics": {}, "status": "started", "vision": {"verified": True}}
        def __enter__(self): return self
        def __exit__(self, *args): self.state["status"] = "completed"
        def progress(self, *args, **kwargs): pass
    monkeypatch.setattr(runner, "ResearchRun", Run)
    monkeypatch.setattr(runner, "load_resume_inputs", lambda *args: (labeled, manifest, role_indices, probabilities, plan))
    calls, tests = [], []
    class Model:
        def predict_proba(self, frame):
            if frame.JS.min() >= 161:
                assert (tmp_path / "report/validation_lock.json").is_file()
                assert (tmp_path / "report/test_evaluation_started.json").is_file()
                tests.append(1)
            return np.where((frame.JS - 1) % 2, 0.8, 0.2)
    def load(checkpoint, digest, train, cfg, **kwargs):
        assert train.JS.between(1, 80).all()
        assert kwargs["base_selection_rows"] == len(role_indices["base_selection"])
        calls.append(checkpoint)
        return Model(), {"model": checkpoint.parent.parent.name}
    monkeypatch.setattr(runner, "load_v3_fold", load)
    result = runner.run_raw_tri_modal_resume(tmp_path, tmp_path, config, "run_fixture", tmp_path / "checkpoints", execute=True)
    assert len(calls) == 25 and len(tests) == 25
    assert result["test_evaluation_count"] == 1
    assert result["tabular_models_refitted"] == result["vision_models_refitted"] == 0
    lock = json.loads((tmp_path / "report/validation_lock.json").read_text())
    assert lock["branches"] == list(BRANCHES)
    assert lock["test_used_for_fitting_or_selection"] is False
    assert result["metrics"]["stacking_v3/test"]["accuracy"] == 1

"""Offline development-study leakage, weighting and numeric-handoff checks."""
import hashlib
import json
from pathlib import Path
import zipfile
import subprocess
import sys

import numpy as np
import pandas as pd
import pytest
import yaml

from malpdf.experiments import static_development as study
from malpdf.experiments.static_development_handoff import sealed_training_script
from malpdf.models.safe_stacking import V3_FEATURES
from malpdf.models.v3_base_learners import METADATA_FEATURES, fit_v3_fold


def rows(partition="train"):
    records = []
    for cohort, size in (("source_raw", 12), ("cic", 4)):
        for label in (0, 1):
            for i in range(size):
                records.append({"sample_id": f"{cohort}_{label}_{i}", "cohort": cohort, "Label": label,
                    "group_id": f"{cohort}_{label}_{i // 2}", "split": partition, "role": "meta_fit"})
    return pd.DataFrame(records)


def validation():
    frames = []
    for role in study.ROLES:
        frame = rows("validation")
        frame["sample_id"] += "_" + role
        frame["group_id"] += "_" + role
        frame["role"] = role
        frames.append(frame)
    return pd.concat(frames, ignore_index=True)


def test_train_balancing_equalizes_cells_and_duplicate_group_mass():
    frame = rows()
    extra = frame.iloc[[0] * 9].copy()
    extra["sample_id"] = ["extra_" + str(i) for i in range(9)]
    frame = pd.concat([frame, extra], ignore_index=True)
    weights = study.cohort_weights(frame, "cohort_group_class", fit_partition="train")
    weighted = frame.assign(weight=weights)
    assert weights.mean() == pytest.approx(1)
    cells = weighted.groupby(["cohort", "Label"]).weight.sum()
    assert np.allclose(cells, len(frame) / 4)
    within = weighted.query("cohort == 'source_raw' and Label == 0").groupby("group_id").weight.sum()
    assert np.allclose(within, within.iloc[0])
    assert np.array_equal(study.cohort_weights(frame, "uniform", fit_partition="train"), np.ones(len(frame)))


@pytest.mark.parametrize("partition,role", [("test", "train"), ("validation", "train"), ("train", "meta_fit")])
def test_weighting_refuses_future_or_mixed_roles(partition, role):
    with pytest.raises(ValueError):
        study.cohort_weights(rows(partition), "cohort_group_class", fit_partition=role)
    with pytest.raises(ValueError, match="mix"):
        study.cohort_weights(validation(), "cohort_group_class", fit_partition="meta_fit")


def test_meta_platt_fit_only_their_disjoint_validation_roles(monkeypatch):
    frame = validation()
    probabilities = np.tile(np.where(frame.Label.to_numpy(), .8, .2)[:, None], (1, 5))
    calls = []
    original = study.LogisticRegression.fit
    def record(self, x, y, **kwargs):
        calls.append((np.array(x), np.array(y), np.array(kwargs["sample_weight"])))
        return original(self, x, y, **kwargs)
    monkeypatch.setattr(study.LogisticRegression, "fit", record)
    _, candidates, selected = study.fit_development_stack(frame, probabilities, "cohort_group_class", [1.])
    assert len(calls) == 2
    fit = frame.role.eq("meta_fit")
    assert np.array_equal(calls[0][0], probabilities[fit])
    assert np.array_equal(calls[0][1], frame.loc[fit].Label)
    assert len(calls[1][0]) == frame.role.eq("calibration_fit").sum()
    assert calls[1][0].shape[1] == 1
    assert selected["macro_mcc"] == pytest.approx(1)
    assert len(candidates) == 1
    with pytest.raises(ValueError, match="Validation"):
        study.fit_development_stack(frame.assign(split="test"), probabilities, "uniform", [1.])
    leaked = frame.copy()
    leaked.loc[leaked.role.eq("calibration_fit"), "group_id"] = frame.loc[fit].group_id.to_numpy()
    with pytest.raises(ValueError, match="Validation"):
        study.fit_development_stack(leaked, probabilities, "uniform", [1.])


def test_base_selection_labels_do_not_fit_meta_or_select_candidates():
    frame = validation()
    probabilities = np.tile(np.where(frame.Label.to_numpy(), .8, .2)[:, None], (1, 5))
    before = study.fit_development_stack(frame, probabilities, "uniform", [.1, 1.])[2]
    frame.loc[frame.role.eq("base_selection"), "Label"] = 1 - frame.loc[frame.role.eq("base_selection"), "Label"]
    after = study.fit_development_stack(frame, probabilities, "uniform", [.1, 1.])[2]
    assert before == after


def synthetic_bundle(path):
    records, roles, folds, reuse = [], [], [], []
    for split in ("train", "validation", "test"):
        for cohort in ("source_raw", "cic"):
            roles_here = range(1, 6) if split == "train" else study.ROLES if split == "validation" else ["test"]
            for role in roles_here:
                for label in (0, 1):
                    sid = f"sample_{len(records):06}"
                    records.append({"sample_id": sid, "Label": label, "split": split,
                        "group_id": f"g_{split}_{cohort}_{role}_{label}", "parser_failed": 0,
                        "cache_relative_path": f"markov_cache/{sid}.npy", "npy_sha256": "0" * 64})
                    if split == "train": folds.append({"sample_id": sid, "fold": role})
                    if split == "validation": roles.append({"sample_id": sid, "role": role})
                    if cohort == "source_raw": reuse.append({"sample_id": sid, "legacy_sample_id": sid})
    manifest = pd.DataFrame(records)
    features = pd.DataFrame({name: np.arange(len(records), dtype=float) for name in V3_FEATURES})
    features.insert(0, "sample_id", manifest.sample_id)
    features.loc[manifest.split.eq("test"), list(V3_FEATURES)] = np.inf  # Test must not be transformed/inspected for feature selection.
    configuration = {"feature_order": list(V3_FEATURES), "metadata_features": list(METADATA_FEATURES), "tabular": {}}
    members = {"manifest.csv": manifest.to_csv(index=False).encode(), "validation_roles.csv": pd.DataFrame(roles).to_csv(index=False).encode(),
        "train_folds.csv": pd.DataFrame(folds).to_csv(index=False).encode(), "source_matrix_reuse.csv": pd.DataFrame(reuse).to_csv(index=False).encode(),
        "tabular_features.csv": features.to_csv(index=False).encode(), "v4_gpu_configuration.json": json.dumps(configuration).encode()}
    metadata = {"seed": 42, "shape": [1, 256, 256], "raw_pdfs_included": False, "raw_pdf_hashes_included": False,
        "partition_rows": manifest.split.value_counts().to_dict(), "reused_source_matrices": len(reuse),
        "file_sha256": {name: hashlib.sha256(content).hexdigest() for name, content in members.items()}}
    members["bundle_metadata.json"] = json.dumps(metadata).encode()
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in members.items(): archive.writestr(name, content)
    return hashlib.sha256(members["bundle_metadata.json"]).hexdigest()


def test_small_numeric_input_preserves_saved_splits_and_excludes_test_values(tmp_path):
    mounted = tmp_path / "input"
    mounted.mkdir()
    digest = synthetic_bundle(mounted / "numeric.zip")
    bundle = study.numeric_input(mounted, digest, tmp_path / "tables")
    train, val, features, assignments, _, _ = study.development_tables(bundle)
    assert train.split.eq("train").all() and val.split.eq("validation").all()
    assert set(assignments) == {1, 2, 3, 4, 5}
    assert np.isfinite(features.to_numpy()).all()
    assert set(features.index) == set(train.sample_id) | set(val.sample_id)
    assert not (bundle / "markov_cache").exists()
    with pytest.raises(ValueError, match="collision|File exists"):
        study.numeric_input(mounted, digest, bundle)


@pytest.mark.parametrize("name", ["xgboost", "lightgbm", "catboost", "random_forest"])
def test_all_tree_families_accept_positive_train_weights_without_mutating_raw_data(tmp_path, name):
    cfg = yaml.safe_load((Path(__file__).parents[1] / "configs/raw_tri_modal_v3.yaml").read_text())
    cfg["cpu_threads"] = 1
    cfg["models"]["xgboost"].update(n_estimators=3, max_depth=2)
    cfg["models"]["lightgbm"].update(n_estimators=3, num_leaves=4, min_child_samples=2)
    cfg["models"]["catboost"].update(iterations=3, depth=2)
    cfg["models"]["random_forest"].update(n_estimators=3, max_depth=2)
    features = pd.DataFrame({key: np.arange(30, dtype=float) for key in V3_FEATURES})
    features.loc[0, "title length"] = np.nan
    labels = np.arange(30) % 2
    weights = np.linspace(.5, 1.5, 20)
    model, info = fit_v3_fold(name, cfg, features.iloc[:20], labels[:20], features.iloc[20:], labels[20:], tmp_path / name,
        feature_order=V3_FEATURES, impute_metadata=True, train_sample_weight=weights)
    assert info["train_weight_sum"] == pytest.approx(20)
    assert np.isfinite(model.predict_proba(features)).all()
    assert np.isnan(features.loc[0, "title length"])
    with pytest.raises(ValueError, match="weights"):
        fit_v3_fold(name, cfg, features.iloc[:20], labels[:20], features.iloc[20:], labels[20:], tmp_path / "invalid",
            feature_order=V3_FEATURES, impute_metadata=True, train_sample_weight=np.zeros(20))
    assert not (tmp_path / "invalid").exists()


def test_cloud_source_seal_is_executable_and_contains_no_local_data(tmp_path):
    folder = tmp_path / "src/malpdf"
    folder.mkdir(parents=True)
    (folder / "__init__.py").write_text("# tiny fixture\n")
    script = sealed_training_script(tmp_path, {"seed": 42}, "a" * 40)
    compile(script, "train.py", "exec")
    assert "raw_pdfs" not in script and "private_id_map" not in script
    assert str(tmp_path) not in script


def test_full_study_refuses_codespace_cpu_training(tmp_path, monkeypatch):
    monkeypatch.setattr(study.torch.cuda, "is_available", lambda: False)
    with pytest.raises(RuntimeError, match="Kaggle CUDA"):
        study.train_static_development(tmp_path, tmp_path / "output", {}, "a" * 40)
    assert not (tmp_path / "output").exists()


def test_numeric_cloud_training_imports_without_any_pdf_parser():
    source = Path(__file__).resolve().parents[1] / "src"
    script = f"""import sys, importlib.abc
sys.path.insert(0, {str(source)!r})
class BlockPdfParsers(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {{'pymupdf', 'fitz', 'pypdf'}}:
            raise AssertionError('Numeric training must not import a PDF parser: ' + fullname)
sys.meta_path.insert(0, BlockPdfParsers())
import malpdf.experiments.static_development
from malpdf.static import StaticInspectionLimits
print('numeric imports verified')
"""
    result = subprocess.run([sys.executable, "-E", "-c", script], text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert "numeric imports verified" in result.stdout

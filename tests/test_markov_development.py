"""Synthetic byte profiles, independent role allocation and weighted stopping."""
import hashlib
import io
import json
from pathlib import Path
import zipfile

import numpy as np
import pandas as pd
import pytest
import torch
from torch.utils.data import DataLoader, TensorDataset
import yaml

from malpdf.data.development_inputs import diverse_validation_roles, load_development_profiles
from malpdf.deep_learning.training import _mean_loss
from malpdf.experiments.static_development_handoff import sealed_training_script
from malpdf.experiments.static_development import cohort_weights
from malpdf.models.safe_stacking import V3_FEATURES
from malpdf.models.v3_base_learners import _features, fit_v3_fold
from malpdf.static.markov import byte_transition_matrix
from malpdf.static.markov_profiles import MARKOV_PROFILE_FEATURES, markov_profile


def test_profiles_preserve_original_probabilities_and_measure_actual_transition_structure():
    matrix = byte_transition_matrix(b"AB" * 100)
    original = matrix.copy()
    values = dict(zip(MARKOV_PROFILE_FEATURES, markov_profile(matrix)))
    assert np.array_equal(matrix, original)
    assert values["markov__active_fraction"] == pytest.approx(2 / 256)
    assert values["markov__entropy_mean"] == 0
    assert values["markov__row_max_mean"] == 1
    assert values["markov__diagonal_mean"] == 0
    assert values["markov__transition_band_1_1"] == 1
    assert not np.array_equal(markov_profile(matrix), markov_profile(byte_transition_matrix(b"A\xff" * 100)))
    assert np.array_equal(markov_profile(np.zeros((256, 256), np.float32)), np.zeros(33))
    with pytest.raises(ValueError, match="sum"):
        markov_profile(np.full((256, 256), .01, np.float32))
    with pytest.raises(ValueError, match="float32"):
        markov_profile(matrix.astype(np.float64))


def validation_rows():
    records = []
    for cohort in ("cic", "source_raw"):
        for group in range(80):
            for row in range(88 if group == 0 else 1):
                records.append({"sample_id": f"{cohort}_{group}_{row}", "cohort": cohort,
                    "group_id": f"{cohort}_{group}", "Label": row % 2 if group == 0 else group % 2,
                    "split": "validation", "role": "original_role"})
    return pd.DataFrame(records)


def test_new_roles_preserve_whole_groups_and_original_partitions_with_diverse_cohorts():
    frame = validation_rows()
    new = diverse_validation_roles(frame)
    assert frame.role.eq("original_role").all()
    assert new.drop(columns="role").equals(frame.drop(columns="role"))
    assert new.groupby("group_id").role.nunique().max() == 1
    assert new.groupby(["cohort", "role"]).group_id.nunique().min() == 20
    assert new.groupby(["cohort", "role"]).Label.nunique().min() == 2
    reordered = diverse_validation_roles(frame.iloc[::-1]).set_index("sample_id").role
    pd.testing.assert_series_equal(new.set_index("sample_id").role.sort_index(), reordered.sort_index())
    with pytest.raises(ValueError, match="Validation-only"):
        diverse_validation_roles(frame.assign(split="test"))
    with pytest.raises(ValueError, match="forty"):
        diverse_validation_roles(frame.loc[frame.group_id.str.endswith("_0")])


def test_stopping_weights_equalize_cohorts_and_groups_in_only_base_selection():
    frame = diverse_validation_roles(validation_rows()).query("role == 'base_selection'")
    weighted = frame.assign(weight=cohort_weights(frame, "cohort_group_class", fit_partition="base_selection"))
    assert np.allclose(weighted.groupby("cohort").weight.sum(), len(frame) / 2)
    for _, group in weighted.groupby("cohort"):
        mass = group.groupby("group_id").weight.sum()
        assert np.allclose(mass, mass.iloc[0])
    with pytest.raises(ValueError, match="mix"):
        cohort_weights(frame.assign(role="meta_fit"), "cohort_group_class", fit_partition="base_selection")


def weighted_loader(weights):
    return DataLoader(TensorDataset(torch.tensor([[0.], [4.]]), torch.zeros(2),
                                    torch.tensor(weights, dtype=torch.float32)), batch_size=1)


def test_weighted_validation_aggregates_global_cohort_mass_and_does_not_update_model():
    model = torch.nn.Linear(1, 1, bias=False)
    with torch.no_grad():
        model.weight.fill_(1)
    initial = model.weight.detach().clone()
    expected = float((100 * np.log(2) + np.logaddexp(0, 4)) / 101)
    for weights in ([100., 1.], [1000., 10.]):
        result = _mean_loss(model, weighted_loader(weights), torch.nn.BCEWithLogitsLoss(),
                            torch.device("cpu"), weighted_validation=True)
        assert result == pytest.approx(expected, abs=1e-7)
    assert torch.equal(model.weight, initial)
    assert model.weight.grad is None
    with pytest.raises(ValueError, match="contract"):
        _mean_loss(model, weighted_loader([1., 1.]), torch.nn.BCEWithLogitsLoss(), torch.device("cpu"))
    for weights in ([0., 1.], [-1., 1.], [np.nan, 1.]):
        with pytest.raises(ValueError, match="weights"):
            _mean_loss(model, weighted_loader(weights), torch.nn.BCEWithLogitsLoss(),
                        torch.device("cpu"), weighted_validation=True)


@pytest.mark.parametrize("name", ["xgboost", "lightgbm", "catboost", "random_forest"])
def test_byte_augmented_tree_models_keep_complete_security_and_train_only_null_handling(tmp_path, name):
    cfg = yaml.safe_load((Path(__file__).parents[1] / "configs/raw_tri_modal_v3.yaml").read_text())
    cfg["cpu_threads"] = 1
    cfg["models"]["xgboost"].update(n_estimators=3, max_depth=2)
    cfg["models"]["lightgbm"].update(n_estimators=3, num_leaves=4, min_child_samples=2)
    cfg["models"]["catboost"].update(iterations=3, depth=2)
    cfg["models"]["random_forest"].update(n_estimators=3, max_depth=2)
    order = (*V3_FEATURES, *MARKOV_PROFILE_FEATURES)
    frame = pd.DataFrame({key: np.arange(30, dtype=float) for key in order})
    frame.loc[0, "title length"] = np.nan
    labels = np.arange(30) % 2
    model, info = fit_v3_fold(name, cfg, frame.iloc[:20], labels[:20], frame.iloc[20:], labels[20:],
        tmp_path / name, feature_order=order, impute_metadata=True, train_sample_weight=np.ones(20))
    assert np.isfinite(model.predict_proba(frame)).all()
    assert info["raw_feature_order"] == list(order)
    assert np.isnan(frame.loc[0, "title length"])
    with pytest.raises(ValueError, match="complete fixed"):
        _features(frame.iloc[:, :-1], order[:-1], allow_missing=True)
    missing = frame.copy()
    missing.loc[0, "JS"] = np.nan
    with pytest.raises(ValueError, match="imputed|NaN"):
        model.predict_proba(missing)


def test_bounded_two_source_profile_reader_never_opens_test_matrices(tmp_path):
    def npy(data):
        stream = io.BytesIO()
        np.save(stream, byte_transition_matrix(data), allow_pickle=False)
        return stream.getvalue()
    input_root = tmp_path / "input"
    input_root.mkdir()
    old = npy(b"AB" * 10)
    fresh = npy(b"A\xff" * 10)
    source_metadata = json.dumps({"numeric_fixture": True}).encode()
    original = input_root / "original.zip"
    with zipfile.ZipFile(original, "w") as handle:
        handle.writestr("bundle_metadata.json", source_metadata)
        handle.writestr("markov_cache/sample_000099.npy", old)
        handle.writestr("markov_cache/sample_999999.npy", b"invalid Test sentinel")
    metadata = {"source_bundle_metadata_sha256": hashlib.sha256(source_metadata).hexdigest(),
                "source_bundle_archive_sha256": hashlib.sha256(original.read_bytes()).hexdigest()}
    delta = input_root / "delta.zip"
    with zipfile.ZipFile(delta, "w") as handle:
        handle.writestr("bundle_metadata.json", json.dumps(metadata))
        handle.writestr("markov_cache/sample_000002.npy", fresh)
        handle.writestr("markov_cache/sample_999999.npy", b"invalid Test sentinel")
    bundle = tmp_path / "tables"
    bundle.mkdir()
    (bundle / "bundle_metadata.json").write_text(json.dumps(metadata))
    pd.DataFrame([{"sample_id": "sample_000001", "legacy_sample_id": "sample_000099"}]).to_csv(bundle / "source_matrix_reuse.csv", index=False)
    rows = pd.DataFrame([{"sample_id": f"sample_{i:06}", "split": split,
        "cache_relative_path": f"markov_cache/sample_{i:06}.npy", "npy_sha256": hashlib.sha256(data).hexdigest()}
        for i, split, data in [(1, "train", old), (2, "validation", fresh)]])
    result = load_development_profiles(input_root, bundle, rows, metadata, workers=1)
    assert result.shape == (2, 33)
    assert np.array_equal(result.iloc[0], markov_profile(byte_transition_matrix(b"AB" * 10)))
    with pytest.raises(ValueError, match="Train/Validation"):
        load_development_profiles(input_root, bundle, rows.assign(split="test"), metadata, workers=1)
    with pytest.raises(ValueError, match="checksum"):
        load_development_profiles(input_root, bundle, rows.assign(npy_sha256="0" * 64), metadata, workers=1)


def test_sealed_profile_training_uses_existing_inputs_and_contains_no_sample_data(tmp_path):
    folder = tmp_path / "src/malpdf"
    folder.mkdir(parents=True)
    (folder / "__init__.py").write_text("# synthetic fixture\n")
    configuration = {"study_mode": "markov_profiles", "additional_existing_datasets": ["owner/existing-numeric"]}
    script = sealed_training_script(tmp_path, configuration, "a" * 40)
    compile(script, "train.py", "exec")
    assert "sample_000" not in script
    assert "input_root=Path('/kaggle/input')" in script

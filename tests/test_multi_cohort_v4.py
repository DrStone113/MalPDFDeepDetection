"""Synthetic safeguards for group splitting, GPU fold fitting and dual-Test locks."""
import hashlib
import json
import io
import zipfile
from types import SimpleNamespace
import numpy as np
import pandas as pd
import pytest
import torch

from malpdf.data.multi_cohort import exact_group_subset, split_cic_groups, validate_combined_groups
from malpdf.data.kaggle_notebook import attach_existing_numeric_bundle, writable_numeric_bundle
from malpdf.experiments.multi_cohort_gpu import fold_preprocessing, train_v4_gpu
from malpdf.experiments.multi_cohort_v4 import align_gpu_scores, claim_v4_tests
from malpdf.experiments import multi_cohort_gpu as gpu


def cic_fixture():
    frame = pd.DataFrame({"sample_id": [f"benign_fixture_{i:04}" for i in range(1452)],
        "Label": np.r_[np.ones(800, int), np.zeros(652, int)], "JS": np.arange(1452, dtype=float)})

    frame.loc[np.r_[np.arange(110), np.arange(800, 899)], "JS"] = -1
    return frame


def test_exact_stratification_keeps_large_mixed_label_group_intact_and_is_order_independent():
    frame = cic_fixture()
    result = split_cic_groups(frame, ["JS"])
    again = split_cic_groups(frame.sample(frac=1, random_state=8), ["JS"])
    pd.testing.assert_frame_equal(result, again)
    assert result.split.value_counts().to_dict() == {"train": 870, "validation": 291, "test": 291}
    assert result.groupby("split").Label.sum().to_dict() == {"train": 480, "validation": 160, "test": 160}
    assert result.groupby("duplicate_group_id").split.nunique().max() == 1
    component = frame.loc[frame.JS.eq(-1), "sample_id"]
    assert result.set_index("sample_id").loc[component].split.nunique() == 1


def test_impossible_group_targets_fail_without_row_split_fallback():
    groups = pd.DataFrame({"benign": [2, 0], "malicious": [0, 2]}, index=["benign", "malicious"])
    with pytest.raises(ValueError, match="whole groups"):
        exact_group_subset(groups, 1, 1)
    with pytest.raises(ValueError, match="Bounded"):
        exact_group_subset(groups, 10_000, 10_000)


@pytest.mark.parametrize("mutation", ["labels", "duplicate"])
def test_cic_split_refuses_cohort_or_label_changes(mutation):
    frame = cic_fixture()
    if mutation == "labels": frame.loc[0, "Label"] = 0
    else: frame.loc[0, "sample_id"] = frame.loc[1, "sample_id"]
    with pytest.raises(ValueError, match="established"):
        split_cic_groups(frame, ["JS"])


@pytest.mark.parametrize("leak", ["vector", "pdf_sha256", "related_group_id"])
def test_combined_overlap_check_rejects_each_leak_channel(leak):
    frame = pd.DataFrame({"sample_id": ["fixture0", "fixture1"], "Label": [0, 1], "JS": [1., 2.]})
    manifest = frame[["sample_id", "Label"]].assign(split=["train", "test"], duplicate_group_id=["g0", "g1"])
    sources = pd.DataFrame({"sample_id": frame.sample_id, "pdf_sha256": ["a", "b"], "related_group_id": ["r0", "r1"]}).set_index("sample_id")
    if leak == "vector": frame["JS"] = 1
    else: sources[leak] = "same"
    with pytest.raises(ValueError, match="leakage"):
        validate_combined_groups(frame, manifest, sources, ["JS"])


def test_ft_preprocessing_uses_train_median_and_scale_only_and_keeps_missing_flag():
    train = np.array([[1., 10.], [2., 20.], [3., np.nan]])
    validation = np.array([[100., 90000.], [200., np.nan]])
    imputer, scaler, transform = fold_preprocessing(train, validation, ["JS", "title length"], ["title length"])
    assert imputer.statistics_[1] == 15
    assert scaler.mean_[1] == 15
    assert transform(validation).shape == (2, 3)
    assert np.isnan(train[2, 1])
    bad = validation.copy(); bad[0, 0] = np.nan
    with pytest.raises(ValueError, match="Security"):
        transform(bad)


def test_gpu_probabilities_join_by_id_and_refuse_wrong_partition_or_duplicates():
    portable = pd.DataFrame({"sample_id": ["sample_000001", "sample_000002", "sample_000003"], "split": ["validation", "validation", "test"]})
    mapping = pd.DataFrame({"export_sample_id": portable.sample_id, "sample_id": ["fixture1", "fixture2", "fixture3"]})
    predictions = pd.DataFrame({"sample_id": ["sample_000002", "sample_000001"], "p_malicious": [.8, .2]})
    assert align_gpu_scores(portable, mapping, "validation", predictions).to_dict() == {"fixture1": .2, "fixture2": .8}
    with pytest.raises(ValueError, match="identities"):
        align_gpu_scores(portable, mapping, "test", predictions)
    predictions.loc[0, "p_malicious"] = np.nan
    with pytest.raises(ValueError, match="finite"):
        align_gpu_scores(portable, mapping, "validation", predictions)


def test_dual_test_claim_is_exclusive_and_written_before_scoring(tmp_path):
    run = SimpleNamespace(report=tmp_path / "reports/run_fixture")
    run.report.mkdir(parents=True)
    claim_v4_tests(tmp_path, run, "a" * 64, "b" * 64)
    assert json.loads((run.report / "test_evaluation_started.json").read_text())["cic_B"] == 1
    with pytest.raises(FileExistsError):
        claim_v4_tests(tmp_path, run, "a" * 64, "c" * 64)


@pytest.fixture
def ft_numeric_bundle(tmp_path):
    root = tmp_path / "bundle"; root.mkdir()
    rows, roles = [], []
    for partition, count in (("train", 20), ("validation", 8), ("test", 4)):
        for i in range(count):
            sid = f"sample_{len(rows) + 1:06}"
            rows.append({"sample_id": sid, "Label": i % 2, "split": partition, "group_id": f"{partition}_{i // 2}",
                "cache_relative_path": f"markov_cache/{sid}.npy", "npy_sha256": "a" * 64, "parser_failed": False})
            if partition == "validation": roles.append({"sample_id": sid, "role": ["base_selection", "meta_fit", "calibration_fit", "threshold_selection"][i // 2]})
    frame = pd.DataFrame(rows)
    frame.to_csv(root / "manifest.csv", index=False)
    pd.DataFrame(roles).to_csv(root / "validation_roles.csv", index=False)
    folds = frame.loc[frame.split.eq("train"), ["sample_id"]].copy().assign(fold=np.repeat(np.arange(1, 6), 4))
    folds.to_csv(root / "train_folds.csv", index=False)
    values = frame[["sample_id"]].assign(JS=np.arange(len(frame), dtype=float), **{"title length": np.arange(len(frame), dtype=float)})
    values.loc[values.index % 3 == 0, "title length"] = np.nan
    values.to_csv(root / "tabular_features.csv", index=False)
    cfg = {"feature_order": ["JS", "title length"], "metadata_features": ["title length"],
        "tabular": {"models": {"ft_transformer": {}}, "training": {"batch_size": 8, "max_epochs": 1, "patience": 1,
            "learning_rate": .001, "weight_decay": 0., "min_delta": 0.}}, "vision": {"batch_size": 8, "max_epochs": 1}}
    (root / "v4_gpu_configuration.json").write_text(json.dumps(cfg))
    metadata = {"seed": 42, "shape": [1,256,256], "raw_pdfs_included": False, "code_commit": "a" * 40,
        "partition_rows": frame.split.value_counts().to_dict(),
        "file_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir() if p.is_file()}}
    (root / "bundle_metadata.json").write_text(json.dumps(metadata))
    return root


def test_gpu_training_refuses_cpu_before_creating_run(ft_numeric_bundle, tmp_path, monkeypatch):
    monkeypatch.setattr(torch.cuda, "is_available", lambda: False)
    with pytest.raises(RuntimeError, match="cloud GPU"):
        train_v4_gpu(ft_numeric_bundle, tmp_path / "outputs")
    assert not (tmp_path / "outputs").exists()


def test_five_ft_folds_cpu_smoke_preserves_train_only_statistics_and_exports_no_test_metrics(ft_numeric_bundle, tmp_path, monkeypatch):
    monkeypatch.setattr(torch.cuda, "is_available", lambda: False)
    monkeypatch.setattr(gpu, "build_tabular_model", lambda name, config: torch.nn.Linear(3, 1))
    def fake_vision(bundle, outputs, cfg, **kwargs):
        out = outputs / "run_benign_fixture"; out.mkdir(parents=True)
        return out
    monkeypatch.setattr(gpu, "train_kaggle_vision", fake_vision)
    directory = train_v4_gpu(ft_numeric_bundle, tmp_path / "outputs", allow_cpu_smoke=True)
    state = json.loads((directory / "run_summary.json").read_text())
    assert state["status"] == "completed" and len(state["ft_folds"]) == 5
    assert state["test_metrics_computed"] is False
    assert all(info["fit_rows"] == 16 and info["base_selection_rows"] == 2 for info in state["ft_folds"])
    assert pd.read_csv(directory / "ft_probs_test.csv").shape == (4, 2)
    assert json.loads((directory / "ft_selection_lock.json").read_text())["selected_role"] == "validation_base_selection"
    for file in directory.glob("ft_transformer/*/scaler.json"):
        assert json.loads(file.read_text())["mean"][0] < 20
    inventory = json.loads((directory / "output_checksums.json").read_text())
    assert "ft_transformer/fold_5/model.pt" in inventory and "ft_selection_lock.json" in inventory
    environment = json.loads((directory / "environment_metadata.json").read_text())
    assert environment["effective_precision"] == "cpu_fp32_smoke" and "torch" in environment["packages"]


def test_expanded_read_only_delta_is_copied_before_adding_source_matrices(tmp_path, monkeypatch):
    mounted = tmp_path / "mounted"; mounted.mkdir()
    matrix = io.BytesIO(); np.save(matrix, np.zeros((256, 256), np.float32), allow_pickle=False)
    content = matrix.getvalue()
    (mounted / "markov_cache").mkdir()
    path = "markov_cache/sample_000002.npy"
    (mounted / path).write_bytes(content)
    frame = pd.DataFrame({"sample_id": ["sample_000001", "sample_000002"],
        "cache_relative_path": ["markov_cache/sample_000001.npy", path],
        "npy_sha256": ["a" * 64, hashlib.sha256(content).hexdigest()]})
    frame.to_csv(mounted / "manifest.csv", index=False)
    metadata = {"file_sha256": {"manifest.csv": hashlib.sha256((mounted / "manifest.csv").read_bytes()).hexdigest()}}
    (mounted / "bundle_metadata.json").write_text(json.dumps(metadata))
    for file in mounted.rglob("*"):
        if file.is_file(): file.chmod(0o444)

    import tempfile
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    copied = writable_numeric_bundle(mounted, metadata)
    assert copied != mounted and (copied / path).read_bytes() == content
    with (copied / "markov_cache/sample_000001.npy").open("xb") as output:
        output.write(b"synthetic restored matrix")
    assert not (mounted / "markov_cache/sample_000001.npy").exists()
    with pytest.raises(ValueError, match="manifest changed"):
        writable_numeric_bundle(mounted, {"file_sha256": {"manifest.csv": "f" * 64}})


@pytest.mark.parametrize("expanded", [False, True])
def test_numeric_delta_restores_pinned_source_matrix_and_refuses_overwrite_or_corruption(tmp_path, expanded):
    source = tmp_path / "input"; source.mkdir()
    bundle = tmp_path / "delta"; bundle.mkdir()
    buffer = io.BytesIO(); np.save(buffer, np.zeros((256,256),np.float32), allow_pickle=False)
    matrix = buffer.getvalue(); matrix_sha = hashlib.sha256(matrix).hexdigest()
    legacy_metadata = b'{"benign_numeric_fixture":true}'
    md_sha = hashlib.sha256(legacy_metadata).hexdigest()
    if expanded:
        legacy = source / "old"; (legacy / "markov_cache").mkdir(parents=True)
        (legacy / "bundle_metadata.json").write_bytes(legacy_metadata)
        (legacy / "markov_cache/sample_000001.npy").write_bytes(matrix)
        archive_sha = "a" * 64
    else:
        path = source / "old.zip"
        with zipfile.ZipFile(path,"x") as z:
            z.writestr("bundle_metadata.json",legacy_metadata)
            z.writestr("markov_cache/sample_000001.npy",matrix)
        archive_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    pd.DataFrame([{"sample_id":"sample_000999","cache_relative_path":"markov_cache/sample_000999.npy","npy_sha256":matrix_sha}]).to_csv(bundle/"manifest.csv",index=False)
    pd.DataFrame([{"sample_id":"sample_000999","legacy_sample_id":"sample_000001"}]).to_csv(bundle/"source_matrix_reuse.csv",index=False)
    metadata={"source_bundle_metadata_sha256":md_sha,"source_bundle_archive_sha256":archive_sha,
        "file_sha256":{n:hashlib.sha256((bundle/n).read_bytes()).hexdigest() for n in ("manifest.csv","source_matrix_reuse.csv")}}
    assert attach_existing_numeric_bundle(bundle,source,metadata)==1
    target=bundle/"markov_cache/sample_000999.npy"
    assert target.read_bytes()==matrix
    with pytest.raises(FileExistsError): attach_existing_numeric_bundle(bundle,source,metadata)
    target.unlink()
    frame=pd.read_csv(bundle/"manifest.csv"); frame["npy_sha256"]="b"*64;frame.to_csv(bundle/"manifest.csv",index=False)
    metadata["file_sha256"]["manifest.csv"]=hashlib.sha256((bundle/"manifest.csv").read_bytes()).hexdigest()
    with pytest.raises(ValueError,match="matrix checksum"):
        attach_existing_numeric_bundle(bundle,source,metadata)

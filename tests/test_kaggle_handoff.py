"""Offline numeric bundle, identity and GPU-control tests with benign matrices."""

import hashlib
import io
import json
from pathlib import Path
import zipfile

import numpy as np
import pandas as pd
import pytest
import torch

from malpdf.data.kaggle_export import anonymize_rows
from malpdf.data.kaggle_notebook import find_kaggle_bundle, render_kaggle_notebook, prepare_kaggle_code
from malpdf.data.markov_arrays import load_markov_npy
from malpdf.experiments import kaggle_vision_runner as runner


def digest(content): return hashlib.sha256(content).hexdigest()


@pytest.fixture
def numeric_bundle(tmp_path):
    root = tmp_path / "bundle"
    (root / "markov_cache").mkdir(parents=True)
    rows, roles = [], []
    role_names = ("base_selection", "meta_fit", "calibration_fit", "threshold_selection")
    for split, count in (("train", 8), ("validation", 16), ("test", 8), ("unlabeled", 4)):
        for i in range(count):
            number = len(rows) + 1
            sid = f"sample_{number:06}"
            matrix = np.zeros((256, 256), dtype=np.float32)
            matrix[0, 0] = i % 2
            matrix[1, 0] = number / 40
            matrix[1, 1] = 1 - matrix[1, 0]
            buffer = io.BytesIO()
            np.save(buffer, matrix, allow_pickle=False)
            content = buffer.getvalue()
            path = f"markov_cache/{sid}.npy"
            (root / path).write_bytes(content)
            rows.append({"sample_id": sid, "Label": i % 2 if split != "unlabeled" else None, "split": split,
                         "group_id": f"{split}_{i // 2}", "cache_relative_path": path, "npy_sha256": digest(content), "parser_failed": False})
            if split == "validation": roles.append({"sample_id": sid, "role": role_names[i // 4]})
    frame = pd.DataFrame(rows)
    frame.to_csv(root / "manifest.csv", index=False)
    pd.DataFrame(roles).to_csv(root / "validation_roles.csv", index=False)
    config = {"batch_size": 8, "max_epochs": 1, "patience": 1, "learning_rate": 0.001, "weight_decay": 0.0, "min_delta": 0.0}
    (root / "vision_configuration.json").write_text(json.dumps(config))
    metadata = {"seed": 42, "shape": [1, 256, 256], "raw_pdfs_included": False, "code_commit": "a" * 40,
                "partition_rows": frame.split.value_counts().to_dict(),
                "file_sha256": {name: digest((root / name).read_bytes()) for name in ("manifest.csv", "validation_roles.csv", "vision_configuration.json")}}
    (root / "bundle_metadata.json").write_text(json.dumps(metadata))
    return root, frame, config


def test_numeric_dataset_checks_integrity_without_pdf_reading(numeric_bundle):
    root, frame, _ = numeric_bundle
    validated, roles, metadata = runner.load_bundle(root)
    assert len(validated) == 36 and len(roles) == 16
    dataset = runner.BundleDataset(root, frame.loc[frame.split.eq("unlabeled")], labels=False)
    assert dataset[0].shape == (1, 256, 256)
    with pytest.raises(ValueError, match="supervised"):
        runner.BundleDataset(root, frame.loc[frame.split.eq("unlabeled")], labels=True)
    path = root / frame.iloc[0].cache_relative_path
    path.write_bytes(b"corrupted")
    with pytest.raises(ValueError, match="changed"):
        runner.BundleDataset(root, frame.iloc[:1], labels=False)[0]
    with pytest.raises(ValueError, match="Unsafe"):
        runner._bytes(root, "../outside.npy", 1024)


def test_portable_loader_rejects_manifest_or_role_tampering(numeric_bundle):
    root, _, _ = numeric_bundle
    with (root / "manifest.csv").open("a") as f: f.write("tampering\n")
    with pytest.raises(ValueError, match="checksum"):
        runner.load_bundle(root)


def test_gpu_training_exports_test_probabilities_once_without_test_loss_or_metrics(numeric_bundle, tmp_path, monkeypatch):
    root, frame, config = numeric_bundle
    config.update(preload_ram=True, mixed_precision=True, num_workers=1, prefetch_factor=1, max_ram_cache_gib=1)
    monkeypatch.setattr(runner, 'available_ram_bytes', lambda: 4 * 1024**3)
    monkeypatch.setattr(torch.cuda, "is_available", lambda: False)
    with pytest.raises(RuntimeError, match="GPU unavailable"):
        runner.train_kaggle_vision(root, tmp_path / "no_gpu", config)
    observed = []
    original = runner.BundleDataset
    class SpyDataset(original):
        def __init__(self, bundle, rows, *, labels, **kwargs):
            observed.append((set(rows.split), labels))
            if rows.split.eq("test").all():
                assert list((tmp_path / "outputs").rglob("vision_selection_lock.json"))
            super().__init__(bundle, rows, labels=labels, **kwargs)
    class Tiny(torch.nn.Module):
        def __init__(self):
            super().__init__()
            self.scale = torch.nn.Parameter(torch.tensor(1.0))
        def forward(self, x): return self.scale * (x[:, 0, 0, 0] - 0.5)
    monkeypatch.setattr(runner, "BundleDataset", SpyDataset)
    monkeypatch.setattr(runner, "VisionResNet18", Tiny)
    output = runner.train_kaggle_vision(root, tmp_path / "outputs", config, allow_cpu_smoke=True)
    state = json.loads((output / "run_summary.json").read_text())
    assert state["status"] == "completed" and state["test_prediction_passes"] == 1
    assert state['data_loading']['matrix_reads'] == len(frame)
    assert state['data_loading']['persistent_workers'] is True
    assert state['mixed_precision_effective'] is False  # Explicit CPU smoke only.
    history = pd.read_csv(output / 'training_history.csv')
    assert (history.epoch_seconds > 0).all() and (history.train_data_wait_seconds >= 0).all()
    assert state["test_metrics_computed"] is False
    assert all(labels is False for partitions, labels in observed if "test" in partitions or "unlabeled" in partitions)
    assert sum(partitions == {"test"} for partitions, _ in observed) == 1
    assert sum(partitions == {"validation"} and labels for partitions, labels in observed) == 1
    for name, count in (("vision_probs_val.csv", 16), ("vision_probs_test.csv", 8), ("vision_probs_unlabeled.csv", 4)):
        predictions = pd.read_csv(output / name)
        assert len(predictions) == count and set(predictions) == {"sample_id", "p_malicious"}
        assert predictions.p_malicious.between(0, 1).all()
    assert (output / "vision_resnet_best.pt").is_file()
    assert json.loads((output / "vision_selection_lock.json").read_text())["selection_rows"] == 4


def test_opaque_ids_preserve_locked_membership_without_exporting_original_hashes():
    original = pd.DataFrame({"sample_id": ["public_pdf:" + f"{i:064x}" for i in range(5)],
                             "Label": [0, 1, 0, 1, np.nan], "parser_failed": [False] * 5})
    saved = pd.DataFrame({"sample_id": original.sample_id[:4], "Label": [0, 1, 0, 1],
                          "split": ["train", "validation", "test", "train"], "duplicate_group_id": ["g0", "g1", "g2", "g3"]})
    sources = pd.DataFrame({"sample_id": original.sample_id, "pdf_sha256": [f"{i:064x}" for i in range(5)], "related_group_id": [f"r{i}" for i in range(5)]}).set_index("sample_id")
    roles = pd.DataFrame({"sample_id": [original.sample_id[1]], "role": ["base_selection"]})
    portable, private, exported_roles = anonymize_rows(original.iloc[:4], saved, sources, original.iloc[4:], roles)
    restored = portable.assign(sample_id=portable.sample_id.map(private.set_index("export_sample_id").sample_id))
    assert restored.loc[restored.split.ne("unlabeled"), "split"].tolist() == saved.split.tolist()
    assert portable.loc[portable.split.eq("unlabeled"), "Label"].isna().all()
    assert "public_pdf:" not in portable.to_csv(index=False)
    assert exported_roles.sample_id.iloc[0] == "sample_000002"


def notebook_bootstrap(input_root, checksum, extraction_root):
    template = Path(__file__).resolve().parents[1] / "notebooks/kaggle_vision_resnet18.ipynb"
    notebook = render_kaggle_notebook(template, checksum)
    source = next("".join(c["source"]) for c in notebook["cells"] if c["cell_type"] == "code")
    source = source.replace("Path('/kaggle/input')", f"Path({str(input_root)!r})")
    source = source.replace("Path('/tmp')", f"Path({str(extraction_root)!r})")
    # Exercise discovery, extraction and all checks without importing fixture code.
    source = source.split("sys.dont_write_bytecode = True", 1)[0]
    namespace = {}
    exec(compile(source, "offline_notebook_fixture", "exec"), namespace)
    return namespace


def test_notebook_rejects_zip_traversal_before_loading_code(tmp_path):
    archive = tmp_path / "malpdf-markov-cache.zip"
    content = b'{"benign_fixture":true}'
    with zipfile.ZipFile(archive, "x") as out:
        out.writestr("bundle_metadata.json", content)
        out.writestr("../outside.npy", b"benign invalid fixture")
    with pytest.raises(ValueError, match="Unsafe or unexpected"):
        notebook_bootstrap(tmp_path, digest(content), tmp_path)
    assert not (tmp_path / "outside.npy").exists()


def test_discovery_finds_nested_expanded_bundle_without_fixed_dataset_slug(numeric_bundle):
    root, _, _ = numeric_bundle
    checksum = digest((root / "bundle_metadata.json").read_bytes())
    selected, archive = find_kaggle_bundle(root.parent, checksum)
    assert selected == root and archive is None


def test_discovery_accepts_renamed_zip_and_ignores_other_attached_exports(tmp_path):
    content = b'{"benign_fixture":true}'
    nested = tmp_path / "datasets" / "researcher" / "different-slug" / "2"
    nested.mkdir(parents=True)
    archive = nested / "numeric-upload-renamed.ZIP"
    with zipfile.ZipFile(archive, "x") as out: out.writestr("bundle_metadata.json", content)
    with zipfile.ZipFile(tmp_path / "other-dataset.zip", "x") as out:
        out.writestr("bundle_metadata.json", b'{"other_export":true}')
    (tmp_path / "not-a-zip.zip").write_bytes(b"benign invalid archive")
    assert find_kaggle_bundle(tmp_path, digest(content)) == (None, archive)


@pytest.mark.parametrize("mounted", [False, True])
def test_discovery_explains_missing_input_or_wrong_version(tmp_path, mounted):
    root = tmp_path if mounted else tmp_path / "unattached-slug"
    if mounted: (root / "bundle_metadata.json").write_text('{}')
    with pytest.raises(ValueError, match="Add Input") as caught:
        find_kaggle_bundle(root, "a" * 64)
    assert str(root) in str(caught.value)


def test_discovery_refuses_ambiguous_matching_bundles(tmp_path):
    content = b'{"benign_fixture":true}'
    for name in ("first", "second"):
        folder = tmp_path / name
        folder.mkdir()
        (folder / "bundle_metadata.json").write_bytes(content)
    with pytest.raises(ValueError, match="Ambiguous"):
        find_kaggle_bundle(tmp_path, digest(content))
    assert find_kaggle_bundle(tmp_path / "second", digest(content)) == (tmp_path / "second", None)


@pytest.mark.parametrize("archived", [False, True])
def test_bootstrap_keeps_checksum_validation_for_both_mount_formats(numeric_bundle, tmp_path, archived):
    root, _, _ = numeric_bundle
    content = (root / "bundle_metadata.json").read_bytes()
    inputs = root
    if archived:
        inputs = tmp_path / "attached" / "datasets" / "researcher" / "renamed"
        inputs.mkdir(parents=True)
        with zipfile.ZipFile(inputs / "renamed.zip", "x", compression=zipfile.ZIP_DEFLATED) as out:
            for path in root.rglob('*'):
                if path.is_file(): out.write(path, path.relative_to(root))
    result = notebook_bootstrap(inputs, digest(content), tmp_path)
    assert result['metadata']['partition_rows']['test'] == 8
    assert (result['BUNDLE_ROOT'] / "manifest.csv").read_bytes() == (root / "manifest.csv").read_bytes()
    if not archived:
        (root / "manifest.csv").write_bytes(b"changed fixture")
        with pytest.raises(ValueError, match="checksum mismatch"):
            notebook_bootstrap(inputs, digest(content), tmp_path)


def test_discovery_prefers_expanded_copy_and_rejects_symlink_metadata(numeric_bundle):
    root, _, _ = numeric_bundle
    content = (root / "bundle_metadata.json").read_bytes()
    with zipfile.ZipFile(root / "original.zip", "x") as out: out.writestr("bundle_metadata.json", content)
    assert find_kaggle_bundle(root, digest(content)) == (root, None)
    candidate = root.parent / "symlink-candidate"
    candidate.mkdir()
    (candidate / "bundle_metadata.json").symlink_to(root / "bundle_metadata.json")
    with pytest.raises(ValueError, match="Unsafe"):
        find_kaggle_bundle(candidate, digest(content))


def test_ram_cache_reads_each_matrix_once_without_changing_probabilities(numeric_bundle, monkeypatch):
    root, frame, _ = numeric_bundle
    monkeypatch.setattr(runner, 'available_ram_bytes', lambda: 4 * 1024**3)
    cache = runner.RamMatrixCache(root, frame, max_bytes=1024**3, reserve_bytes=0)
    expected = load_markov_npy((root / frame.iloc[0].cache_relative_path).read_bytes())
    assert np.array_equal(cache.tensor[0, 0].numpy(), expected)
    def no_disk(*args, **kwargs): raise AssertionError('RAM dataset must not reread disk')
    monkeypatch.setattr(runner, '_bytes', no_disk)
    dataset = runner.BundleDataset(root, frame.loc[frame.split.eq('train')], labels=True, cache=cache)
    loader = torch.utils.data.DataLoader(dataset, batch_size=4, num_workers=1,
                                        persistent_workers=True, multiprocessing_context='fork')
    for epoch in range(2):
        assert sum(len(batch[0]) for batch in loader) == 8
    assert cache.rows_read == len(frame)


def test_ram_budget_and_checksum_fail_closed(numeric_bundle, monkeypatch):
    root, frame, _ = numeric_bundle
    monkeypatch.setattr(runner, 'available_ram_bytes', lambda: 1)
    with pytest.raises(ValueError, match='RAM budget'):
        runner.RamMatrixCache(root, frame, max_bytes=1024**3, reserve_bytes=0)
    monkeypatch.setattr(runner, 'available_ram_bytes', lambda: 4 * 1024**3)
    (root / frame.iloc[0].cache_relative_path).write_bytes(b'changed benign fixture')
    with pytest.raises(ValueError, match='changed after export'):
        runner.RamMatrixCache(root, frame, max_bytes=1024**3, reserve_bytes=0)


def test_failed_ram_preload_retains_evidence_and_never_predicts_test(numeric_bundle, tmp_path, monkeypatch):
    root, _, config = numeric_bundle
    config.update(preload_ram=True, max_ram_cache_gib=1)
    monkeypatch.setattr(torch.cuda, 'is_available', lambda: False)
    monkeypatch.setattr(runner, 'available_ram_bytes', lambda: 1)
    with pytest.raises(ValueError, match='RAM budget'):
        runner.train_kaggle_vision(root, tmp_path / 'outputs', config, allow_cpu_smoke=True)
    state = json.loads(next((tmp_path / 'outputs').rglob('run_summary.json')).read_text())
    assert state['status'] == 'failed' and state['test_prediction_passes'] == 0
    assert list((tmp_path / 'outputs').rglob('model_comparison.csv'))
    assert list((tmp_path / 'outputs').rglob('research_log.md'))


def test_pinned_overlay_preserves_original_code_and_rejects_tampering(tmp_path, monkeypatch):
    root = tmp_path / 'bundle'
    names = ('code/src/malpdf/experiments/kaggle_vision_runner.py', 'code/src/malpdf/deep_learning/training.py')
    original = b'version = 1\n'
    updated = 'version = 2\n'
    for name in names:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(original)
    metadata = {'file_sha256': {name: digest(original) for name in names}}
    overrides = {name: {'source': updated, 'sha256': digest(updated.encode())} for name in names}
    import tempfile
    def isolated_destination(**kwargs):
        target = tmp_path / 'overlay'
        target.mkdir()
        return str(target)
    monkeypatch.setattr(tempfile, 'mkdtemp', isolated_destination)
    code_root = prepare_kaggle_code(root, metadata, overrides)
    assert (code_root / 'malpdf/experiments/kaggle_vision_runner.py').read_text() == updated
    assert all((root / name).read_bytes() == original for name in names)
    overrides[names[0]]['source'] = 'tampered = True\n'
    with pytest.raises(ValueError, match='source checksum'):
        prepare_kaggle_code(root, metadata, overrides)

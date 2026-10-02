"""Vision tests are offline and use synthetic bytes, caches and split locks."""

from dataclasses import replace
import csv
import hashlib
import json
from pathlib import Path
import runpy

import numpy as np
import pandas as pd
import pytest
import torch
from torch import nn
from torch.utils.data import DataLoader, TensorDataset
import yaml

from malpdf.data.rit_pdfmal_split import create_rit_pdfmal_split
from malpdf.data.vision_dataset import MarkovCacheDataset, align_protocol_g_samples, load_vision_source_manifest, verify_vision_caches
from malpdf.experiments import protocol_g_benchmark as protocol_g
from malpdf.experiments import vision_runner as runner
from malpdf.models import vision_resnet
from malpdf.static.cache_manager import cache_markov_pdf
from malpdf.static.schema import RIT_FEATURES


@pytest.fixture(autouse=True)
def bounded_cpu_threads():
    previous = torch.get_num_threads()
    torch.set_num_threads(1)
    yield
    torch.set_num_threads(previous)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def vision_sources(tmp_path, monkeypatch):
    root = tmp_path
    data = root / "data/processed"
    data.mkdir(parents=True)
    frame = pd.DataFrame([{**{column: index + offset * 13 for offset, column in enumerate(RIT_FEATURES)}, "Label": index // 5} for index in range(10)])
    dataset = data / "synthetic.csv"
    frame.to_csv(dataset, index=False)
    split, summary = create_rit_pdfmal_split(frame, seed=42)
    split_path = data / "rit-pdfmal-2026_split_manifest.csv"
    split.to_csv(split_path, index=False)
    monkeypatch.setattr(protocol_g, "VERIFIED_DATASET_SHA256", sha(dataset))
    expected = {name: {"rows": values["row_count"], "groups": values["unique_group_count"], "label_0": values["benign"]["count"], "label_1": values["malicious"]["count"]} for name, values in summary["split_statistics"].items()}
    monkeypatch.setattr(protocol_g, "EXPECTED_G_SPLIT", {**expected, "total_rows": len(frame), "total_groups": split.duplicate_group_id.nunique()})
    reports = root / "reports"
    reports.mkdir()
    (reports / "rit-pdfmal-2026_split_report.json").write_text(json.dumps({"seed": 42, "dataset": {"sha256": sha(dataset)}}))
    (reports / "research_log.md").write_text("# Research log\nHistorical entries stay intact.\n")
    raw = root / "data/raw"
    raw.mkdir()
    cache = data / "markov_cache"
    rows = []
    for index, row in split.iterrows():
        source = raw / f"synthetic_{index}.pdf"
        source.write_bytes(f"%PDF-1.4\n% harmless synthetic fixture {index}\n%%EOF\n".encode())
        digest = sha(source)
        cache_markov_pdf(source, digest, raw_boundary=raw, cache_directory=cache)
        rows.append({"sample_id": row.sample_id, "Label": str(row.Label), "pdf_relative_path": str(source.relative_to(root)), "pdf_sha256": digest})
    source_path = data / "source_pdf_manifest.csv"
    with source_path.open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    configuration = yaml.safe_load((Path(__file__).resolve().parents[1] / "configs/vision_resnet18.yaml").read_text())
    configuration["paths"].update({"source_manifest": str(source_path.relative_to(root)), "source_manifest_sha256": sha(source_path), "dataset": str(dataset.relative_to(root)), "dataset_sha256": sha(dataset), "split_manifest": str(split_path.relative_to(root)), "split_manifest_sha256": sha(split_path)})
    configuration["training"].update({"max_epochs": 1, "patience": 1, "batch_size": 2})
    configuration["runtime"].update({"cpu_threads": 1, "dry_run_max_samples": 2})
    return root, configuration, split, source_path, cache


def test_resnet_stem_logit_and_sigmoid_without_weight_download(monkeypatch):
    actual_builder = vision_resnet.resnet18
    weights_used = []
    def builder(*, weights):
        weights_used.append(weights)
        return actual_builder(weights=weights)
    monkeypatch.setattr(vision_resnet, "resnet18", builder)
    model = vision_resnet.VisionResNet18().eval()
    stem = model.backbone.conv1
    assert (stem.in_channels, stem.out_channels, stem.kernel_size, stem.stride, stem.padding) == (1, 64, (7, 7), (2, 2), (3, 3))
    assert stem.bias is None and model.backbone.fc.out_features == 1
    assert weights_used == [None]
    inputs = torch.eye(256, dtype=torch.float32).reshape(1, 1, 256, 256)
    with torch.no_grad():
        logits = model(inputs)
        probabilities = model.predict_proba(inputs)
    assert logits.shape == probabilities.shape == (1, 1)
    assert torch.allclose(probabilities, torch.sigmoid(logits))
    assert torch.isfinite(probabilities).all()


def test_real_resnet_supports_a_finite_binary_gradient_step():
    torch.manual_seed(42)
    model = vision_resnet.VisionResNet18()
    features = torch.eye(256, dtype=torch.float32).reshape(1, 1, 256, 256).repeat(2, 1, 1, 1)
    optimizer = torch.optim.AdamW(model.parameters(), lr=0.001)
    before = model.backbone.fc.bias.detach().clone()
    loss = nn.functional.binary_cross_entropy_with_logits(model(features).reshape(-1), torch.ones(2))
    assert torch.isfinite(loss)
    loss.backward()
    assert torch.isfinite(model.backbone.fc.bias.grad).all()
    optimizer.step()
    assert not torch.equal(before, model.backbone.fc.bias)


@pytest.mark.parametrize("case", ["channels", "dimensions", "dtype", "nonfinite"])
def test_invalid_resnet_input_is_rejected(case):
    model = vision_resnet.VisionResNet18()
    features = torch.zeros((1, 1, 256, 256))
    if case == "channels":
        features = torch.zeros((1, 3, 256, 256))
    elif case == "dimensions":
        features = features[:, :, :128]
    elif case == "dtype":
        features = features.double()
    else:
        features[0, 0, 0, 0] = float("nan")
    with pytest.raises(ValueError):
        model(features)


def test_dataset_adds_one_channel_and_preserves_labels(vision_sources):
    root, config, split, source, cache = vision_sources
    samples = load_vision_source_manifest(root, source, config["paths"]["source_manifest_sha256"])
    samples = verify_vision_caches(samples, cache)
    dataset = MarkovCacheDataset(samples, cache)
    features, labels = next(iter(DataLoader(dataset, batch_size=2)))
    assert features.shape == (2, 1, 256, 256) and features.dtype == torch.float32
    assert labels.dtype == torch.float32 and labels.tolist() == [float(sample.label) for sample in samples[:2]]
    partitions, readiness = align_protocol_g_samples(samples, split)
    assert readiness["ready"] and sum(len(values) for values in partitions.values()) == 10


def test_dataset_detects_changed_cache_even_with_updated_sidecar(vision_sources):
    root, config, _, source, cache = vision_sources
    samples = verify_vision_caches(load_vision_source_manifest(root, source, config["paths"]["source_manifest_sha256"]), cache)
    dataset = MarkovCacheDataset(samples, cache)
    path = cache / (samples[0].pdf_sha256 + ".npy")
    np.save(path, np.eye(256, dtype=np.float32), allow_pickle=False)
    metadata_path = path.with_suffix(".json")
    metadata = json.loads(metadata_path.read_text())
    metadata["npy_sha256"] = sha(path)
    metadata_path.write_text(json.dumps(metadata))
    with pytest.raises(ValueError, match="changed after vision preflight"):
        dataset[0]


@pytest.mark.parametrize("case", ["label", "pdf_hash", "related_group", "feature_group"])
def test_alignment_rejects_labels_and_all_cross_partition_group_leakage(vision_sources, case):
    root, config, split, source, _ = vision_sources
    samples = load_vision_source_manifest(root, source, config["paths"]["source_manifest_sha256"])
    if case == "label":
        samples[0] = replace(samples[0], label=1 - samples[0].label)
    else:
        left = next(index for index, row in split.iterrows() if row.split == "train" and row.Label == 0)
        right = next(index for index, row in split.iterrows() if row.split == "test" and row.Label == 0)
        if case == "pdf_hash":
            samples[right] = replace(samples[right], pdf_sha256=samples[left].pdf_sha256)
        elif case == "related_group":
            samples[left] = replace(samples[left], related_group_id="shared_family")
            samples[right] = replace(samples[right], related_group_id="shared_family")
        else:
            split.loc[right, "duplicate_group_id"] = split.loc[left, "duplicate_group_id"]
    with pytest.raises(ValueError):
        align_protocol_g_samples(samples, split)


def test_partial_source_mapping_cannot_become_an_official_partition(vision_sources):
    root, config, split, source, _ = vision_sources
    samples = load_vision_source_manifest(root, source, config["paths"]["source_manifest_sha256"])
    partitions, readiness = align_protocol_g_samples(samples[:-1], split)
    assert partitions is None and not readiness["ready"]
    assert readiness["missing_source_ids"] == 1


class TinyVisionModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.network = nn.Sequential(nn.Conv2d(1, 2, kernel_size=1), nn.AdaptiveAvgPool2d(1), nn.Flatten(), nn.Linear(2, 1))
    def forward(self, features):
        return self.network(features)


def test_dry_run_preserves_cache_and_split_and_never_fits_or_saves_checkpoint(vision_sources, monkeypatch):
    root, config, _, _, cache = vision_sources
    before = {path: sha(path) for path in (root / "data").rglob("*") if path.is_file()}
    log_before = (root / "reports/research_log.md").read_bytes()
    monkeypatch.setattr(runner, "VisionResNet18", TinyVisionModel)
    def forbidden(*args, **kwargs):
        raise AssertionError("Dry-run entered training/checkpoint code")
    monkeypatch.setattr(runner, "train_with_validation", forbidden)
    monkeypatch.setattr(runner, "_save_checkpoint", forbidden)
    report = runner.run_vision_model(root, config, run_id="dry")
    assert report["status"] == "dry_run_completed"
    assert report["smoke"]["input_shape"] == [2, 1, 256, 256]
    assert report["smoke"]["optimizer_steps"] == 0 and not report["smoke"]["checkpoint_saved"]
    assert report["metrics"] == {} and not list((root / report["artifact_directory"]).glob("*.pt"))
    assert all(sha(path) == digest for path, digest in before.items())
    assert (root / "reports/research_log.md").read_bytes().startswith(log_before)
    first = {path: sha(path) for path in (root / "reports/experiments/vision_resnet/dry").iterdir()}
    second = runner.run_vision_model(root, config, run_id="dry_two")
    assert second["smoke"]["bce_loss"] == report["smoke"]["bce_loss"]
    assert all(sha(path) == digest for path, digest in first.items())
    with pytest.raises(ValueError, match="run directory exists"):
        runner.run_vision_model(root, config, run_id="dry")


def test_smoke_can_use_foreign_cache_ids_but_execute_refuses_the_mapping(vision_sources, monkeypatch):
    root, config, _, source, _ = vision_sources
    table = pd.read_csv(source)
    table["sample_id"] = [f"foreign_{index}" for index in range(len(table))]
    table.to_csv(source, index=False)
    config["paths"]["source_manifest_sha256"] = sha(source)
    monkeypatch.setattr(runner, "VisionResNet18", TinyVisionModel)
    report = runner.run_vision_model(root, config, run_id="foreign_dry")
    assert not report["protocol_g_readiness"]["ready"] and report["protocol_g_readiness"]["matched_ids"] == 0
    with pytest.raises(ValueError, match="complete Protocol G"):
        runner.run_vision_model(root, config, execute=True, run_id="foreign_execute")
    assert not list((root / "artifacts/vision_resnet/foreign_execute").glob("*.pt"))


def test_official_training_refuses_dirty_code_before_any_fit(vision_sources, monkeypatch):
    root, config, *_ = vision_sources
    monkeypatch.setattr(runner, "repository_git_state", lambda root: {"status": "dirty", "porcelain_entries": []})
    with pytest.raises(ValueError, match="clean committed worktree"):
        runner.run_vision_model(root, config, execute=True, run_id="dirty")


def test_synthetic_training_locks_checkpoint_before_single_test_evaluation(vision_sources, monkeypatch):
    root, config, *_ = vision_sources
    monkeypatch.setattr(runner, "repository_git_state", lambda root: {"status": "clean", "porcelain_entries": []})
    monkeypatch.setattr(runner, "VisionResNet18", TinyVisionModel)
    actual_evaluate = runner.evaluate_vision_model
    evaluated = []
    def evaluate(model, loader, *, device):
        partition = loader.dataset.samples[0].split
        if partition == "test":
            lock = root / "reports/experiments/vision_resnet/train/validation_lock.json"
            assert lock.exists() and (root / "artifacts/vision_resnet/train/best_model.pt").exists()
            assert json.loads(lock.read_text())["test_evaluations_before_lock"] == 0
        evaluated.append(partition)
        return actual_evaluate(model, loader, device=device)
    monkeypatch.setattr(runner, "evaluate_vision_model", evaluate)
    report = runner.run_vision_model(root, config, execute=True, run_id="train")
    assert report["status"] == "completed" and evaluated == ["validation", "test"]
    checkpoint = torch.load(root / report["checkpoint"]["path"], map_location="cpu", weights_only=True)
    assert checkpoint["best_epoch"] == 1
    assert checkpoint["split_manifest_sha256"] == config["paths"]["split_manifest_sha256"]
    assert report["metrics"]["test"]["evaluation_count"] == 1
    assert all(np.isfinite(report["metrics"]["test"][key]) for key in ("accuracy", "f1_malicious", "mcc", "loss"))
    assert (root / "reports/research_log.md").read_text().count("vision execute / completed") == 2


def test_binary_metrics_include_stable_bce_loss_and_malicious_positive_semantics():
    class FixedLogits(nn.Module):
        def forward(self, features):
            return features[:, 0, 0, 0].reshape(-1, 1)
    features = torch.zeros((2, 1, 256, 256))
    features[:, 0, 0, 0] = torch.tensor([-2.0, 2.0])
    loader = DataLoader(TensorDataset(features, torch.tensor([0.0, 1.0])), batch_size=2)
    metrics = runner.evaluate_vision_model(FixedLogits(), loader, device=torch.device("cpu"))
    assert metrics["positive_label"] == 1
    assert metrics["accuracy"] == metrics["f1_malicious"] == metrics["mcc"] == 1
    assert metrics["loss"] == pytest.approx(0.126928, abs=1e-6)
    assert metrics["ece_bins"] == 10


@pytest.mark.parametrize("case", ["seed", "batch_size", "nonfinite_rate", "threads", "threshold"])
def test_configuration_rejects_unsafe_or_unlocked_values(vision_sources, case):
    root, config, *_ = vision_sources
    if case == "seed":
        config["seed"] = 43
    elif case == "batch_size":
        config["training"]["batch_size"] = True
    elif case == "nonfinite_rate":
        config["training"]["learning_rate"] = float("nan")
    elif case == "threshold":
        config["training"]["threshold"] = 0.9
    else:
        config["runtime"]["cpu_threads"] = 1000
    with pytest.raises(ValueError):
        runner.run_vision_model(root, config)
    assert not (root / "reports/experiments/vision_resnet").exists()


def test_vision_cli_defaults_to_dry_run(vision_sources, monkeypatch, capsys):
    root, config, *_ = vision_sources
    directory = root / "configs"
    directory.mkdir()
    path = directory / "vision.yaml"
    path.write_text(yaml.safe_dump(config))
    main = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/03_train_vision_model.py"))["main"]
    monkeypatch.setitem(main.__globals__, "ROOT", root)
    monkeypatch.setattr(runner, "VisionResNet18", TinyVisionModel)
    assert main(["--config", str(path), "--run-id", "cli"]) == 0
    stdout = capsys.readouterr().out
    assert "dry_run_completed" in stdout and "No optimizer steps/checkpoint" in stdout


def test_smoke_training_checks_backward_and_checkpoint_without_protocol_g_claims(vision_sources, monkeypatch):
    root, config, _, source, _ = vision_sources
    table = pd.read_csv(source)
    table["sample_id"] = [f"foreign_{index}" for index in range(len(table))]
    table["Label"] = 1
    table.to_csv(source, index=False)
    config["paths"]["source_manifest_sha256"] = sha(source)
    before = {path: sha(path) for path in (root / "data").rglob("*") if path.is_file()}
    log_before = (root / "reports/research_log.md").read_bytes()
    monkeypatch.setattr(runner, "repository_git_state", lambda root: {"status": "dirty", "porcelain_entries": []})
    monkeypatch.setattr(runner, "VisionResNet18", TinyVisionModel)
    def forbidden(*args, **kwargs):
        raise AssertionError("Technical smoke entered official validation training")
    monkeypatch.setattr(runner, "train_with_validation", forbidden)
    report = runner.run_vision_model(root, config, smoke_train=True, smoke_epochs=2, smoke_batch_size=2, run_id="backward")
    assert report["mode"] == "smoke_train" and report["status"] == "smoke_train_completed"
    assert not report["protocol_g_readiness"]["ready"] and report["git_worktree"]["status"] == "dirty"
    smoke = report["smoke_training"]
    assert smoke["epochs"] == 2 and smoke["batch_size"] == 2 and smoke["optimizer_steps"] == 2
    assert smoke["gradients_finite"] and smoke["parameters_changed"] and smoke["checkpoint_reload_verified"]
    assert smoke["parameter_sha256_before"] != smoke["parameter_sha256_after"]
    assert smoke["validation_evaluations"] == smoke["test_evaluations"] == 0
    assert list(report["metrics"]) == ["smoke_same_samples"]
    metrics = report["metrics"]["smoke_same_samples"]
    assert metrics["single_class_labels"] and not metrics["mcc_defined"] and metrics["mcc"] == 0
    assert all(np.isfinite(metrics[key]) for key in ("accuracy", "f1_malicious", "mcc", "loss", "ece", "brier"))
    checkpoint_path = root / report["checkpoint"]["path"]
    assert checkpoint_path.name == "smoke_model.pt" and report["checkpoint"]["sha256"] == sha(checkpoint_path)
    checkpoint = torch.load(checkpoint_path, map_location="cpu", weights_only=True)
    assert checkpoint["purpose"] == "technical_smoke_only" and checkpoint["official_model"] is False
    assert checkpoint["epochs"] == 2 and checkpoint["optimizer_steps"] == 2
    directory = root / "reports/experiments/vision_resnet/backward"
    lock = json.loads((directory / "locked_methodology.json").read_text())
    assert lock["smoke_training"]["epochs"] == 2 and lock["smoke_training"]["official_model"] is False
    assert "Same samples as fitting" in lock["smoke_training"]["evaluation_scope"]
    assert not (directory / "validation_lock.json").exists()
    assert json.loads((directory / "metrics.json").read_text()) == report["metrics"]
    with (directory / "model_comparison.csv").open() as handle:
        comparison = list(csv.DictReader(handle))
    assert len(comparison) == 1 and comparison[0]["partition"] == "smoke_same_samples"
    assert comparison[0]["scope"] == metrics["scope"]
    assert all(sha(path) == digest for path, digest in before.items())
    assert (root / "reports/research_log.md").read_bytes().startswith(log_before)
    log = (root / "reports/research_log.md").read_text()
    assert "vision smoke_train / smoke_train_completed" in log and "not Protocol G performance" in log
    assert "Single-class labels" in log


def test_smoke_training_enforces_sample_cap_and_small_batch(vision_sources, monkeypatch):
    root, config, *_ = vision_sources
    config["runtime"]["dry_run_max_samples"] = 64
    monkeypatch.setattr(runner, "VisionResNet18", TinyVisionModel)
    report = runner.run_vision_model(root, config, smoke_train=True, smoke_epochs=1, smoke_batch_size=4, run_id="bounded")
    assert report["smoke_training"]["sample_count"] == 8
    assert report["smoke_training"]["optimizer_steps"] == 2


@pytest.mark.parametrize("options", [
    {"execute": True, "smoke_train": True}, {"smoke_train": 1},
    {"smoke_epochs": 0}, {"smoke_epochs": 3}, {"smoke_epochs": True},
    {"smoke_batch_size": 0}, {"smoke_batch_size": 8}, {"smoke_batch_size": True},
])
def test_smoke_training_rejects_unsafe_modes_and_limits_before_writing(vision_sources, options):
    root, config, *_ = vision_sources
    with pytest.raises(ValueError):
        runner.run_vision_model(root, config, **options)
    assert not (root / "reports/experiments/vision_resnet").exists()


def test_smoke_training_fails_closed_on_nonfinite_gradients_and_logs_failure(vision_sources, monkeypatch):
    root, config, *_ = vision_sources
    class InvalidGradients(TinyVisionModel):
        def __init__(self):
            super().__init__()
            next(self.parameters()).register_hook(lambda gradient: torch.full_like(gradient, float("nan")))
    monkeypatch.setattr(runner, "VisionResNet18", InvalidGradients)
    def forbidden(*args, **kwargs):
        raise AssertionError("Non-finite gradients reached checkpoint creation")
    monkeypatch.setattr(runner, "_save_checkpoint", forbidden)
    with pytest.raises(RuntimeError, match="gradients are missing or non-finite"):
        runner.run_vision_model(root, config, smoke_train=True, run_id="bad_gradients")
    directory = root / "reports/experiments/vision_resnet/bad_gradients"
    report = json.loads((directory / "run_summary.json").read_text())
    assert report["status"] == "failed" and report["metrics"] == {}
    assert (directory / "locked_methodology.json").exists() and (directory / "model_comparison.csv").exists()
    assert not list((root / report["artifact_directory"]).glob("*.pt"))
    assert "vision smoke_train / failed" in (root / "reports/research_log.md").read_text()


def test_vision_cli_smoke_training_runs_backward_and_checkpoint(vision_sources, monkeypatch, capsys):
    root, config, *_ = vision_sources
    directory = root / "configs"
    directory.mkdir()
    path = directory / "vision.yaml"
    path.write_text(yaml.safe_dump(config))
    main = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/03_train_vision_model.py"))["main"]
    monkeypatch.setitem(main.__globals__, "ROOT", root)
    monkeypatch.setattr(runner, "VisionResNet18", TinyVisionModel)
    assert main(["--config", str(path), "--smoke-train", "--smoke-epochs", "2", "--smoke-batch-size", "2", "--run-id", "cli_backward"]) == 0
    stdout = capsys.readouterr().out
    assert "smoke_train_completed" in stdout and "2 optimizer steps" in stdout
    assert "reload verified" in stdout and "same fitting samples" in stdout
    assert "Accuracy=" in stdout and "F1 malicious=" in stdout and "MCC=" in stdout and "Loss=" in stdout

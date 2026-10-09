"""Offline cache-backed tri-modal tests; all bytes/tables/checkpoints are synthetic."""

import hashlib
import json
from pathlib import Path
import runpy

import numpy as np
import pandas as pd
import pytest
import torch
import yaml

from malpdf.evaluation.selective import calibration_metrics
from malpdf.experiments import late_fusion_runner as fusion_runner
from malpdf.experiments import tri_modal_runner as tri
from malpdf.models import late_fusion
from malpdf.models.vision_resnet import VisionResNet18
from malpdf.static.cache_manager import load_cached_markov_pdf
from malpdf.static.markov import MARKOV_ALGORITHM, byte_transition_matrix
from test_late_fusion import probability_sources, sha  # Shared offline Protocol G fixture.


class TinyVision(torch.nn.Module):
    def __init__(self):
        super().__init__()
        self.scale = torch.nn.Parameter(torch.tensor(6.0))

    def forward(self, features):
        assert features.dtype == torch.float32 and tuple(features.shape[1:]) == (1, 256, 256)
        return (features[:, 0, 0, 1] * self.scale - 3).reshape(-1, 1)


@pytest.fixture
def cache_sources(probability_sources, monkeypatch):
    root, fusion, manifest = probability_sources
    directory = root / "data/processed/markov_cache"
    directory.mkdir()
    rows = []
    for index, row in manifest.iterrows():
        content = bytes([0, 1 if row.Label else 2, 0, 1 if row.Label else 2, index, 255])
        digest = hashlib.sha256(content).hexdigest()
        path = directory / f"{digest}.npy"
        np.save(path, byte_transition_matrix(content), allow_pickle=False)
        path.with_suffix(".json").write_text(json.dumps({"algorithm": MARKOV_ALGORITHM, "pdf_sha256": digest,
            "pdf_bytes": len(content), "shape": [256, 256], "dtype": "float32", "npy_sha256": sha(path)}))
        rows.append({"sample_id": row.sample_id, "Label": row.Label, "pdf_relative_path": f"data/raw/synthetic_{index}.pdf", "pdf_sha256": digest})
    source = root / "data/processed/source_pdf_manifest.csv"
    pd.DataFrame(rows).iloc[::-1].to_csv(source, index=False)
    def spec(path):
        return {"path": str(path.relative_to(root)), "sha256": sha(path)}
    checkpoint = root / "artifacts/vision_resnet/synthetic/best_model.pt"
    checkpoint.parent.mkdir(parents=True)
    payload = {"model_state_dict": TinyVision().state_dict(), "architecture": "vision_resnet18", "seed": 42,
               "best_epoch": 1, "best_validation_loss": 0.1, "source_manifest_sha256": sha(source),
               "split_manifest_sha256": fusion["inputs"]["split_manifest"]["sha256"], "threshold": 0.5}
    torch.save(payload, checkpoint)
    checkpoint_evidence = {**spec(checkpoint), "best_epoch": 1, "best_validation_loss": 0.1}
    configuration = {"seed": 42, "paths": {"source_manifest": spec(source)["path"], "source_manifest_sha256": sha(source),
        **{name: fusion["inputs"][name]["path"] for name in ("dataset", "split_manifest")},
        **{f"{name}_sha256": fusion["inputs"][name]["sha256"] for name in ("dataset", "split_manifest")}}}
    summary = {"status": "completed", "mode": "execute", "code_commit_sha": "c" * 40, "git_worktree": {"status": "clean"},
               "checkpoint": checkpoint_evidence, "protocol_g_readiness": {"ready": True}}
    methodology = {"configuration": configuration, "mode": "execute", "code_commit_sha": "c" * 40,
                   "training": "Existing train_with_validation; AdamW/BCEWithLogitsLoss; lowest validation loss"}
    lock = {**checkpoint_evidence, "seed": 42, "threshold": 0.5, "selection_metric": "validation_loss", "test_evaluations_before_lock": 0}
    training_run = {}
    for name, value in (("summary", summary), ("methodology", methodology), ("validation_lock", lock)):
        path = root / f"reports/experiments/base/vision_{name}.json"
        path.write_text(json.dumps(value))
        training_run[name] = spec(path)
    monkeypatch.setattr(tri, "VisionResNet18", TinyVision)
    return root, {"fusion": fusion, "vision_cache": {"source_manifest": spec(source), "cache_directory": str(directory.relative_to(root)),
                    "checkpoint": spec(checkpoint), "training_run": training_run, "batch_size": 4, "cpu_threads": 2}}, manifest


def change_json(root, spec, edit):
    path = root / spec["path"]
    value = json.loads(path.read_text())
    edit(value)
    path.write_text(json.dumps(value))
    spec["sha256"] = sha(path)


def test_complete_cache_pipeline_locks_before_single_test_inference_and_decode(cache_sources, monkeypatch):
    root, config, manifest = cache_sources
    history = (root / "reports/research_log.md").read_bytes()
    protected = {path: sha(path) for path in root.rglob("*") if path.is_file() and path.name != "research_log.md"}
    lock_path = root / "reports/experiments/tri_modal_fusion/full/validation_lock.json"
    real_predict, real_fit = tri.CacheVisionPredictor.predict, late_fusion.LogisticRegression.fit
    real_read = fusion_runner._prediction_frame
    inferred, decoded = [], []
    def predict(self, partition, subset):
        inferred.append(partition)
        if partition == "test":
            assert lock_path.is_file()
        return real_predict(self, partition, subset)
    def fit(self, *args, **kwargs):
        assert not lock_path.exists(), "Refit after validation lock"
        return real_fit(self, *args, **kwargs)
    def read(root, spec, columns):
        if spec == config["fusion"]["inputs"]["test"]:
            assert lock_path.exists()
            decoded.append("test")
        return real_read(root, spec, columns)
    monkeypatch.setattr(tri.CacheVisionPredictor, "predict", predict)
    monkeypatch.setattr(late_fusion.LogisticRegression, "fit", fit)
    monkeypatch.setattr(fusion_runner, "_prediction_frame", read)
    result = tri.run_tri_modal_fusion(root, config, execute=True, run_id="full")
    assert result["status"] == "completed" and inferred == ["validation", "test"] and decoded == ["test"]
    assert result["test_evaluation_count"] == 1 and result["candidate_count"] == 18 and result["skipped_vision_weights"] == []
    lock = json.loads(lock_path.read_text())
    assert lock["branches"] == list(late_fusion.VISION_BRANCHES) and not lock["test_used_for_fitting_or_selection"]
    assert not lock["refit_after_selection"] and lock["seed"] == 42
    directory = lock_path.parent
    assert json.loads((directory / "vision_provenance.json").read_text())["cache_readiness"]["ready"]
    assert json.loads((directory / "data_provenance.json").read_text())["vision_cache_readiness"]["ready"]
    assert len(pd.read_csv(directory / "model_comparison.csv")) == 9
    metrics = json.loads((directory / "metrics.json").read_text())
    assert metrics == result["metrics"] and "vision_resnet18/test" in metrics
    artifact = root / result["artifact_directory"]
    vision = pd.read_parquet(artifact / "vision_test_predictions.parquet")
    assert set(vision.sample_id) == set(manifest.loc[manifest.split == "test"].sample_id)
    for label, score in zip(vision.true_label, vision.vision_probability):
        assert (score >= 0.5) == bool(label)  # Inference uses cache tensors, never labels.
    table = pd.read_parquet(artifact / "test_predictions.parquet")
    expected = calibration_metrics(table.true_label.to_numpy(), table.ensemble_probability.to_numpy(), n_bins=10)
    assert metrics["tri_modal_fusion/test"] == expected
    assert result["routing"]["referral_rate"] == 0.1 and result["routing"]["dynamic_samples_executed"] == 0
    assert pd.read_csv(directory / "selection_results.csv").vision_weight.max() > 0
    roles = pd.read_csv(artifact / "validation_roles.csv")
    merged = roles.merge(manifest, on="sample_id", validate="one_to_one")
    assert merged.split.eq("validation").all() and merged.groupby("duplicate_group_id").role.nunique().max() == 1
    assert all(sha(path) == digest for path, digest in protected.items())
    log = (root / "reports/research_log.md").read_bytes()
    assert log.startswith(history) and log.decode().count("tri-modal fusion execute / completed") == 9
    with pytest.raises(ValueError, match="directory exists"):
        tri.run_tri_modal_fusion(root, config, execute=True, run_id="full")


def test_foreign_cve_like_cache_cohort_blocks_all_fit_inference_and_test_access(cache_sources, monkeypatch):
    root, config, manifest = cache_sources
    source = root / config["vision_cache"]["source_manifest"]["path"]
    rows = pd.read_csv(source).iloc[:5].copy()
    rows["sample_id"] = [f"foreign:{index}" for index in range(5)]
    rows.to_csv(source, index=False)
    config["vision_cache"]["source_manifest"]["sha256"] = sha(source)
    def forbidden(*args, **kwargs):
        pytest.fail("Ineligible cache cohort reached fitting, inference, or test reading")
    monkeypatch.setattr(fusion_runner, "fit_validation_stack", forbidden)
    monkeypatch.setattr(fusion_runner, "_prediction_frame", forbidden)
    monkeypatch.setattr(tri, "VisionResNet18", forbidden)
    result = tri.run_tri_modal_fusion(root, config, execute=True, run_id="foreign")
    assert result["status"] == "blocked_missing_vision" and result["metrics"] == {} and result["test_evaluation_count"] == 0
    ready = result["vision_cache_readiness"]
    assert ready["matched_ids"] == 0 and ready["missing_source_ids"] == len(manifest) and ready["foreign_source_ids"] == 5
    assert ready["source_cache_rows_verified"] == 5
    directory = root / "reports/experiments/tri_modal_fusion/foreign"
    assert not (directory / "validation_lock.json").exists()
    assert pd.read_csv(directory / "model_comparison.csv").accuracy.isna().all()
    assert "tri-modal fusion execute / blocked_missing_vision" in (root / "reports/research_log.md").read_text()


def test_complete_cache_without_official_checkpoint_is_blocked(cache_sources):
    root, config, _ = cache_sources
    config["vision_cache"].update(checkpoint=None, training_run=None)
    result = tri.run_tri_modal_fusion(root, config, execute=True, run_id="missing_model")
    assert result["status"] == "blocked_missing_vision" and result["test_evaluation_count"] == 0
    assert "checkpoint" in result["error"]["message"] and not result["vision_cache_readiness"]["ready"]


@pytest.mark.parametrize("case", ["smoke", "dirty_training", "methodology", "lock"])
def test_unreviewed_training_proof_is_rejected_and_logged(cache_sources, case):
    root, config, _ = cache_sources
    training = config["vision_cache"]["training_run"]
    if case == "smoke":
        change_json(root, training["summary"], lambda value: value.update(mode="smoke_train", status="smoke_train_completed"))
    elif case == "dirty_training":
        change_json(root, training["summary"], lambda value: value.update(git_worktree={"status": "dirty"}))
    elif case == "methodology":
        change_json(root, training["methodology"], lambda value: value.update(training="fit on test"))
    else:
        change_json(root, training["validation_lock"], lambda value: value.update(test_evaluations_before_lock=1))
    with pytest.raises(ValueError):
        tri.run_tri_modal_fusion(root, config, execute=True, run_id=case)
    summary = json.loads((root / f"reports/experiments/tri_modal_fusion/{case}/run_summary.json").read_text())
    assert summary["status"] == "failed" and summary["test_evaluation_count"] == 0
    assert "tri-modal fusion execute / failed" in (root / "reports/research_log.md").read_text()


@pytest.mark.parametrize("case", ["hash", "smoke_payload", "seed", "nan"])
def test_checkpoint_hash_metadata_and_nonfinite_state_fail_closed(cache_sources, case):
    root, config, _ = cache_sources
    spec = config["vision_cache"]["checkpoint"]
    path = root / spec["path"]
    payload = torch.load(path, weights_only=True)
    if case == "smoke_payload":
        payload.update(purpose="technical_smoke_only", official_model=False)
    elif case == "seed":
        payload["seed"] = 43
    else:
        payload["model_state_dict"]["scale"].fill_(float("nan"))
    torch.save(payload, path)
    if case != "hash":
        spec["sha256"] = sha(path)
        for name in ("summary", "validation_lock"):
            change_json(root, config["vision_cache"]["training_run"][name],
                        lambda value: (value["checkpoint"] if "checkpoint" in value else value).update(sha256=sha(path)))
    with pytest.raises(ValueError):
        tri.run_tri_modal_fusion(root, config, execute=True, run_id=case)
    assert not (root / f"reports/experiments/tri_modal_fusion/{case}/validation_lock.json").exists()


def test_corrupt_cache_preserves_failure_evidence_before_any_inference(cache_sources):
    root, config, _ = cache_sources
    path = next((root / config["vision_cache"]["cache_directory"]).glob("*.npy"))
    path.write_bytes(b"invalid synthetic npy")
    with pytest.raises(ValueError, match="checksum"):
        tri.run_tri_modal_fusion(root, config, execute=True, run_id="corrupt")
    report = json.loads((root / "reports/experiments/tri_modal_fusion/corrupt/run_summary.json").read_text())
    assert report["status"] == "failed" and report["metrics"] == {} and report["test_evaluation_count"] == 0


def test_dry_run_never_infers_or_fits_and_dirty_execute_is_refused(cache_sources, monkeypatch):
    root, config, _ = cache_sources
    monkeypatch.setattr(tri.CacheVisionPredictor, "predict", lambda *args: pytest.fail("Dry-run inference"))
    monkeypatch.setattr(fusion_runner, "fit_validation_stack", lambda *args: pytest.fail("Dry-run fitting"))
    monkeypatch.setattr(fusion_runner, "repository_git_state", lambda root: {"status": "dirty"})
    result = tri.run_tri_modal_fusion(root, config, run_id="preflight")
    assert result["status"] == "dry_run_completed" and result["test_evaluation_count"] == 0
    assert result["metrics"] == {} and not result["official_execution_ready"]
    with pytest.raises(ValueError, match="clean committed worktree"):
        tri.run_tri_modal_fusion(root, config, execute=True, run_id="dirty")


def test_predictor_forbids_test_before_lock_repeated_inference_and_cache_mutation(cache_sources):
    root, config, manifest = cache_sources
    directory = root / "reports/experiments/tri_modal_fusion/predictor"
    artifacts = root / "artifacts/tri_modal_fusion/predictor"
    directory.mkdir(parents=True)
    artifacts.mkdir(parents=True)
    predictor = tri.CacheVisionPredictor(root, config["vision_cache"], config["fusion"]["inputs"], manifest, directory, artifacts, {})
    test = manifest.loc[manifest.split == "test"]
    with pytest.raises(ValueError, match="persisted fusion validation lock"):
        predictor.predict("test", test)
    validation = manifest.loc[manifest.split == "validation"]
    predictor.predict("validation", validation)
    with pytest.raises(ValueError, match="only once"):
        predictor.predict("validation", validation)
    (directory / "validation_lock.json").write_text("{}")
    sample = predictor.partitions["test"][0]
    path = predictor.cache_directory / f"{sample.pdf_sha256}.npy"
    matrix, metadata = load_cached_markov_pdf(sample.pdf_sha256, cache_directory=predictor.cache_directory)
    matrix[0] = 0
    np.save(path, matrix, allow_pickle=False)
    metadata["npy_sha256"] = sha(path)
    path.with_suffix(".json").write_text(json.dumps(metadata))
    with pytest.raises(ValueError, match="changed after vision preflight"):
        predictor.predict("test", test)


def test_real_resnet_checkpoint_forward_path_uses_verified_cache(cache_sources, monkeypatch):
    root, config, manifest = cache_sources
    monkeypatch.setattr(tri, "VisionResNet18", VisionResNet18)
    path = root / config["vision_cache"]["checkpoint"]["path"]
    payload = torch.load(path, weights_only=True)
    payload["model_state_dict"] = VisionResNet18().state_dict()
    torch.save(payload, path)
    config["vision_cache"]["checkpoint"]["sha256"] = sha(path)
    for name in ("summary", "validation_lock"):
        change_json(root, config["vision_cache"]["training_run"][name],
                    lambda value: (value["checkpoint"] if "checkpoint" in value else value).update(sha256=sha(path)))
    result = tri.run_tri_modal_fusion(root, config, execute=True, run_id="real_resnet")
    assert result["status"] == "completed" and result["test_evaluation_count"] == 1
    frame = pd.read_parquet(root / result["artifact_directory"] / "vision_test_predictions.parquet")
    assert len(frame) == manifest.split.eq("test").sum() and frame.vision_probability.between(0, 1).all()


@pytest.mark.parametrize("case", ["seed", "directory", "checkpoint", "batch", "no_positive_vision", "runtime", "saved_vision"])
def test_invalid_configuration_rejected_before_run_creation(cache_sources, case):
    root, config, _ = cache_sources
    if case == "seed":
        config["fusion"]["seed"] = 0
    elif case == "directory":
        config["vision_cache"]["cache_directory"] = "data/processed/../../escape"
    elif case == "checkpoint":
        config["vision_cache"]["checkpoint"]["path"] = "data/raw/untrusted.pt"
    elif case == "batch":
        config["vision_cache"]["batch_size"] = 100_000
    elif case == "no_positive_vision":
        config["fusion"]["candidates"]["vision_weights"] = [0]
    elif case == "runtime":
        config["vision_cache"]["cpu_threads"] = True
    else:
        config["fusion"]["vision"] = {"validation": config["fusion"]["inputs"]["validation"], "test": config["fusion"]["inputs"]["test"], "provenance": config["fusion"]["inputs"]["base_provenance"]}
    with pytest.raises(ValueError):
        tri.run_tri_modal_fusion(root, config, execute=True)
    assert not (root / "reports/experiments/tri_modal_fusion").exists()


def test_cli_reports_missing_official_vision_and_returns_two(cache_sources, monkeypatch, capsys):
    root, config, _ = cache_sources
    config["vision_cache"].update(checkpoint=None, training_run=None)
    path = root / "configs/tri_modal_fusion.yaml"
    path.parent.mkdir()
    path.write_text(yaml.safe_dump(config))
    main = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/05_evaluate_tri_modal_fusion.py"))["main"]
    monkeypatch.setitem(main.__globals__, "ROOT", root)
    assert main(["--config", str(path), "--execute", "--run-id", "cli"]) == 2
    output = capsys.readouterr().out
    assert "blocked_missing_vision" in output and "test evaluations: 0" in output and "metrics N/A" in output

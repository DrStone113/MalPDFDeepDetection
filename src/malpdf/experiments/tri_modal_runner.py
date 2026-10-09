"""Cache-backed Vision inference for validation-locked three-branch fusion."""

from __future__ import annotations

from io import BytesIO
import json
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from torch.utils.data import DataLoader
import yaml

from malpdf.data.vision_dataset import (
    MarkovCacheDataset, align_protocol_g_samples, load_vision_source_manifest,
    verify_vision_caches, vision_validation_groups,
)
from malpdf.deep_learning.training import probabilities_from_logits, set_deep_learning_seed
from malpdf.experiments.late_fusion_runner import (
    _input_bytes, _input_spec, run_late_fusion, validate_late_fusion_configuration,
)
from malpdf.experiments.vision_runner import _write_json
from malpdf.models.vision_resnet import VisionResNet18
from malpdf.static.safety import read_bounded_bytes


def validate_cache_vision_configuration(configuration: dict) -> None:
    if not isinstance(configuration, dict) or set(configuration) != {
        "source_manifest", "cache_directory", "checkpoint", "training_run", "batch_size", "cpu_threads",
    }:
        raise ValueError("Cache Vision requires source/cache/checkpoint/training-run and runtime limits")
    _input_spec(configuration["source_manifest"])
    if not configuration["source_manifest"]["path"].startswith("data/processed/"):
        raise ValueError("Vision source manifest must stay in processed data")
    directory = configuration["cache_directory"]
    if not isinstance(directory, str) or not directory.startswith("data/processed/") or ".." in Path(directory).parts or "\\" in directory:
        raise ValueError("Vision cache directory must stay in processed data")
    checkpoint, training = configuration["checkpoint"], configuration["training_run"]
    if (checkpoint is None) != (training is None):
        raise ValueError("Official checkpoint and training provenance must be configured together")
    if checkpoint is not None:
        _input_spec(checkpoint)
        if not checkpoint["path"].startswith("artifacts/") or Path(checkpoint["path"]).suffix != ".pt":
            raise ValueError("Vision checkpoint must be a local ignored .pt artifact")
        if not isinstance(training, dict) or set(training) != {"summary", "methodology", "validation_lock"}:
            raise ValueError("Vision training proof requires summary, methodology and validation lock")
        for spec in training.values():
            _input_spec(spec)
    for name, cap in (("batch_size", 64), ("cpu_threads", 8)):
        if type(configuration[name]) is not int or not 1 <= configuration[name] <= cap:
            raise ValueError("Vision runtime must use positive bounded integers")


def load_tri_modal_configuration(root: Path, path: Path) -> dict:
    content = read_bounded_bytes(path, boundary=root / "configs", max_bytes=128 * 1024)
    configuration = yaml.safe_load(content)
    validate_tri_modal_configuration(configuration)
    return configuration


def validate_tri_modal_configuration(configuration: dict) -> None:
    if not isinstance(configuration, dict) or set(configuration) != {"fusion", "vision_cache"}:
        raise ValueError("Tri-modal configuration requires fusion and vision_cache")
    validate_late_fusion_configuration(configuration["fusion"])
    if configuration["fusion"]["vision"] is not None:
        raise ValueError("Tri-modal Vision probabilities must come from verified caches")
    validate_cache_vision_configuration(configuration["vision_cache"])
    if not any(value > 0 for value in configuration["fusion"]["candidates"]["vision_weights"]):
        raise ValueError("Tri-modal candidates must include positive Vision weights")


class CacheVisionPredictor:
    """Infer each partition at most once; test requires the saved fusion lock.

    Only bounded NPY/checkpoint bytes are read. Labels establish manifest identity
    and are never model inputs. Ineligible cohorts produce aggregate readiness
    evidence without fitting, inference, or test prediction access.
    """

    def __init__(self, root: Path, configuration: dict, inputs: dict, manifest: pd.DataFrame,
                 directory: Path, artifacts: Path, report: dict) -> None:
        self.root, self.configuration = root, configuration
        self.directory, self.artifacts = directory, artifacts
        self.ready = False
        self.inferred_partitions = set()
        self.cache_directory = root / configuration["cache_directory"]
        if not self.cache_directory.is_dir() or any(part.is_symlink() for part in (self.cache_directory, *self.cache_directory.parents)):
            raise ValueError("Vision cache directory must exist without symbolic links")
        spec = configuration["source_manifest"]
        samples = load_vision_source_manifest(root, root / spec["path"], spec["sha256"])
        _, self.readiness = align_protocol_g_samples(samples, manifest)
        report["vision_cache_readiness"] = self.readiness
        self.readiness["cache_files_present"] = sum(1 for _ in self.cache_directory.glob("*.npy"))
        verified = verify_vision_caches(samples, self.cache_directory)
        self.readiness["source_cache_rows_verified"] = len(verified)
        self.readiness["checkpoint_configured"] = configuration["checkpoint"] is not None
        if not self.readiness["ready"]:
            self.readiness["reason"] += "; an official train-only RIT Vision checkpoint is also required"
            return
        if configuration["checkpoint"] is None:
            self.readiness.update(ready=False, reason="Complete cache cohort found, but an official checksum-locked train-only Vision checkpoint/training run is unavailable")
            return
        self.readiness.update(ready=False, reason="Complete cache alignment; official checkpoint verification pending")
        self._validate_training_proof(inputs)
        content = _input_bytes(root, configuration["checkpoint"], max_bytes=64 * 1024 * 1024)
        payload = torch.load(BytesIO(content), map_location="cpu", weights_only=True)
        if not isinstance(payload, dict) or payload.get("purpose") == "technical_smoke_only" or payload.get("official_model") is False:
            raise ValueError("Smoke checkpoints are ineligible for tri-modal fusion")
        expected = {"architecture": "vision_resnet18", "seed": 42, "threshold": 0.5,
                    "source_manifest_sha256": spec["sha256"], "split_manifest_sha256": inputs["split_manifest"]["sha256"],
                    "best_epoch": self.training_summary["checkpoint"]["best_epoch"],
                    "best_validation_loss": self.training_summary["checkpoint"]["best_validation_loss"]}
        if any(payload.get(key) != value for key, value in expected.items()):
            raise ValueError("Vision checkpoint metadata disagrees with the locked training proof")
        state = payload.get("model_state_dict")
        if not isinstance(state, dict) or not state or any(not isinstance(value, torch.Tensor) or not torch.isfinite(value).all() for value in state.values()):
            raise ValueError("Vision checkpoint requires finite tensor state")
        old_threads = torch.get_num_threads()
        try:
            torch.set_num_threads(configuration["cpu_threads"])
            self.determinism = set_deep_learning_seed(42)
            self.model = VisionResNet18()
            self.model.load_state_dict(state, strict=True)
            self.model.eval()
        finally:
            torch.set_num_threads(old_threads)
        self.partitions, _ = align_protocol_g_samples(verified, manifest)
        self.groups = vision_validation_groups(verified, manifest)
        pd.DataFrame([{"sample_id": sample.sample_id, "npy_sha256": sample.npy_sha256} for sample in verified]).to_csv(artifacts / "cache_integrity.csv", index=False)
        self.readiness.update(ready=True, reason="Full Protocol G cache alignment and official train-only checkpoint verified")
        _write_json(directory / "vision_provenance.json", {"checkpoint": configuration["checkpoint"], "training_run": configuration["training_run"],
                    "source_manifest": spec, "cache_readiness": self.readiness, "seed": 42, "determinism": self.determinism,
                    "cache_integrity_path": str((artifacts / "cache_integrity.csv").relative_to(root)),
                    "device": "cpu", "base_fit_partition": "train", "checkpoint_selection_partition": "validation",
                    "test_inference_policy": "Exactly once after fusion validation_lock.json", "raw_pdf_reads": 0})
        self.ready = True

    def _validate_training_proof(self, inputs: dict) -> None:
        proof = {name: json.loads(_input_bytes(self.root, spec, max_bytes=1024 * 1024))
                 for name, spec in self.configuration["training_run"].items()}
        summary, methodology, lock = (proof[name] for name in ("summary", "methodology", "validation_lock"))
        revision = summary.get("code_commit_sha", "")
        if summary.get("status") != "completed" or summary.get("mode") != "execute" or summary.get("git_worktree", {}).get("status") != "clean" or len(revision) != 40 or any(value not in "0123456789abcdef" for value in revision):
            raise ValueError("Vision requires completed clean official training; smoke checkpoints are ineligible")
        config = methodology.get("configuration", {})
        paths = config.get("paths", {})
        expected_paths = {"source_manifest": self.configuration["source_manifest"]["path"],
                          "source_manifest_sha256": self.configuration["source_manifest"]["sha256"],
                          **{name: inputs[name]["path"] for name in ("dataset", "split_manifest")},
                          **{f"{name}_sha256": inputs[name]["sha256"] for name in ("dataset", "split_manifest")}}
        checkpoint = summary.get("checkpoint", {})
        if config.get("seed") != 42 or paths != expected_paths or methodology.get("mode") != "execute" or methodology.get("code_commit_sha") != revision or methodology.get("training") != "Existing train_with_validation; AdamW/BCEWithLogitsLoss; lowest validation loss":
            raise ValueError("Vision training methodology must bind train-only Protocol G inputs and validation early stopping")
        if not summary.get("protocol_g_readiness", {}).get("ready") or checkpoint.get("path") != self.configuration["checkpoint"]["path"] or checkpoint.get("sha256") != self.configuration["checkpoint"]["sha256"]:
            raise ValueError("Vision training proof does not bind the complete source cohort and checkpoint")
        if type(checkpoint.get("best_epoch")) is not int or checkpoint["best_epoch"] < 1 or type(checkpoint.get("best_validation_loss")) not in (int, float) or not np.isfinite(checkpoint["best_validation_loss"]) or checkpoint["best_validation_loss"] < 0:
            raise ValueError("Vision checkpoint selection requires finite validation-loss evidence")
        if lock != {**checkpoint, "seed": 42, "threshold": 0.5, "selection_metric": "validation_loss", "test_evaluations_before_lock": 0}:
            raise ValueError("Vision checkpoint must have been locked by validation loss before test")
        self.training_summary = summary

    def predict(self, partition: str, subset: pd.DataFrame) -> pd.DataFrame:
        if not self.ready or partition not in {"validation", "test"} or partition in self.inferred_partitions:
            raise ValueError("Vision can infer each eligible validation/test partition only once")
        if partition == "test" and not (self.directory / "validation_lock.json").is_file():
            raise ValueError("Vision test inference requires the persisted fusion validation lock")
        lookup = {sample.sample_id: sample for sample in self.partitions[partition]}
        if set(lookup) != set(subset.sample_id) or any(lookup[row.sample_id].label != row.Label for row in subset.itertuples()):
            raise ValueError("Vision inference IDs/labels disagree with Protocol G")
        ordered = [lookup[value] for value in subset.sample_id]
        loader = DataLoader(MarkovCacheDataset(ordered, self.cache_directory), batch_size=self.configuration["batch_size"],
                            shuffle=False, num_workers=0, generator=torch.Generator().manual_seed(42))
        self.inferred_partitions.add(partition)
        scores = []
        old_threads = torch.get_num_threads()
        try:
            torch.set_num_threads(self.configuration["cpu_threads"])
            with torch.inference_mode():
                for features, _ in loader:
                    logits = self.model(features).reshape(-1)
                    if not torch.isfinite(logits).all():
                        raise ValueError("Vision inference produced non-finite logits")
                    scores.append(probabilities_from_logits(logits))
        finally:
            torch.set_num_threads(old_threads)
        frame = pd.DataFrame({"sample_id": subset.sample_id.to_numpy(), "true_label": subset.Label.to_numpy(),
                              "vision_probability": np.concatenate(scores)})
        frame.to_parquet(self.artifacts / f"vision_{partition}_predictions.parquet", index=False)
        return frame


def run_tri_modal_fusion(root: Path, configuration: dict, *, execute: bool = False, run_id: str | None = None) -> dict:
    validate_tri_modal_configuration(configuration)
    return run_late_fusion(root, configuration["fusion"], execute=execute, run_id=run_id,
                           cache_vision=configuration["vision_cache"])

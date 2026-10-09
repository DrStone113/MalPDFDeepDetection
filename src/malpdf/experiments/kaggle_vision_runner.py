"""Portable Vision training on a sealed numeric bundle; Test probabilities only."""

from datetime import datetime, timezone
import hashlib
import importlib.metadata
import io
import json
from pathlib import Path
import platform
import multiprocessing
import shutil
from time import perf_counter

import numpy as np
import pandas as pd
import torch
from torch.utils.data import DataLoader, Dataset

from malpdf.data.markov_arrays import MAX_CACHE_BYTES, load_markov_npy
from malpdf.deep_learning.training import probabilities_from_logits, set_deep_learning_seed, train_with_validation
from malpdf.evaluation.binary import evaluate_binary_predictions
from malpdf.models.vision_resnet import VisionResNet18


def _json(path, value):
    with path.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, allow_nan=False)
        handle.write("\n")


def _bytes(root, name, cap):
    relative = Path(name)
    path = root / relative
    if (relative.is_absolute() or ".." in relative.parts or "\\" in name
            or path.is_symlink() or not path.resolve().is_relative_to(root.resolve())):
        raise ValueError("Unsafe bundle-relative input path")
    with path.open("rb") as handle:
        content = handle.read(cap + 1)
    if len(content) > cap:
        raise ValueError("Bundle member exceeds its resource cap")
    return content


def load_bundle(root):
    metadata = json.loads(_bytes(root, "bundle_metadata.json", 1024 * 1024))
    if metadata["seed"] != 42 or metadata["shape"] != [1, 256, 256] or metadata["raw_pdfs_included"] is not False:
        raise ValueError("Numeric-only seed-42 bundle required")
    for name, digest in metadata["file_sha256"].items():
        if hashlib.sha256(_bytes(root, name, 16 * 1024**2)).hexdigest() != digest:
            raise ValueError("Bundle code/manifest checksum differs")
    frame = pd.read_csv(io.BytesIO(_bytes(root, "manifest.csv", 16 * 1024**2)))
    roles = pd.read_csv(io.BytesIO(_bytes(root, "validation_roles.csv", 16 * 1024**2)))
    if (set(frame) != {"sample_id", "Label", "split", "group_id", "cache_relative_path", "npy_sha256", "parser_failed"}
            or not frame.sample_id.is_unique or not frame.cache_relative_path.is_unique
            or not frame.sample_id.str.fullmatch(r"sample_[0-9]{6}").all()
            or not frame.split.isin(["train", "validation", "test", "unlabeled"]).all()
            or frame.groupby("group_id").split.nunique().max() != 1):
        raise ValueError("Bundle schema or group/identity disjointness failed")
    labeled = frame.loc[frame.split.ne("unlabeled")]
    if not labeled.Label.isin([0, 1]).all() or not frame.loc[frame.split.eq("unlabeled")].Label.isna().all():
        raise ValueError("Unknown labels cannot enter supervised training")
    if frame.split.value_counts().to_dict() != metadata["partition_rows"]:
        raise ValueError("Portable split differs from the locked export")
    validation = frame.loc[frame.split.eq("validation")]
    if (not roles.sample_id.is_unique or set(roles.sample_id) != set(validation.sample_id)
            or set(roles.role) != {"base_selection", "meta_fit", "calibration_fit", "threshold_selection"}):
        raise ValueError("The four locked validation roles are required")
    joined = validation.merge(roles, on="sample_id", validate="one_to_one")
    if joined.groupby("group_id").role.nunique().max() != 1:
        raise ValueError("A validation group crosses fit/selection roles")
    for partition in ("train", "validation", "test"):
        if set(frame.loc[frame.split.eq(partition)].Label) != {0, 1}:
            raise ValueError("Each supervised partition requires both classes")
    if any(set(joined.loc[joined.role.eq(role)].Label) != {0, 1} for role in roles.role.unique()):
        raise ValueError("Each validation role requires both classes")
    return frame, roles, metadata


def available_ram_bytes():
    """Respect both Linux available RAM and the container's memory quota."""
    limits = []
    meminfo = Path('/proc/meminfo')
    if meminfo.is_file():
        for line in meminfo.read_text().splitlines():
            if line.startswith('MemAvailable:'):
                limits.append(int(line.split()[1]) * 1024)
    for base, maximum, current in ((Path('/sys/fs/cgroup'), 'memory.max', 'memory.current'),
                                   (Path('/sys/fs/cgroup/memory'), 'memory.limit_in_bytes', 'memory.usage_in_bytes')):
        if (base / maximum).is_file() and (base / current).is_file():
            value = (base / maximum).read_text().strip()
            if value != 'max':
                limits.append(max(0, int(value) - int((base / current).read_text())))
    if not limits:
        raise RuntimeError('Cannot verify available RAM; use disk loading explicitly')
    return min(limits)


class RamMatrixCache:
    """One preallocated float32 block, read only in forked loader workers."""
    def __init__(self, root, frame, *, max_bytes, reserve_bytes):
        required = len(frame) * 256 * 256 * 4
        if required > max_bytes or required + reserve_bytes > available_ram_bytes():
            raise ValueError('Insufficient RAM budget for cache and reserved working memory')
        self.tensor = torch.empty((len(frame), 1, 256, 256), dtype=torch.float32)
        self.positions = {sid: i for i, sid in enumerate(frame.sample_id)}
        self.bytes, self.rows_read = required, 0
        started = last = perf_counter()
        for i, row in enumerate(frame.itertuples()):
            content = _bytes(root, row.cache_relative_path, MAX_CACHE_BYTES)
            if hashlib.sha256(content).hexdigest() != row.npy_sha256:
                raise ValueError('Matrix changed after export')
            self.tensor[i, 0].copy_(torch.from_numpy(load_markov_npy(content)))
            self.rows_read += 1
            if perf_counter() - last >= 10:
                print(json.dumps({'event': 'ram_preload', 'rows': self.rows_read, 'total': len(frame)}), flush=True)
                last = perf_counter()
        self.seconds = perf_counter() - started


class BundleDataset(Dataset):
    def __init__(self, root, frame, *, labels, cache=None):
        self.root, self.frame, self.labels, self.cache = root, frame.reset_index(drop=True), labels, cache
        if labels and not self.frame.Label.isin([0, 1]).all():
            raise ValueError("Only binary supervised labels may enter a loss")
        self.targets = torch.tensor(self.frame.Label.to_numpy(dtype=np.float32), dtype=torch.float32) if labels else None
        self.positions = [cache.positions[sid] for sid in self.frame.sample_id] if cache is not None else None
    def __len__(self): return len(self.frame)
    def __getitem__(self, index):
        if self.cache is not None:
            value = self.cache.tensor[self.positions[index]]
        else:
            row = self.frame.iloc[index]
            content = _bytes(self.root, row.cache_relative_path, MAX_CACHE_BYTES)
            if hashlib.sha256(content).hexdigest() != row.npy_sha256:
                raise ValueError("Matrix changed after export")
            value = torch.from_numpy(load_markov_npy(content)).unsqueeze(0)
        return (value, self.targets[index]) if self.labels else value


def predict(model, loader, device, *, mixed_precision=False):
    model.eval()
    result = []
    with torch.inference_mode():
        for batch in loader:
            value = batch[0] if isinstance(batch, (list, tuple)) else batch
            with torch.autocast(device_type=device.type, dtype=torch.float16, enabled=mixed_precision):
                logits = model(value.to(device, non_blocking=device.type == 'cuda').contiguous(memory_format=torch.channels_last))
            result.append(probabilities_from_logits(logits.float().reshape(-1)))
    return np.concatenate(result)


def train_kaggle_vision(bundle_root, output_root, configuration, *, allow_cpu_smoke=False, code_provenance=None):
    """Stopping sees only base_selection; Test labels never enter evaluation."""
    frame, roles, bundle = load_bundle(bundle_root)
    config = dict(configuration)
    expected = {"batch_size", "max_epochs", "patience", "learning_rate", "weight_decay", "min_delta"}
    optional = {'preload_ram', 'mixed_precision', 'num_workers', 'prefetch_factor', 'max_ram_cache_gib'}
    if (not expected.issubset(config) or set(config) - expected - optional or any(type(config[k]) is not int or not 1 <= config[k] <= limit for k, limit in (("batch_size", 512), ("max_epochs", 150), ("patience", 150)))
            or any(type(config[k]) not in (int, float) or not np.isfinite(config[k]) or not 0 <= config[k] <= 1 for k in ("learning_rate", "weight_decay", "min_delta"))
            or config["learning_rate"] == 0):
        raise ValueError("Bounded finite Vision parameters are required")
    for key, default in (('preload_ram', False), ('mixed_precision', False), ('num_workers', 0), ('prefetch_factor', 1), ('max_ram_cache_gib', 6)):
        config.setdefault(key, default)
    if (any(type(config[k]) is not bool for k in ('preload_ram', 'mixed_precision'))
            or type(config['num_workers']) is not int or not 0 <= config['num_workers'] <= 4
            or type(config['prefetch_factor']) is not int or not 1 <= config['prefetch_factor'] <= 4
            or type(config['max_ram_cache_gib']) not in (int, float) or not np.isfinite(config['max_ram_cache_gib'])
            or not 0 < config['max_ram_cache_gib'] <= 16):
        raise ValueError('Bounded RAM, worker and precision settings are required')
    device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
    if device.type != "cuda" and not allow_cpu_smoke:
        raise RuntimeError("GPU unavailable: enable Kaggle Accelerator=GPU before training")
    if allow_cpu_smoke and (config["max_epochs"] > 2 or config["batch_size"] > 16):
        raise ValueError("CPU smoke is capped at two epochs and batch size 16")
    if config['preload_ram'] and config['num_workers'] and 'fork' not in multiprocessing.get_all_start_methods():
        raise ValueError('Shared RAM workers require Linux fork; choose num_workers=0 on this platform')
    effective_amp = config['mixed_precision'] and device.type == 'cuda'
    provenance = code_provenance or {'generating_commit': bundle['code_commit'], 'worktree': 'sealed exported code'}
    if code_provenance is not None:
        if provenance.get('worktree') != 'clean' or len(provenance.get('generating_commit', '')) != 40:
            raise ValueError('An optimized code overlay requires clean committed provenance')
        actual = {'code/src/malpdf/experiments/kaggle_vision_runner.py': Path(__file__),
                  'code/src/malpdf/deep_learning/training.py': Path(train_with_validation.__code__.co_filename)}
        if set(provenance['file_sha256']) != set(actual) or any(hashlib.sha256(path.read_bytes()).hexdigest() != provenance['file_sha256'][name] for name, path in actual.items()):
            raise ValueError('Loaded optimized training code differs from its sealed provenance')
    run_id = "run_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ_") + provenance['generating_commit'][:12]
    directory = output_root / run_id
    directory.mkdir(parents=True, exist_ok=False)
    state = {"run_id": run_id, "status": "started", "seed": 42, "code_commit": provenance['generating_commit'],
             'base_bundle_code_commit': bundle['code_commit'], 'training_code_provenance': provenance,
             'mixed_precision_effective': effective_amp,
             "bundle_metadata_sha256": hashlib.sha256((bundle_root / "bundle_metadata.json").read_bytes()).hexdigest(),
             "metrics": {}, "test_metrics_computed": False, "test_prediction_passes": 0}
    _json(directory / "locked_methodology.json", {**state, "configuration": config, "device": str(device),
        "early_stopping_role": "validation_base_selection_only", "raw_pdfs_read": 0,
        "test_policy": "Probability export only, no labels in loaders, no Test metrics or selection",
        "gpu_strategy": "One GPU (cuda:0); selecting T4 x2 does not enable two-GPU training automatically"})
    _json(directory / "environment_metadata.json", {"python": platform.python_version(),
        "packages": {name: importlib.metadata.version(name) for name in ("numpy", "pandas", "scikit-learn", "torch", "torchvision")},
        "cuda_version": torch.version.cuda, "gpu_count": torch.cuda.device_count(),
        "gpu_name": torch.cuda.get_device_name(0) if device.type == "cuda" else None})
    try:
        state["determinism"] = set_deep_learning_seed(42)
        torch.set_num_threads(2)
        cache = RamMatrixCache(bundle_root, frame, max_bytes=int(config['max_ram_cache_gib'] * 1024**3),
            reserve_bytes=int((0.25 if allow_cpu_smoke else 2) * 1024**3)) if config['preload_ram'] else None
        state['data_loading'] = {'preload_ram': cache is not None, 'bytes': cache.bytes if cache else 0,
            'preload_seconds': cache.seconds if cache else 0, 'matrix_reads': cache.rows_read if cache else None,
            'storage_dtype': 'float32', 'normalization': 'unchanged P(next byte | current byte)',
            'sharing': 'read-only fork copy-on-write' if cache and config['num_workers'] else 'single process',
            'num_workers': config['num_workers'], 'pin_memory': device.type == 'cuda',
            'persistent_workers': bool(config['num_workers']), 'prefetch_factor': config['prefetch_factor']}
        if config['num_workers'] and Path('/dev/shm').is_dir():
            needed = 2 * config['num_workers'] * config['prefetch_factor'] * config['batch_size'] * 256 * 256 * 4 + 8 * 1024**2
            if needed > shutil.disk_usage('/dev/shm').free:
                raise ValueError('Insufficient shared memory for loader prefetch; lower workers, batch or prefetch before a new run')
        train = frame.loc[frame.split.eq("train")]
        validation = frame.loc[frame.split.eq("validation")]
        selected_ids = set(roles.loc[roles.role.eq("base_selection"), "sample_id"])
        selected = validation.loc[validation.sample_id.isin(selected_ids)]
        def loader(rows, *, labels, shuffle=False):
            options = {'persistent_workers': True, 'prefetch_factor': config['prefetch_factor']} if config['num_workers'] else {}
            if cache is not None and config['num_workers']:
                options['multiprocessing_context'] = 'fork'
            return DataLoader(BundleDataset(bundle_root, rows, labels=labels, cache=cache), batch_size=config["batch_size"],
                shuffle=shuffle, num_workers=config['num_workers'], pin_memory=device.type == "cuda",
                generator=torch.Generator().manual_seed(42), **options)
        model = VisionResNet18().to(memory_format=torch.channels_last)
        outcome = train_with_validation(model, loader(train, labels=True, shuffle=True), loader(selected, labels=True),
            device=device, **{key: config[key] for key in ("learning_rate", "weight_decay", "max_epochs", "patience", "min_delta")},
            mixed_precision=effective_amp, non_blocking=device.type == 'cuda', channels_last=True, record_performance=True,
            progress=lambda value: print(json.dumps(value), flush=True))
        if any(not torch.isfinite(value).all() for value in outcome.best_state_dict.values()):
            raise RuntimeError("Selected Vision checkpoint is non-finite")
        checkpoint = directory / "vision_resnet_best.pt"
        with checkpoint.open("xb") as handle:
            torch.save({"model_state_dict": outcome.best_state_dict, "architecture": "single_channel_resnet18",
                        "best_epoch": outcome.best_epoch, "seed": 42, "code_commit": state['code_commit'],
                        'training_code_provenance': provenance}, handle)
        model.load_state_dict(torch.load(checkpoint, map_location=device, weights_only=True)["model_state_dict"], strict=True)
        pd.DataFrame(outcome.history).to_csv(directory / "training_history.csv", index=False)
        state.update(best_epoch=outcome.best_epoch, best_validation_loss=outcome.best_validation_loss, training_seconds=outcome.training_seconds)
        _json(directory / "vision_selection_lock.json", {**state, "checkpoint_sha256": hashlib.sha256(checkpoint.read_bytes()).hexdigest(),
            "selected_role": "validation_base_selection", "selection_rows": len(selected), "configuration": config})
        for partition, filename in (("validation", "vision_probs_val.csv"), ("test", "vision_probs_test.csv"), ("unlabeled", "vision_probs_unlabeled.csv")):
            rows = frame.loc[frame.split.eq(partition)]
            if rows.empty: continue
            probabilities = predict(model, loader(rows, labels=False), device, mixed_precision=effective_amp)
            pd.DataFrame({"sample_id": rows.sample_id, "p_malicious": probabilities}).to_csv(directory / filename, index=False)
            if partition == "test": state["test_prediction_passes"] += 1
            if partition == "validation":
                mask = rows.sample_id.isin(selected_ids).to_numpy()
                state["metrics"] = evaluate_binary_predictions(rows.Label.to_numpy()[mask], (probabilities[mask] >= 0.5).astype(int), probabilities[mask])
        state["status"] = "completed"
        names = ["vision_resnet_best.pt", "vision_probs_val.csv", "vision_probs_test.csv", "vision_probs_unlabeled.csv", "training_history.csv", "vision_selection_lock.json"]
        _json(directory / "output_checksums.json", {name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in names if (directory / name).exists()})
    except BaseException as error:
        state.update(status="interrupted" if isinstance(error, (KeyboardInterrupt, SystemExit)) else "failed", error_type=type(error).__name__)
        _json(directory / "error.json", {"type": type(error).__name__, "message": str(error)})
        raise
    finally:
        _json(directory / "run_summary.json", state)
        pd.DataFrame([{**state["metrics"], "model": "vision_resnet18", "partition": "validation_base_selection",
                      "status": state["status"], "test_metrics": "N/A: probabilities only"}]).to_csv(directory / "model_comparison.csv", index=False)
        with (directory / "research_log.md").open("x") as handle:
            handle.write("| UTC | Run ID | Status | Protocol/seed | Model | Partition | F1 | MCC | ECE | Brier | Commit | Worktree | Evidence | Notes |\n")
            handle.write("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n")
            handle.write("| " + " | ".join(map(str, [datetime.now(timezone.utc).isoformat(), run_id, state["status"], "raw-cohort Protocol G / 42", "vision_resnet18", "validation_base_selection", state["metrics"].get("f1_malicious", "N/A"), state["metrics"].get("mcc", "N/A"), "N/A", "N/A", state['code_commit'], provenance['worktree'], "run_summary.json", "Label=1 malicious; Test probability export only; ECE/Brier not evaluated"])) + " |\n")
    print(json.dumps({"status": state["status"], "output_directory": str(directory), "best_epoch": state["best_epoch"]}, indent=2))
    return directory

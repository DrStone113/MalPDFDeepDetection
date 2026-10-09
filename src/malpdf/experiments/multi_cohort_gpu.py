"""Sealed v4 GPU training: five FT folds plus scratch Vision, no Test metrics."""
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import io
import json
import platform
import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
import torch
from torch.utils.data import DataLoader, TensorDataset
from malpdf.deep_learning.models import build_tabular_model
from malpdf.deep_learning.training import set_deep_learning_seed, train_with_validation
from malpdf.experiments.kaggle_vision_runner import _bytes, _json, load_bundle, train_kaggle_vision


def fold_preprocessing(values, selected, order, metadata_features):
    positions = [i for i, name in enumerate(order) if name in metadata_features]
    others = [i for i in range(len(order)) if i not in positions]
    if np.isinf(values).any() or np.isinf(selected).any() or np.isnan(values[:, others]).any() or np.isnan(selected[:, others]).any():
        raise ValueError("Security measurements cannot be missing or imputed")
    imputer = SimpleImputer(strategy="median", keep_empty_features=True).fit(values)
    def expand(a):
        if np.isinf(a).any() or np.isnan(a[:, others]).any(): raise ValueError("Security measurements cannot be imputed")
        return np.hstack((imputer.transform(a), np.isnan(a[:, positions]).astype(float)))
    scaler = StandardScaler().fit(expand(values))
    def transform(a):
        result = scaler.transform(expand(a)).astype(np.float32)
        if not np.isfinite(result).all(): raise ValueError("FT transformed input overflow")
        return result
    return imputer, scaler, transform


def predict_ft(model, values, device, batch_size, *, amp):
    model.eval(); output = []
    with torch.inference_mode():
        for start in range(0, len(values), batch_size):
            x = torch.from_numpy(values[start:start + batch_size]).to(device)
            with torch.autocast(device_type=device.type, dtype=torch.float16, enabled=amp):
                p = torch.sigmoid(model(x).reshape(-1).float())
            if not torch.isfinite(p).all(): raise RuntimeError("Non-finite FT probabilities")
            output.append(p.cpu().numpy())
    return np.concatenate(output)


def train_v4_gpu(bundle_root, output_root, *, allow_cpu_smoke=False):
    frame, roles, bundle = load_bundle(bundle_root)
    configuration = json.loads(_bytes(bundle_root, "v4_gpu_configuration.json", 1024**2))
    cfg, vision_cfg = configuration["tabular"], configuration["vision"]
    if not torch.cuda.is_available() and not allow_cpu_smoke:
        raise RuntimeError("V4 deep training requires an explicitly authorized cloud GPU")
    if allow_cpu_smoke and (cfg["training"]["max_epochs"] > 2 or cfg["training"]["batch_size"] > 16):
        raise ValueError("Explicit CPU smoke is bounded to two epochs and batch16")
    device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
    amp = device.type == "cuda"
    directory = output_root / ("run_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ_") + bundle["code_commit"][:12])
    directory.mkdir(parents=True, exist_ok=False)
    bundle_sha = hashlib.sha256(_bytes(bundle_root, "bundle_metadata.json", 1024**2)).hexdigest()
    state = {"status": "started", "seed": 42, "bundle_metadata_sha256": bundle_sha,
        "code_commit": bundle["code_commit"], "test_metrics_computed": False, "ft_folds": []}
    _json(directory / "locked_methodology.json", {**state, "configuration": configuration,
        "fit_scope": "combined_Train_fitting_fold_only", "early_stopping": "Validation_base_selection_only",
        "Test_policy": "Probability exports only; no Test labels in loaders, no Test metrics or selection"})
    _json(directory / "environment_metadata.json", {"python": platform.python_version(),
        "packages": {name: importlib.metadata.version(name) for name in
            ("numpy", "pandas", "scikit-learn", "torch", "torchvision")},
        "code_commit": bundle["code_commit"], "cuda_version": torch.version.cuda,
        "device": str(device), "gpu_name": torch.cuda.get_device_name(device) if amp else None,
        "requested_precision": "cuda_fp16_amp", "effective_precision": "cuda_fp16_amp" if amp else "cpu_fp32_smoke"})
    try:
        torch.set_num_threads(2)
        table = pd.read_csv(io.BytesIO(_bytes(bundle_root, "tabular_features.csv", 16 * 1024**2))).set_index("sample_id")
        folds = pd.read_csv(io.BytesIO(_bytes(bundle_root, "train_folds.csv", 16 * 1024**2)))
        order, meta = configuration["feature_order"], configuration["metadata_features"]
        if (not table.index.is_unique or set(table.index) != set(frame.sample_id) or list(table.columns) != order
                or not folds.sample_id.is_unique or set(folds.sample_id) != set(frame.loc[frame.split.eq("train"), "sample_id"])
                or set(folds.fold) != {1, 2, 3, 4, 5}):
            raise ValueError("FT table/fold identities violate sealed Train contract")
        train = frame.loc[frame.split.eq("train")].reset_index(drop=True)
        assignments = folds.set_index("sample_id").loc[train.sample_id].fold.to_numpy()
        if train.assign(fold=assignments).groupby("group_id").fold.nunique().max() != 1:
            raise ValueError("FT Train groups cross folds")
        selected = frame.loc[frame.sample_id.isin(roles.loc[roles.role.eq("base_selection"), "sample_id"])]
        val, test = frame.loc[frame.split.eq("validation")], frame.loc[frame.split.eq("test")]
        probabilities = {"validation": np.zeros(len(val)), "test": np.zeros(len(test))}
        expanded = [*order, *(name + "__missing" for name in order if name in meta)]
        def loader(x, y, shuffle):
            return DataLoader(TensorDataset(torch.from_numpy(x), torch.tensor(y.to_numpy(), dtype=torch.float32)),
                batch_size=cfg["training"]["batch_size"], shuffle=shuffle, num_workers=1,
                pin_memory=amp, persistent_workers=True, multiprocessing_context="fork", prefetch_factor=1,
                generator=torch.Generator().manual_seed(42))
        for fold in range(1, 6):
            set_deep_learning_seed(42)
            fitting = train.loc[assignments != fold]
            if set(fitting.Label) != {0, 1}: raise ValueError("Each FT fitting fold needs both classes")
            values, selected_values = table.loc[fitting.sample_id].to_numpy(float), table.loc[selected.sample_id].to_numpy(float)
            imputer, scaler, transform = fold_preprocessing(values, selected_values, order, meta)
            parameters = {**cfg["models"]["ft_transformer"], "input_features": len(expanded)}
            model = build_tabular_model("ft_transformer", parameters)
            training = cfg["training"]
            result = train_with_validation(model, loader(transform(values), fitting.Label, True),
                loader(transform(selected_values), selected.Label, False), device=device,
                **{k: training[k] for k in ("learning_rate", "weight_decay", "max_epochs", "patience", "min_delta")},
                mixed_precision=amp, non_blocking=amp, record_performance=True,
                progress=lambda event: print(json.dumps({"model": "ft_transformer", "fold": fold, **event}), flush=True))
            model.load_state_dict(result.best_state_dict, strict=True)
            folder = directory / "ft_transformer" / f"fold_{fold}"
            folder.mkdir(parents=True, exist_ok=False)
            checkpoint = folder / "model.pt"
            with checkpoint.open("xb") as output:
                torch.save({"model_state_dict": result.best_state_dict, "architecture": "ft_transformer", "seed": 42,
                    "configuration": parameters, "best_epoch": result.best_epoch}, output)
            _json(folder / "imputation.json", {"fit_scope": "train_fitting_fold_only", "fit_rows": len(fitting),
                "statistics": imputer.statistics_.tolist(), "feature_order": order, "expanded_feature_order": expanded})
            _json(folder / "scaler.json", {"fit_scope": "train_fitting_fold_only", "fit_rows": len(fitting),
                "mean": scaler.mean_.tolist(), "var": scaler.var_.tolist(), "scale": scaler.scale_.tolist(), "feature_order": expanded})
            info = {"model": "ft_transformer", "seed": 42, "fit_partition": "train_fitting_fold",
                "preprocessing_scope": "train_fitting_fold_only", "fit_rows": len(fitting), "fitting_rows": len(fitting),
                "base_selection_rows": len(selected), "raw_feature_order": order, "feature_order": expanded,
                "parameters": parameters, "checkpoint_sha256": hashlib.sha256(checkpoint.read_bytes()).hexdigest(),
                "best_epoch": result.best_epoch, "early_stopping_partition": "validation_base_selection",
                "best_validation_loss": result.best_validation_loss, "training_seconds": result.training_seconds,
                "precision": "cuda_fp16_amp" if amp else "explicit_cpu_smoke_fp32"}
            _json(folder / "fit_metadata.json", info)
            pd.DataFrame(result.history).to_csv(folder / "training_history.csv", index=False)
            state["ft_folds"].append(info)
            for partition, rows in (("validation", val), ("test", test)):
                probabilities[partition] += predict_ft(model, transform(table.loc[rows.sample_id].to_numpy(float)), device,
                    training["batch_size"], amp=amp) / 5
        _json(directory / "ft_selection_lock.json", {**state, "status": "completed", "selected_role": "validation_base_selection",
            "selection_rows": len(selected), "test_probability_exports": 1})
        for partition, rows in (("validation", val), ("test", test)):
            pd.DataFrame({"sample_id": rows.sample_id, "p_malicious": probabilities[partition]}).to_csv(
                directory / f"ft_probs_{'val' if partition == 'validation' else 'test'}.csv", index=False)
        vision_dir = train_kaggle_vision(bundle_root, directory / "vision", vision_cfg, allow_cpu_smoke=allow_cpu_smoke)
        state.update(status="completed", vision_directory=str(vision_dir.relative_to(directory)), ft_test_probability_exports=1,
            mixed_precision_effective=amp)
    except BaseException as error:
        state.update(status="interrupted" if isinstance(error, (KeyboardInterrupt, SystemExit)) else "failed", error_type=type(error).__name__)
        _json(directory / "error.json", {"type": type(error).__name__, "message": str(error)})
        raise
    finally:
        _json(directory / "run_summary.json", state)
        pd.DataFrame([{"model": "v4_gpu", "partition": "N/A", "status": state["status"], "metrics": "N/A: probability exports only"}]).to_csv(directory / "model_comparison.csv", index=False)
        with (directory / "research_log.md").open("x") as log:
            log.write("| UTC | Run | Status | Seed | Model | Partition | F1 | MCC | ECE | Brier | Commit | Notes |\n|---|---|---|---|---|---|---|---|---|---|---|---|\n")
            log.write(f"| {datetime.now(timezone.utc).isoformat()} | {directory.name} | {state['status']} | 42 | FT+Vision | N/A | N/A | N/A | N/A | N/A | {bundle['code_commit']} | No Test metrics; sealed numeric inputs |\n")
        _json(directory / "output_checksums.json", {str(p.relative_to(directory)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in directory.rglob("*") if p.is_file()})
    return directory

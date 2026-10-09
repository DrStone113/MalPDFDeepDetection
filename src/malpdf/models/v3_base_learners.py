"""Five explicitly seeded base learners; fold-fitting data never includes test."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
import torch
from torch.utils.data import DataLoader, TensorDataset

from malpdf.data.rit_pdfmal import sha256_file
from malpdf.deep_learning.models import build_tabular_model
from malpdf.deep_learning.training import probabilities_from_logits, set_deep_learning_seed, train_with_validation
from malpdf.experiments.vision_runner import _save_checkpoint, _write_json
from malpdf.models.classical import create_model
from malpdf.models.safe_stacking import V3_FEATURES
from malpdf.static.schema import RIT_FEATURES, PROTOCOL_G_REQUIRED_FEATURES
from malpdf.reproducibility import set_random_seed
from malpdf.static.safety import read_bounded_bytes


def _features(frame: pd.DataFrame, feature_order=V3_FEATURES, *, allow_missing=False) -> np.ndarray:
    full = (*RIT_FEATURES, "script_ratio", "ObfuscationCount")
    required = {*PROTOCOL_G_REQUIRED_FEATURES, "script_ratio", "ObfuscationCount"}
    original_order = tuple(f for f in feature_order if not f.startswith("markov__"))
    extras = tuple(f for f in feature_order if f.startswith("markov__"))
    if extras:
        from malpdf.static.markov_profiles import MARKOV_PROFILE_FEATURES
        if extras != MARKOV_PROFILE_FEATURES or tuple(feature_order) != (*original_order, *extras):
            raise ValueError("Markov additions require the complete fixed numeric profile contract")
    if (not required <= set(original_order) or tuple(f for f in full if f in original_order) != original_order
            or len(set(feature_order)) != len(feature_order)
            or tuple(frame.columns) != tuple(feature_order) or frame.empty):
        raise ValueError("V3 base inputs require the complete ordered safety feature contract")
    values = frame.to_numpy(dtype=np.float64)
    if np.isinf(values).any() or (not allow_missing and np.isnan(values).any()):
        raise ValueError("V3 base input features must be finite")
    return values


METADATA_FEATURES = ("pdfsize", "metadata size", "pages", "xref length", "title length", "isEncrypted", "embedded files", "images", "contains_text", "pdf_ver")


@dataclass(frozen=True)
class SavedMedianImputer:
    """Transform using persisted Train-fold medians without fitting again."""
    statistics_: np.ndarray

    def transform(self, values):
        if values.ndim != 2 or values.shape[1] != len(self.statistics_):
            raise ValueError("Saved imputer feature count differs")
        return np.where(np.isnan(values), self.statistics_, values)


@dataclass
class FoldImputer:
    """Median values are learned on fitting-fold rows; flags are fixed, unfitted."""
    imputer: SimpleImputer | SavedMedianImputer
    feature_order: tuple

    def transform(self, values):
        mask = np.isnan(values)
        positions = [i for i, name in enumerate(self.feature_order) if name in METADATA_FEATURES]
        if mask[:, [i for i in range(len(self.feature_order)) if i not in positions]].any():
            raise ValueError("Actual lexical/security/obfuscation features cannot be imputed")
        result = np.hstack((self.imputer.transform(values), mask[:, positions].astype(float)))
        if not np.isfinite(result).all():
            raise ValueError("Fold imputation produced non-finite values")
        return result

    @property
    def expanded_order(self):
        return (*self.feature_order, *(name + "__missing" for name in self.feature_order if name in METADATA_FEATURES))


@dataclass
class NativeMissingIndicators:
    """Preserve native tree NaNs; append fixed metadata flags without fitting."""
    feature_order: tuple

    def transform(self, values):
        mask = np.isnan(values)
        positions = [i for i, name in enumerate(self.feature_order) if name in METADATA_FEATURES]
        if np.isinf(values).any() or mask[:, [i for i in range(len(self.feature_order)) if i not in positions]].any():
            raise ValueError("Only unavailable metadata may be NaN")
        return np.hstack((values, mask[:, positions].astype(float)))

    @property
    def expanded_order(self):
        return (*self.feature_order, *(name + "__missing" for name in self.feature_order if name in METADATA_FEATURES))


@dataclass
class V3FoldModel:
    name: str
    model: object
    batch_size: int
    scaler: StandardScaler | None = None
    feature_order: tuple = V3_FEATURES
    preprocessor: FoldImputer | NativeMissingIndicators | None = None

    def predict_proba(self, frame: pd.DataFrame) -> np.ndarray:
        values = _features(frame, self.feature_order, allow_missing=self.preprocessor is not None)
        if self.preprocessor is not None:
            values = self.preprocessor.transform(values)
        if self.name == "ft_transformer":
            transformed = self.scaler.transform(values).astype(np.float32)
            if not np.isfinite(transformed).all():
                raise ValueError("FT transformed inputs overflowed float32")
            loader = DataLoader(TensorDataset(torch.from_numpy(transformed)), batch_size=self.batch_size, shuffle=False, num_workers=0)
            self.model.eval()
            scores = []
            with torch.inference_mode():
                for (features,) in loader:
                    logits = self.model(features).reshape(-1)
                    if not torch.isfinite(logits).all():
                        raise RuntimeError("FT inference logits are non-finite")
                    scores.append(probabilities_from_logits(logits))
            result = np.concatenate(scores)
        elif self.name == "lightgbm":
            result = self.model.booster_.predict(values)
        else:
            if not np.array_equal(self.model.classes_, [0, 1]):
                raise ValueError("Base model malicious probability requires classes [0,1]")
            result = self.model.predict_proba(values)[:, 1]
        if result.shape != (len(frame),) or not np.isfinite(result).all() or (result < 0).any() or (result > 1).any():
            raise RuntimeError("Base predictions must be aligned finite malicious probabilities")
        return result


def fit_v3_fold(name: str, configuration: dict, train_x: pd.DataFrame, train_y: np.ndarray,
                selection_x: pd.DataFrame, selection_y: np.ndarray, artifact_directory: Path, *,
                feature_order=V3_FEATURES, impute_metadata=False, progress=None,
                train_sample_weight=None) -> tuple[V3FoldModel, dict]:
    """Train on one fitting fold; FT stopping uses base-selection validation only."""
    values = _features(train_x, feature_order, allow_missing=impute_metadata)
    selected = _features(selection_x, feature_order, allow_missing=impute_metadata)
    if len(train_y) != len(values) or set(train_y) != {0, 1} or len(selection_y) != len(selected) or set(selection_y) != {0, 1}:
        raise ValueError("Fold train/base-selection labels must be aligned binary data")
    if train_sample_weight is not None:
        train_sample_weight = np.asarray(train_sample_weight, dtype=float)
        if (name == "ft_transformer" or train_sample_weight.shape != (len(values),)
                or not np.isfinite(train_sample_weight).all() or (train_sample_weight <= 0).any()):
            raise ValueError("Tree sample weights must be aligned, positive and finite; FT uses its GPU sampler")
    set_random_seed(42)
    parameters = dict(configuration["models"][name])
    training = configuration["training"]
    threads = configuration["cpu_threads"]
    scaler = None
    info = {"model": name, "seed": 42, "fit_rows": len(values), "base_selection_rows": len(selected),
            "fit_partition": "train_fitting_fold", "feature_order": list(V3_FEATURES), "parameters": parameters}
    if train_sample_weight is not None:
        info["train_weight_sha256"] = hashlib.sha256(train_sample_weight.astype("<f8").tobytes()).hexdigest()
        info["train_weight_sum"] = float(train_sample_weight.sum())
    artifact_directory.mkdir(parents=True, exist_ok=False)
    preprocessor = None
    if impute_metadata:
        if name in {"xgboost", "lightgbm", "catboost"}:
            preprocessor = NativeMissingIndicators(tuple(feature_order))
            info["missing_policy"] = "Native NaN handling; fixed metadata indicators; no imputer fitted"
        else:
            preprocessor = FoldImputer(SimpleImputer(strategy="median", keep_empty_features=True).fit(values), tuple(feature_order))
            info["missing_policy"] = "Train-fold median imputation plus fixed metadata indicators"
        values, selected = preprocessor.transform(values), preprocessor.transform(selected)
        info.update(raw_feature_order=list(feature_order), feature_order=list(preprocessor.expanded_order),
                    preprocessing_scope="train_fitting_fold_only", fitting_rows=len(train_x))
        if isinstance(preprocessor, FoldImputer):
            _write_json(artifact_directory / "imputation.json", {"fit_scope": "train_fitting_fold_only", "fit_rows": len(train_x),
                    "strategy": "median; all-missing training columns use explicit zero placeholder with missing flag",
                    "statistics": preprocessor.imputer.statistics_.tolist(), "feature_order": list(feature_order),
                    "expanded_feature_order": list(preprocessor.expanded_order)})
    if name == "ft_transformer":
        parameters["input_features"] = values.shape[1]
        info["determinism"] = set_deep_learning_seed(42)
        scaler = StandardScaler().fit(values)
        fit_values = scaler.transform(values).astype(np.float32)
        selected_values = scaler.transform(selected).astype(np.float32)
        if not np.isfinite(fit_values).all() or not np.isfinite(selected_values).all():
            raise ValueError("FT preprocessing produced non-finite input tensors")
        def loader(features, labels, shuffle):
            return DataLoader(TensorDataset(torch.from_numpy(features), torch.tensor(labels, dtype=torch.float32)),
                              batch_size=training["batch_size"], shuffle=shuffle, num_workers=0,
                              generator=torch.Generator().manual_seed(42))
        model = build_tabular_model(name, parameters)
        outcome = train_with_validation(model, loader(fit_values, train_y, True), loader(selected_values, selection_y, False),
                                        device=torch.device("cpu"), learning_rate=training["learning_rate"],
                                        weight_decay=training["weight_decay"], max_epochs=training["max_epochs"],
                                        patience=training["patience"], min_delta=training["min_delta"], progress=progress)
        if any(not torch.isfinite(value).all() for value in outcome.best_state_dict.values()):
            raise RuntimeError("FT selected checkpoint contains non-finite tensors")
        model.load_state_dict(outcome.best_state_dict, strict=True)
        checkpoint = artifact_directory / "model.pt"
        _save_checkpoint(checkpoint, {"model_state_dict": outcome.best_state_dict, "architecture": name,
                                     "seed": 42, "configuration": parameters, "best_epoch": outcome.best_epoch})
        pd.DataFrame(outcome.history).to_csv(artifact_directory / "training_history.csv", index=False)
        _write_json(artifact_directory / "scaler.json", {"fit_scope": "train_fitting_fold_only", "fit_rows": len(values),
                    "mean": scaler.mean_.tolist(), "scale": scaler.scale_.tolist(), "var": scaler.var_.tolist(),
                    "feature_order": info["feature_order"]})
        info.update(best_epoch=outcome.best_epoch, best_validation_loss=outcome.best_validation_loss,
                    early_stopping_partition="validation_base_selection", training_seconds=outcome.training_seconds)
    else:
        if name in {"xgboost", "random_forest"}:
            model = create_model(name, seed=42)
            model.set_params(**parameters, n_jobs=threads)
        elif name == "lightgbm":
            from lightgbm import LGBMClassifier
            model = LGBMClassifier(**parameters, objective="binary", random_state=42, n_jobs=threads,
                                   deterministic=True, force_col_wise=True, verbosity=-1)
        elif name == "catboost":
            from catboost import CatBoostClassifier
            model = CatBoostClassifier(**parameters, loss_function="Logloss", random_seed=42, thread_count=threads,
                                       task_type="CPU", allow_writing_files=False, verbose=False)
        else:
            raise ValueError("Unknown v3 base model")
        fit_arguments = {} if train_sample_weight is None else {"sample_weight": train_sample_weight}
        model.fit(values, train_y, **fit_arguments)
        if name == "xgboost":
            checkpoint = artifact_directory / "model.ubj"
            model.save_model(checkpoint)
        elif name == "lightgbm":
            checkpoint = artifact_directory / "model.txt"
            model.booster_.save_model(str(checkpoint))
        elif name == "catboost":
            checkpoint = artifact_directory / "model.cbm"
            model.save_model(str(checkpoint))
        else:
            checkpoint = artifact_directory / "model.joblib"
            joblib.dump(model, checkpoint)
    info.update(checkpoint=str(checkpoint), checkpoint_sha256=sha256_file(checkpoint))
    _write_json(artifact_directory / "fit_metadata.json", info)
    return V3FoldModel(name, model, training["batch_size"], scaler, tuple(feature_order), preprocessor), info


def load_v3_fold(checkpoint: Path, expected_sha256: str, train_reference: pd.DataFrame,
                 configuration: dict, *, boundary: Path, base_selection_rows: int):
    """Reload an explicitly trusted local checkpoint after checksum verification.

    RF joblib is accepted only from the checksum-pinned, locally trained reuse
    plan. Imported Kaggle weights are never deserialized here. Preprocessing
    statistics are checked against the original fitting Train fold, not fitted
    or adjusted using future rows.
    """
    content = read_bounded_bytes(checkpoint, boundary=boundary, max_bytes=128 * 1024**2)
    if hashlib.sha256(content).hexdigest() != expected_sha256:
        raise ValueError("Saved tabular checkpoint checksum differs")
    def saved(name):
        return json.loads(read_bounded_bytes(checkpoint.parent / name, boundary=boundary, max_bytes=128 * 1024))
    info = saved("fit_metadata.json")
    name, order = checkpoint.parent.parent.name, tuple(train_reference.columns)
    expected_parameters = dict(configuration["models"][name])
    expanded = NativeMissingIndicators(order).expanded_order
    if name == "ft_transformer":
        expected_parameters["input_features"] = len(expanded)
    if (info.get("model") != name or info.get("seed") != 42
            or info.get("checkpoint_sha256") != expected_sha256
            or info.get("fit_partition") != "train_fitting_fold"
            or info.get("preprocessing_scope") != "train_fitting_fold_only"
            or info.get("fit_rows") != len(train_reference)
            or info.get("fitting_rows") != len(train_reference)
            or info.get("base_selection_rows") != base_selection_rows
            or info.get("raw_feature_order") != list(order)
            or info.get("feature_order") != list(expanded)
            or info.get("parameters") != expected_parameters):
        raise ValueError("Saved fitting metadata contradicts the locked Train fold")
    values = _features(train_reference, order, allow_missing=True)
    if name in {"random_forest", "ft_transformer"}:
        imputation = saved("imputation.json")
        statistics = np.asarray(imputation["statistics"], float)
        reference = np.array([np.median(column[~np.isnan(column)]) if np.isfinite(column).any() else 0
                              for column in values.T])
        if (imputation.get("fit_scope") != "train_fitting_fold_only"
                or imputation.get("fit_rows") != len(values)
                or imputation.get("feature_order") != list(order)
                or imputation.get("expanded_feature_order") != list(expanded)
                or statistics.shape != reference.shape or not np.isfinite(statistics).all()
                or not np.allclose(statistics, reference, rtol=1e-12, atol=1e-12)):
            raise ValueError("Saved imputation is inconsistent with original Train-only medians")
        processor = FoldImputer(SavedMedianImputer(statistics), order)
    else:
        processor = NativeMissingIndicators(order)
    scaler = None
    if name == "ft_transformer":
        if info.get("early_stopping_partition") != "validation_base_selection":
            raise ValueError("Saved FT checkpoint must have Validation base-selection stopping")
        scale = saved("scaler.json")
        expanded_values = processor.transform(values)
        mean, variance, divisor = (np.asarray(scale[key], float) for key in ("mean", "var", "scale"))
        expected_variance = expanded_values.var(axis=0)
        if (scale.get("fit_scope") != "train_fitting_fold_only" or scale.get("fit_rows") != len(values)
                or scale.get("feature_order") != list(expanded)
                or any(v.shape != (len(expanded),) or not np.isfinite(v).all() for v in (mean, variance, divisor))
                or (divisor <= 0).any() or (variance < 0).any()
                or not np.allclose(mean, expanded_values.mean(axis=0), rtol=1e-10, atol=1e-10)
                or not np.allclose(variance, expected_variance, rtol=1e-10, atol=1e-10)
                or not np.allclose(divisor, np.where(variance == 0, 1, np.sqrt(variance)), rtol=1e-10, atol=1e-10)):
            raise ValueError("Saved scaler is inconsistent with original Train-only statistics")
        scaler = StandardScaler()
        scaler.mean_, scaler.var_, scaler.scale_ = mean, variance, divisor
        scaler.n_features_in_, scaler.n_samples_seen_ = len(expanded), len(values)
        payload = torch.load(io.BytesIO(content), map_location="cpu", weights_only=True)
        if (payload.get("architecture") != name or payload.get("seed") != 42
                or payload.get("configuration") != expected_parameters
                or payload.get("best_epoch") != info.get("best_epoch")
                or any(not torch.isfinite(v).all() for v in payload["model_state_dict"].values())):
            raise ValueError("Saved FT state differs from its selection metadata")
        model = build_tabular_model(name, expected_parameters)
        model.load_state_dict(payload["model_state_dict"], strict=True)
    elif name == "xgboost":
        model = create_model(name, seed=42)
        model.load_model(bytearray(content))
        model.set_params(n_jobs=configuration["cpu_threads"])
    elif name == "lightgbm":
        from lightgbm import Booster
        model = SimpleNamespace(booster_=Booster(model_str=content.decode("utf-8")))
    elif name == "catboost":
        from catboost import CatBoostClassifier
        model = CatBoostClassifier(thread_count=configuration["cpu_threads"])
        model.load_model(blob=content)
    elif name == "random_forest":
        model = joblib.load(io.BytesIO(content))
        model.set_params(n_jobs=configuration["cpu_threads"])
    else:
        raise ValueError("Unsupported saved tabular branch")
    return V3FoldModel(name, model, configuration["training"]["batch_size"], scaler, order, processor), info

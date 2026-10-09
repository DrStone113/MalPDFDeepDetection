"""Bounded, retrospective Train/Validation study; exposed Test sets stay sealed.

The existing v4 numeric input and four validation roles are reused unchanged.
This study trains the five static branches, not the frozen Vision branch. It
tests whether source/class/group balancing helps the small independent CIC
cohort; it cannot produce a new independent Test-performance claim.
"""
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import io
import json
from pathlib import Path
import platform
from time import perf_counter
import zipfile

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_curve
import torch
from torch.utils.data import DataLoader, TensorDataset, WeightedRandomSampler

from malpdf.data.kaggle_notebook import find_kaggle_bundle
from malpdf.deep_learning.models import build_tabular_model
from malpdf.deep_learning.training import set_deep_learning_seed, train_with_validation
from malpdf.evaluation.selective import calibration_metrics, fail_closed_routing
from malpdf.experiments.kaggle_vision_runner import _bytes, _json, load_bundle
from malpdf.experiments.multi_cohort_gpu import fold_preprocessing, predict_ft
from malpdf.models.late_fusion import _check_fitted_logistic, _logistic_state
from malpdf.models.safe_stacking import V3_BRANCHES
from malpdf.models.v3_base_learners import fit_v3_fold
from malpdf.reproducibility import set_random_seed

SCHEMES = ("uniform", "cohort_group_class")
ROLES = ("base_selection", "meta_fit", "calibration_fit", "threshold_selection")


def cohort_weights(rows, scheme, *, fit_partition):
    """Compute weights from only the supplied fitting partition, mean one.

    Balanced Train mass is equal per cohort and class, then per group within
    that cell. Mixed-label equivalence groups are preserved, never relabeled.
    Validation meta/calibration/Youden use equal cohort mass without changing
    within-cohort label prevalence. Selection metrics themselves are unweighted.
    """
    if (rows.empty or not rows.sample_id.is_unique or rows.group_id.isna().any()
            or not rows.Label.isin([0, 1]).all() or set(rows.cohort) != {"source_raw", "cic"}
            or fit_partition not in ("train", *ROLES)
            or scheme not in SCHEMES
            or not rows.split.eq("train" if fit_partition == "train" else "validation").all()):
        raise ValueError("Weights require complete aligned Train or declared Validation fitting rows")
    if fit_partition != "train" and not rows.role.eq(fit_partition).all():
        raise ValueError("Validation weights cannot mix fitting and selection roles")
    if scheme == "uniform":
        return np.ones(len(rows), dtype=float)
    if fit_partition == "base_selection":
        counts = rows.groupby(["cohort", "group_id"]).sample_id.transform("size")
        groups = rows.groupby("cohort").group_id.transform("nunique")
        result = 1.0 / (counts.to_numpy(float) * groups.to_numpy(float))
    elif fit_partition == "train":
        if any(set(group.Label) != {0, 1} for _, group in rows.groupby("cohort")):
            raise ValueError("Both classes are required in each Train cohort")
        counts = rows.groupby(["cohort", "Label", "group_id"]).sample_id.transform("size")
        groups = rows.groupby(["cohort", "Label"]).group_id.transform("nunique")
        result = 1.0 / (counts.to_numpy(float) * groups.to_numpy(float))
    else:
        result = 1.0 / rows.groupby("cohort").sample_id.transform("size").to_numpy(float)
    result /= result.mean()
    if not np.isfinite(result).all() or (result <= 0).any():
        raise ValueError("Invalid cohort weights")
    return result


def numeric_input(input_root, expected_metadata_sha256, destination):
    """Read the pinned small tables/code only; do not expand matrix caches."""
    if destination.exists() or any(p.is_symlink() for p in (destination, *destination.parents)):
        raise ValueError("Immutable numeric destination collision or symlink")
    expanded, archive = find_kaggle_bundle(input_root, expected_metadata_sha256)
    def materialize(read):
        metadata_bytes = read("bundle_metadata.json", 1024**2)
        if hashlib.sha256(metadata_bytes).hexdigest() != expected_metadata_sha256:
            raise ValueError("Numeric metadata checksum changed")
        metadata = json.loads(metadata_bytes)
        if metadata.get("raw_pdf_hashes_included") is not False:
            raise ValueError("Only the authorized opaque numeric bundle is permitted")
        members = {"bundle_metadata.json": metadata_bytes}
        for name, digest in metadata["file_sha256"].items():
            relative = Path(name)
            if (relative.is_absolute() or ".." in relative.parts or "\\" in name
                    or relative.suffix not in (".py", ".csv", ".json")):
                raise ValueError("Unexpected numeric/code input member")
            content = read(name, 16 * 1024**2 if relative.suffix == ".csv" else 1024**2)
            if hashlib.sha256(content).hexdigest() != digest:
                raise ValueError("Pinned input checksum differs")
            members[name] = content
        destination.mkdir(parents=True, exist_ok=False)
        for name, content in members.items():
            path = destination / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as handle:
                handle.write(content)
    if archive is None:
        materialize(lambda name, cap: _bytes(expanded, name, cap))
    else:
        with zipfile.ZipFile(archive) as handle:
            names = handle.namelist()
            if len(names) != len(set(names)):
                raise ValueError("Duplicate ZIP members")
            def read(name, cap):
                member = handle.getinfo(name)
                if (member.file_size > cap or member.flag_bits & 1
                        or member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                        or member.external_attr >> 16 & 0o170000 == 0o120000):
                    raise ValueError("Unsafe numeric ZIP member")
                with handle.open(member) as stream:
                    content = stream.read(cap + 1)
                if len(content) > cap:
                    raise ValueError("Numeric member exceeds cap")
                return content
            materialize(read)
    return destination


def development_tables(bundle_root):
    frame, roles, metadata = load_bundle(bundle_root)
    configuration = json.loads(_bytes(bundle_root, "v4_gpu_configuration.json", 1024**2))
    features = pd.read_csv(io.BytesIO(_bytes(bundle_root, "tabular_features.csv", 16 * 1024**2))).set_index("sample_id")
    folds = pd.read_csv(io.BytesIO(_bytes(bundle_root, "train_folds.csv", 16 * 1024**2)))
    reuse = pd.read_csv(io.BytesIO(_bytes(bundle_root, "source_matrix_reuse.csv", 16 * 1024**2)))
    if (not reuse.sample_id.is_unique or not set(reuse.sample_id) <= set(frame.sample_id)
            or len(reuse) != metadata["reused_source_matrices"]
            or not features.index.is_unique or set(features.index) != set(frame.sample_id)
            or list(features.columns) != configuration["feature_order"]
            or not folds.sample_id.is_unique or set(folds.fold) != {1, 2, 3, 4, 5}
            or set(folds.sample_id) != set(frame.loc[frame.split.eq("train"), "sample_id"])
            or not frame.parser_failed.isin([0, 1]).all()):
        raise ValueError("Portable feature, cohort or saved five-fold identities differ")
    # The reuse manifest already identifies the original source cohort. No new
    # source names, PDF hashes or private ID mappings are uploaded to Kaggle.
    frame["cohort"] = np.where(frame.sample_id.isin(reuse.sample_id), "source_raw", "cic")
    # Drop exposed Test rows before any preprocessing, weighting or model work.
    frame = frame.loc[frame.split.isin(["train", "validation"])].copy()
    features = features.loc[frame.sample_id].copy()
    frame = frame.merge(roles, on="sample_id", how="left", validate="one_to_one")
    train = frame.loc[frame.split.eq("train")].copy()
    validation = frame.loc[frame.split.eq("validation")].copy()
    assignments = folds.set_index("sample_id").loc[train.sample_id].fold.to_numpy()
    if train.assign(fold=assignments).groupby("group_id").fold.nunique().max() != 1:
        raise ValueError("Train groups cross the saved CV folds")
    for fold in range(1, 6):
        for position in (assignments == fold, assignments != fold):
            if set(train.loc[position].Label) != {0, 1}:
                raise ValueError("Train CV fitting/held-out folds need both classes")
    for role in ROLES:
        selected = validation.loc[validation.role.eq(role)]
        if set(selected.cohort) != {"source_raw", "cic"} or any(set(g.Label) != {0, 1} for _, g in selected.groupby("cohort")):
            raise ValueError("Every Validation role needs both classes in both cohorts")
    return train, validation, features, assignments, configuration, metadata


def _macro_metrics(rows, scores, threshold):
    per_cohort = {name: calibration_metrics(group.Label.to_numpy(int), scores[rows.cohort.eq(name).to_numpy()], threshold=threshold)
                  for name, group in rows.groupby("cohort")}
    return {"macro_mcc": float(np.mean([m["mcc"] for m in per_cohort.values()])),
            "macro_f1": float(np.mean([m["f1_malicious"] for m in per_cohort.values()])),
            "minimum_cohort_mcc": float(min(m["mcc"] for m in per_cohort.values())),
            "macro_brier": float(np.mean([m["brier"] for m in per_cohort.values()]))}


def fit_development_stack(rows, probabilities, scheme, regularization_cs):
    """Meta fit, Platt fit and model/Youden selection use disjoint saved roles."""
    values = np.asarray(probabilities, float)
    if (not rows.split.eq("validation").all() or not rows.sample_id.is_unique
            or rows.group_id.isna().any() or not rows.Label.isin([0, 1]).all()
            or set(rows.role) != set(ROLES) or rows.groupby("group_id").role.nunique().max() != 1
            or values.shape != (len(rows), len(V3_BRANCHES))
            or not np.isfinite(values).all() or (values < 0).any() or (values > 1).any()
            or not 1 <= len(regularization_cs) <= 3 or len(set(regularization_cs)) != len(regularization_cs)
            or any(not np.isfinite(c) or c <= 0 for c in regularization_cs)):
        raise ValueError("Only finite complete Validation probabilities and four disjoint roles are accepted")
    for role in ROLES:
        selected_rows = rows.loc[rows.role.eq(role)]
        if set(selected_rows.cohort) != {"source_raw", "cic"} or any(set(g.Label) != {0, 1} for _, g in selected_rows.groupby("cohort")):
            raise ValueError("Every Validation role requires both classes in both cohorts")
    set_random_seed(42)
    fit = rows.role.eq("meta_fit").to_numpy()
    calibrate = rows.role.eq("calibration_fit").to_numpy()
    select = rows.role.eq("threshold_selection").to_numpy()
    selection_rows = rows.loc[select]
    candidates, fitted = [], []
    for order, c in enumerate(regularization_cs):
        meta = LogisticRegression(C=c, solver="lbfgs", max_iter=1000, random_state=42)
        meta.fit(values[fit], rows.loc[fit].Label.to_numpy(int),
                 sample_weight=cohort_weights(rows.loc[fit], scheme, fit_partition="meta_fit"))
        _check_fitted_logistic(meta)
        platt = LogisticRegression(C=1.0, solver="lbfgs", max_iter=1000, random_state=42)
        platt.fit(meta.predict_proba(values[calibrate])[:, 1, None], rows.loc[calibrate].Label.to_numpy(int),
                  sample_weight=cohort_weights(rows.loc[calibrate], scheme, fit_partition="calibration_fit"))
        _check_fitted_logistic(platt)
        scores = platt.predict_proba(meta.predict_proba(values[select])[:, 1, None])[:, 1]
        fpr, tpr, thresholds = roc_curve(selection_rows.Label.to_numpy(int), scores,
            sample_weight=cohort_weights(selection_rows, scheme, fit_partition="threshold_selection"), drop_intermediate=False)
        youden = tpr - fpr
        finite = np.isfinite(thresholds) & (thresholds >= 0) & (thresholds <= 1)
        maximum = youden[finite].max()
        tied = [(float(t), _macro_metrics(selection_rows, scores, float(t)))
                for t, j in zip(thresholds[finite], youden[finite]) if abs(j - maximum) <= 1e-12]
        threshold, metrics = max(tied, key=lambda pair: (pair[1]["macro_mcc"], pair[1]["minimum_cohort_mcc"],
            pair[1]["macro_f1"], -abs(pair[0] - .5), pair[0]))
        candidate = {"scheme": scheme, "regularization_c": c, "candidate_order": order,
                     "threshold": threshold, "youden_j": float(maximum), **metrics}
        candidates.append(candidate)
        fitted.append((meta, platt, threshold))
    best = max(range(len(candidates)), key=lambda i: (candidates[i]["macro_mcc"], candidates[i]["minimum_cohort_mcc"],
        candidates[i]["macro_f1"], -candidates[i]["macro_brier"], -i))
    return fitted[best], candidates, candidates[best]


def train_static_development(bundle_root, output_root, configuration, code_commit, *, input_root=None):
    """Two fixed training strategies, five Train-group folds, no Test inference."""
    if not torch.cuda.is_available():
        raise RuntimeError("This development study requires the authorized Kaggle CUDA GPU")
    profiles = configuration.get("study_mode") == "markov_profiles"
    if (configuration.get("study_mode") not in (None, "markov_profiles")
            or configuration["seed"] != 42
            or tuple(configuration["schemes"]) != (("cohort_group_class",) if profiles else SCHEMES)
            or configuration["test_policy"] != "no_test_inference_or_metrics"
            or configuration["folds"] != 5 or configuration["ece_bins"] != 10):
        raise ValueError("Development configuration must preserve the locked bounded design")
    if profiles and (input_root is None or configuration.get("feature_variants") != ["structural", "structural_markov"]
                     or configuration.get("profile_workers") != 2):
        raise ValueError("Byte-profile study requires its paired feature design and existing numeric inputs")
    directory = output_root / ("run_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ_") + code_commit[:12])
    directory.mkdir(parents=True, exist_ok=False)
    started = perf_counter()
    state = {"status": "started", "seed": 42, "code_commit": code_commit, "test_evaluations": 0,
             "test_inference": 0, "completed_fits": [], "metrics_scope": "retrospective_validation_development"}
    results, routing_rows = [], []
    def event(**values):
        print(json.dumps({"utc": datetime.now(timezone.utc).isoformat(), **values}), flush=True)
    _json(directory / "locked_methodology.json", {**configuration, "code_commit": code_commit,
        "base_fit": "saved Train fitting folds only; Train-only preprocessing",
        "ft_checkpoint_selection": "equal cohort/group mass in new Validation base_selection loss" if profiles else "saved Validation base_selection loss only; unchanged unweighted loss",
        "validation_roles": "new diverse group-count allocation within existing Validation; original files unchanged" if profiles else "original saved allocation unchanged",
        "meta_fit": "Validation meta_fit", "platt_fit": "Validation calibration_fit",
        "candidate_and_youden_selection": "Validation threshold_selection only",
        "selection_tie_breaker": "macro-cohort MCC, minimum cohort MCC, macro F1, lower macro Brier, declared candidate order",
        "balanced_train": "equal cohort/class mass; inverse group multiplicity within each cohort/class; mean weight one",
        "balanced_validation": "equal cohort mass within each separate fitting/selection role",
        "ft_weighting": "seeded replacement sampling; unchanged BCE and batch/epoch budgets",
        "no_refit": True, "label_convention": "Label=1 malicious", "ece_convention": "10 equal-width bins; p=1 last bin",
        "vision": "existing ResNet unchanged; this is a five-branch static ablation, not a new tri-modal Test evaluation",
        "interpretation": "Previously exposed Test sets excluded. Validation improvements require a future independent cohort confirmation."})
    _json(directory / "environment_metadata.json", {"python": platform.python_version(),
        "packages": {name: importlib.metadata.version(name) for name in
            ("numpy", "pandas", "scikit-learn", "torch", "torchvision", "xgboost", "lightgbm", "catboost")},
        "cuda_version": torch.version.cuda, "gpu": torch.cuda.get_device_name(0),
        "precision": "FT CUDA FP16 AMP; trees CPU", "threads": 2})
    try:
        torch.set_num_threads(2)
        device = torch.device("cuda:0")
        train, val, features, assignments, base, metadata = development_tables(bundle_root)
        if hashlib.sha256(_bytes(bundle_root, "bundle_metadata.json", 1024**2)).hexdigest() != configuration["bundle_metadata_sha256"]:
            raise ValueError("Development input does not match the locked Kaggle bundle")
        cfg, original_order, missing = base["tabular"], base["feature_order"], base["metadata_features"]
        if profiles:
            from malpdf.data.development_inputs import diverse_validation_roles, load_development_profiles
            from malpdf.static.markov_profiles import MARKOV_PROFILE_FEATURES
            val = diverse_validation_roles(val)
            val.loc[:, ["sample_id", "role"]].to_csv(directory / "development_validation_roles.csv", index=False)
            measured = load_development_profiles(input_root, bundle_root, pd.concat([train, val]), metadata,
                                                  workers=configuration["profile_workers"])
            features = features.join(measured, validate="one_to_one")
            _json(directory / "byte_profile_lock.json", {"feature_order": list(MARKOV_PROFILE_FEATURES),
                "fit_required": False, "matrix_probabilities_modified": False, "test_matrices_read": 0,
                "profile_rows": len(measured), "profile_bytes": int(measured.to_numpy().nbytes),
                "scope": "conditional byte-structure descriptors; not exploit signatures"})
            equivalence = []
            for partition, frame in (("train", train), ("validation", val)):
                for cohort, cohort_rows in frame.groupby("cohort"):
                    for variant in configuration["feature_variants"]:
                        columns = original_order + (list(MARKOV_PROFILE_FEATURES) if variant == "structural_markov" else [])
                        vectors = pd.util.hash_pandas_object(features.loc[cohort_rows.sample_id, columns], index=False).to_numpy()
                        grouped = cohort_rows.assign(vector=vectors).groupby("vector").Label.agg(["count", "sum"])
                        mixed = (grouped["sum"] > 0) & (grouped["sum"] < grouped["count"])
                        equivalence.append({"partition": partition, "cohort": cohort, "variant": variant,
                            "rows": len(cohort_rows), "vectors": len(grouped), "mixed_vectors": int(mixed.sum()),
                            "mixed_vector_rows": int(grouped.loc[mixed, "count"].sum()),
                            "minority_label_rows": int(np.minimum(grouped["sum"], grouped["count"] - grouped["sum"]).sum()),
                            "identity_claim": "numeric profile equivalence only; hash grouping is not PDF identity"})
            pd.DataFrame(equivalence).to_csv(directory / "input_equivalence_comparison.csv", index=False)
        variants = configuration["feature_variants"] if profiles else [None]
        selection = val.loc[val.role.eq("base_selection")]
        _json(directory / "input_provenance.json", {"bundle_metadata_sha256": configuration["bundle_metadata_sha256"],
            "original_bundle_commit": metadata["code_commit"], "input_checksums": metadata["file_sha256"],
            "train_rows": len(train), "validation_rows": len(val), "features": list(features.columns),
            "cohort_train_rows": train.cohort.value_counts().to_dict(),
            "roles": [{"cohort": cohort, "role": role, "rows": len(g), "groups": g.group_id.nunique()}
                      for (cohort, role), g in val.groupby(["cohort", "role"])],
            "limitation": "New Validation-role design is retrospective development, not an independent Test." if profiles else "CIC base_selection has one mixed-label feature-equivalence group; its row count is not independent evidence."})
        fitted_stacks = []
        designs = [(scheme, variant) for scheme in configuration["schemes"] for variant in variants]
        for weighting, variant in designs:
            scheme = variant or weighting
            order = original_order + (list(MARKOV_PROFILE_FEATURES) if variant == "structural_markov" else [])
            inputs = features.loc[:, order]
            combined = np.zeros((len(val), len(V3_BRANCHES)), dtype=float)
            for fold in range(1, 6):
                fitting = train.loc[assignments != fold]
                weights = cohort_weights(fitting, weighting, fit_partition="train")
                for column, name in enumerate(V3_BRANCHES):
                    event(event="fit_started", scheme=scheme, fold=fold, model=name, fit_rows=len(fitting))
                    folder = directory / scheme / name / f"fold_{fold}"
                    fit_started = perf_counter()
                    if name != "ft_transformer":
                        model, info = fit_v3_fold(name, cfg, inputs.loc[fitting.sample_id], fitting.Label.to_numpy(int),
                            inputs.loc[selection.sample_id], selection.Label.to_numpy(int), folder,
                            feature_order=tuple(order), impute_metadata=True,
                            train_sample_weight=None if weighting == "uniform" else weights)
                        prediction = model.predict_proba(inputs.loc[val.sample_id])
                    else:
                        set_deep_learning_seed(42)
                        values = inputs.loc[fitting.sample_id].to_numpy(float)
                        selected = inputs.loc[selection.sample_id].to_numpy(float)
                        imputer, scaler, transform = fold_preprocessing(values, selected, order, missing)
                        training = cfg["training"]
                        selection_weights = cohort_weights(selection, weighting, fit_partition="base_selection") if profiles else None
                        def loader(x, y, *, fitting_loader=False, validation_weights=None):
                            sampler = WeightedRandomSampler(torch.from_numpy(weights), len(weights), replacement=True,
                                generator=torch.Generator().manual_seed(42)) if fitting_loader and weighting != "uniform" else None
                            tensors = (torch.from_numpy(x), torch.tensor(y.to_numpy(), dtype=torch.float32))
                            if validation_weights is not None:
                                tensors += (torch.from_numpy(validation_weights.astype(np.float32)),)
                            return DataLoader(TensorDataset(*tensors),
                                batch_size=training["batch_size"], shuffle=fitting_loader and sampler is None,
                                sampler=sampler, num_workers=1, pin_memory=True, persistent_workers=True,
                                multiprocessing_context="fork", prefetch_factor=1, generator=torch.Generator().manual_seed(42))
                        parameters = {**cfg["models"][name], "input_features": len(order) + len(missing)}
                        model = build_tabular_model(name, parameters)
                        result = train_with_validation(model, loader(transform(values), fitting.Label, fitting_loader=True),
                            loader(transform(selected), selection.Label, validation_weights=selection_weights), device=device, mixed_precision=True,
                            non_blocking=True, record_performance=True,
                            weighted_validation=profiles,
                            **{key: training[key] for key in ("learning_rate", "weight_decay", "max_epochs", "patience", "min_delta")},
                            progress=lambda e: event(scheme=scheme, fold=fold, model=name, **e))
                        model.load_state_dict(result.best_state_dict, strict=True)
                        folder.mkdir(parents=True, exist_ok=False)
                        with (folder / "model.pt").open("xb") as output:
                            torch.save({"model_state_dict": result.best_state_dict, "configuration": parameters,
                                        "best_epoch": result.best_epoch, "seed": 42}, output)
                        pd.DataFrame(result.history).to_csv(folder / "training_history.csv", index=False)
                        _json(folder / "preprocessing.json", {"fit_partition": "train_fitting_fold", "fit_rows": len(fitting),
                            "feature_order": order, "missing_features": missing, "imputer": imputer.statistics_.tolist(),
                            "scaler_mean": scaler.mean_.tolist(), "scaler_scale": scaler.scale_.tolist()})
                        info = {"best_epoch": result.best_epoch, "best_validation_loss": result.best_validation_loss,
                                "train_weight_sha256": hashlib.sha256(weights.astype("<f8").tobytes()).hexdigest()}
                        if profiles:
                            info["selection_weight_sha256"] = hashlib.sha256(selection_weights.astype("<f8").tobytes()).hexdigest()
                        prediction = predict_ft(model, transform(inputs.loc[val.sample_id].to_numpy(float)), device,
                                                training["batch_size"], amp=True)
                        del model
                        torch.cuda.empty_cache()
                    combined[:, column] += prediction / 5
                    elapsed = perf_counter() - fit_started
                    state["completed_fits"].append({"scheme": scheme, "fold": fold, "model": name,
                        "fit_rows": len(fitting), "seconds": elapsed, **info})
                    event(event="fit_completed", scheme=scheme, fold=fold, model=name, seconds=elapsed)
            table = val.loc[:, ["sample_id", "cohort", "Label", "role", "parser_failed"]].copy()
            for column, name in enumerate(V3_BRANCHES):
                table[name] = combined[:, column]
            table.to_csv(directory / f"{scheme}_validation_predictions.csv", index=False)
            fitted, candidates, selected = fit_development_stack(val, combined, weighting, configuration["regularization_cs"])
            selected = {**selected, "feature_variant": variant or "structural"}
            meta, platt, threshold = fitted
            _json(directory / f"{scheme}_stack_lock.json", {"selected": selected, "candidates": candidates,
                "meta": _logistic_state(meta), "platt": _logistic_state(platt), "threshold": threshold,
                "branches": list(V3_BRANCHES), "test_used": False})
            pd.DataFrame(candidates).to_csv(directory / f"{scheme}_selection_candidates.csv", index=False)
            calibrated = platt.predict_proba(meta.predict_proba(combined)[:, 1, None])[:, 1]
            table["stack_probability"] = calibrated
            table.to_csv(directory / f"{scheme}_validation_predictions_calibrated.csv", index=False)
            # Both fit-role diagnostics and candidate-selection diagnostics are
            # labelled honestly; no Validation role is an independent final Test.
            for role in ROLES:
                for cohort in ("source_raw", "cic"):
                    mask = val.role.eq(role) & val.cohort.eq(cohort)
                    rows = val.loc[mask]
                    for column, name in enumerate((*V3_BRANCHES, "static_stack")):
                        probabilities = combined[mask, column] if name != "static_stack" else calibrated[mask]
                        decision = .5 if name != "static_stack" else threshold
                        metrics = calibration_metrics(rows.Label.to_numpy(int), probabilities, threshold=decision)
                        results.append({"scheme": scheme, "model": name, "partition": f"validation_{role}_{cohort}",
                            "rows": len(rows), "groups": rows.group_id.nunique(), "threshold": decision,
                            **{key: metrics[key] for key in ("accuracy", "f1_malicious", "mcc", "brier", "log_loss", "ece")}})
                        if name == "static_stack":
                            routing, _ = fail_closed_routing(rows.Label.to_numpy(int), probabilities,
                                rows.sample_id.tolist(), rows.parser_failed.to_numpy(bool), threshold=decision)
                            routing_rows.append({"scheme": scheme, "partition": f"validation_{role}_{cohort}", **routing})
            fitted_stacks.append(selected)
        best = max(range(len(fitted_stacks)), key=lambda i: (fitted_stacks[i]["macro_mcc"],
            fitted_stacks[i]["minimum_cohort_mcc"], fitted_stacks[i]["macro_f1"], -fitted_stacks[i]["macro_brier"], -i))
        state.update(status="completed", selected=fitted_stacks[best], candidate_schemes=fitted_stacks)
        _json(directory / "selection_lock.json", {"selected": fitted_stacks[best], "test_inference": 0,
            "deployment": "development candidate only; existing production/research checkpoints unchanged"})
    except BaseException as error:
        state.update(status="interrupted" if isinstance(error, (KeyboardInterrupt, SystemExit)) else "failed",
                     error_type=type(error).__name__)
        _json(directory / "error.json", {"type": type(error).__name__, "message": str(error)})
        raise
    finally:
        state["elapsed_seconds"] = perf_counter() - started
        _json(directory / "run_summary.json", state)
        pd.DataFrame(results, columns=["scheme", "model", "partition", "rows", "groups", "threshold", "accuracy",
            "f1_malicious", "mcc", "brier", "log_loss", "ece"]).to_csv(directory / "model_comparison.csv", index=False)
        _json(directory / "routing_analysis.json", routing_rows)
        with (directory / "research_log.md").open("x") as log:
            log.write("| UTC | Run | Kind/status | Protocol/seed | Model | Partition | F1 malicious | MCC | ECE | Brier | Commit | Worktree | Evidence | Notes |\n")
            log.write("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n")
            for row in results or [{"model": "N/A", "partition": "N/A", "scheme": "N/A"}]:
                fields = [datetime.now(timezone.utc).isoformat(), directory.name, "static_development/" + state["status"],
                    "saved Protocol G / 42", row["scheme"] + ":" + row["model"], row["partition"],
                    *[row.get(k, "N/A") for k in ("f1_malicious", "mcc", "ece", "brier")], code_commit,
                    "sealed committed code", "model_comparison.csv", "Validation diagnostics only; Label=1 malicious; ECE 10 equal-width bins; Test untouched"]
                log.write("| " + " | ".join(map(str, fields)) + " |\n")
        _json(directory / "output_checksums.json", {str(p.relative_to(directory)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in directory.rglob("*") if p.is_file()})
    return directory

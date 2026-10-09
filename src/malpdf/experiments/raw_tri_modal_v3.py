"""Full raw-cohort training with validation-only stacking and one test pass."""

from __future__ import annotations

import hashlib
import io
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold
import torch
from torch.utils.data import DataLoader

from malpdf.data.raw_cohort import RAW_FEATURES, assert_group_partitions
from malpdf.data.rit_pdfmal_split import build_duplicate_group_ids
from malpdf.data.vision_dataset import MarkovCacheDataset, VisionSample, verify_vision_caches
from malpdf.deep_learning.training import probabilities_from_logits, set_deep_learning_seed, train_with_validation
from malpdf.evaluation.selective import binary_entropy, calibration_metrics, fail_closed_routing
from malpdf.experiments.protocol_p import repository_git_state
from malpdf.experiments.safe_stacking_v3 import validate_v3_configuration
from malpdf.experiments.vision_runner import _save_checkpoint
from malpdf.models.late_fusion import entropy_routing
from malpdf.models.safe_stacking import V3_BRANCHES, fit_validation_v3
from malpdf.models.v3_base_learners import METADATA_FEATURES, fit_v3_fold
from malpdf.models.vision_resnet import VisionResNet18
from malpdf.provenance.research_runs import ResearchRun, write_json
from malpdf.reproducibility import set_random_seed
from malpdf.static.safety import read_bounded_bytes
from malpdf.static.schema import PROTOCOL_G_DROPPED_CONSTANT_FEATURES

BRANCHES = (*V3_BRANCHES, "vision_resnet18")
ROLE_ORDER = ("base_selection", "meta_fit", "calibration_fit", "threshold_selection")


def validate_configuration(config):
    if not isinstance(config, dict) or set(config) != {"seed", "folds", "inputs", "cpu_threads", "models", "training", "meta_regularization_cs", "vision", "expected_samples"}:
        raise ValueError("Raw tri-modal configuration is incomplete")
    if set(config["inputs"]) != {"dataset", "split_manifest", "source_manifest", "all_features"}:
        raise ValueError("All four raw cohort files require checksum locks")
    base = {key: config[key] for key in ("seed", "folds", "cpu_threads", "models", "training", "meta_regularization_cs")}
    base["inputs"] = {key: config["inputs"][key] for key in ("dataset", "split_manifest", "source_manifest")}
    validate_v3_configuration(base, expected_input_features=len(RAW_FEATURES))
    extra = config["inputs"]["all_features"]
    if set(extra) != {"path", "sha256"} or not extra["path"].startswith("data/processed/") or len(extra["sha256"]) != 64:
        raise ValueError("Full feature inventory needs a processed-data checksum lock")
    expected = config["expected_samples"]
    if expected != {"labeled": 19958, "unlabeled": 4}:
        raise ValueError("The authorized raw cohort is 19958 labeled plus four unlabeled PDFs")
    vision = config["vision"]
    if not isinstance(vision, dict) or set(vision) != set(config["training"]):
        raise ValueError("Vision needs the same bounded training parameter schema")
    bounded = {**base, "training": vision}
    validate_v3_configuration(bounded, expected_input_features=len(RAW_FEATURES))
    if vision["batch_size"] > 64:
        raise ValueError("256-pixel ResNet training batches are capped at 64")


def _table(root, spec, *, keep_default_na=True):
    content = read_bounded_bytes(root / spec["path"], boundary=root / "data/processed", max_bytes=32 * 1024**2)
    if hashlib.sha256(content).hexdigest() != spec["sha256"]:
        raise ValueError("Raw-cohort input differs from its saved checksum lock")
    return pd.read_csv(io.BytesIO(content), keep_default_na=keep_default_na)


def load_locked_cohort(root, config):
    tables = {name: _table(root, spec, keep_default_na=name != "source_manifest") for name, spec in config["inputs"].items()}
    labeled, manifest, source, full = (tables[name] for name in ("dataset", "split_manifest", "source_manifest", "all_features"))
    required = {"sample_id", "Label", *RAW_FEATURES, "parser_failed"}
    if (set(labeled) != required or set(full) != required or len(labeled) != config["expected_samples"]["labeled"]
            or len(full) != sum(config["expected_samples"].values()) or len(source) != len(full)
            or any(not frame.sample_id.is_unique for frame in tables.values())
            or set(labeled.sample_id) != set(manifest.sample_id) or set(full.sample_id) != set(source.sample_id)):
        raise ValueError("Raw cohort count/schema/identity differs from the authorized lock")
    assert_group_partitions(manifest)
    for frame in (labeled, full):
        values = frame.loc[:, list(RAW_FEATURES)].to_numpy(float)
        lexical = [i for i, name in enumerate(RAW_FEATURES) if name not in METADATA_FEATURES]
        if (np.isinf(values).any() or np.isnan(values[:, lexical]).any()
                or not frame.parser_failed.isin([True, False]).all()
                or (np.isnan(values).any(axis=1) & ~frame.parser_failed.to_numpy(bool)).any()):
            raise ValueError("Only flagged unavailable metadata may remain missing")
        counts = frame.ObfuscationCount.to_numpy(float)
        ratio = (frame.JS + frame.JavaScript) / (1 + frame.obj)
        if (counts < 0).any() or not np.equal(counts, np.floor(counts)).all() or not np.allclose(frame.script_ratio, ratio, rtol=1e-14, atol=1e-15):
            raise ValueError("Actual security interactions violate their measurement definition")
    labeled = labeled.set_index("sample_id").loc[manifest.sample_id].reset_index()
    source_index = source.set_index("sample_id")
    full_index = full.set_index("sample_id")
    full_labeled = full_index.loc[labeled.sample_id].copy()
    full_labeled["Label"] = full_labeled.Label.astype(int)
    if (set(labeled.Label) != {0, 1} or not np.array_equal(labeled.Label, manifest.Label)
            or not np.array_equal(labeled.Label.astype(str), source_index.loc[labeled.sample_id].Label)
            or not labeled.set_index("sample_id").equals(full_labeled)):
        raise ValueError("Saved feature, PDF and split identities/labels disagree")
    unknown = full.loc[full.Label.isna()].copy().sort_values("sample_id", kind="stable")
    if len(unknown) != config["expected_samples"]["unlabeled"] or not source_index.loc[unknown.sample_id].Label.eq("").all():
        raise ValueError("Unknown samples must remain genuinely unlabeled")
    # Verify equivalence containment without regenerating the established split.
    vector = build_duplicate_group_ids(labeled.loc[:, [*RAW_FEATURES, "Label"]])
    audit = manifest.copy()
    audit["feature_vector"] = vector
    for name in ("pdf_sha256", "related_group_id"):
        audit[name] = source_index.loc[manifest.sample_id, name].to_numpy()
    for name in ("feature_vector", "pdf_sha256", "related_group_id"):
        if audit.groupby(name).duplicate_group_id.nunique().max() != 1:
            raise ValueError("An equivalent PDF/vector/related component crosses saved groups")
    if source.pdf_sha256.nunique() != len(source) or not all(sid == "public_pdf:" + digest for sid, digest in zip(source.sample_id, source.pdf_sha256)):
        raise ValueError("Raw identities require unique content hashes")
    return labeled, manifest.reset_index(drop=True), source_index, unknown


def safety_feature_order(train):
    """Only the three allowed columns can be removed, based on Train alone."""
    removed = tuple(name for name in PROTOCOL_G_DROPPED_CONSTANT_FEATURES if train[name].nunique(dropna=False) == 1)
    return tuple(name for name in RAW_FEATURES if name not in removed), removed


def group_folds(manifest, *, partition, count):
    if not manifest.split.eq(partition).all() or not manifest.sample_id.is_unique or manifest.duplicate_group_id.isna().any():
        raise ValueError("Fold/role assignment requires one unique locked partition")
    labels, groups = manifest.Label.to_numpy(), manifest.duplicate_group_id.to_numpy()
    folds = tuple(StratifiedGroupKFold(n_splits=count, shuffle=True, random_state=42).split(np.zeros((len(manifest), 1)), labels, groups))
    covered = np.zeros(len(manifest), int)
    for fit, held in folds:
        if set(groups[fit]) & set(groups[held]) or set(labels[fit]) != {0, 1} or set(labels[held]) != {0, 1}:
            raise ValueError("Each fitting/held role needs both classes and disjoint groups")
        covered[held] += 1
    if not np.all(covered == 1):
        raise ValueError("Every row must belong to exactly one held fold/role")
    return folds


def validation_roles(manifest):
    return {name: positions for name, (_, positions) in zip(ROLE_ORDER, group_folds(manifest, partition="validation", count=4))}


def _vision_samples(frame, sources):
    return [VisionSample(row.sample_id, int(row.Label) if pd.notna(row.Label) else None,
                         sources.loc[row.sample_id].pdf_sha256) for row in frame.itertuples()]


def _vision_loader(samples, cache, batch_size, *, shuffle=False, include_labels=True):
    return DataLoader(MarkovCacheDataset(samples, cache, include_labels=include_labels), batch_size=batch_size,
                      shuffle=shuffle, num_workers=0, generator=torch.Generator().manual_seed(42))


def vision_probabilities(model, loader, *, progress=None):
    model.eval()
    scores = []
    with torch.inference_mode():
        for batch in loader:
            features = batch[0] if isinstance(batch, (list, tuple)) else batch
            scores.append(probabilities_from_logits(model(features).reshape(-1)))
            if progress is not None and len(scores) % 50 == 0:
                progress(sum(len(value) for value in scores))
    result = np.concatenate(scores)
    if not np.isfinite(result).all():
        raise RuntimeError("Vision predictions are non-finite")
    return result


def run_raw_tri_modal(root, code_root, config, *, execute=False, run_id=None):
    """Fit only Train/validation and preserve evidence if any stage fails."""
    methodology = {"configuration": config, "scope": "New acquired raw cohort, historical RIT split unchanged",
        "train_policy": "Five group-aware train-only folds per tabular branch; Vision full Train from scratch, float32 channels-last CPU convolutions",
        "validation_policy": "Four group-disjoint roles: base stopping, meta fit, Platt fit, MCC/Youden selection; no refit",
        "missing_policy": "Raw nulls retained; native NaN boosting; RF/FT train-fold median plus fixed metadata flags",
        "referral_policy": "Always refer parser failures; entropy fills remaining 10% budget, allowing excess forced referrals",
        "test_policy": "One vector inference/evaluation after a persisted validation lock; fixed base threshold 0.5",
        "unlabeled_policy": "Four S3 samples inferred separately; no label invented, no metrics"}
    with ResearchRun(root, "raw_tri_modal_v3", methodology, code_root=code_root, run_id=run_id) as run:
        validate_configuration(config)
        if not execute:
            raise ValueError("Official training requires explicit --execute")
        if run.state["code_worktree"]["status"] != "clean":
            raise ValueError("Official training requires a clean committed code worktree")
        set_random_seed(42)
        torch.set_num_threads(config["cpu_threads"])
        labeled, manifest, sources, unknown = load_locked_cohort(root, config)
        run.state.update(inputs=config["inputs"], labeled_rows=len(labeled), unlabeled_rows=len(unknown),
                         partition_rows=manifest.split.value_counts().to_dict(), cuda_available=torch.cuda.is_available(), device="cpu")
        frames, manifests = {}, {}
        for partition in ("train", "validation", "test"):
            mask = manifest.split.eq(partition)
            frames[partition] = labeled.loc[mask].reset_index(drop=True)
            manifests[partition] = manifest.loc[mask].reset_index(drop=True)
        train, validation = frames["train"], frames["validation"]
        feature_order, dropped = safety_feature_order(train)
        roles = validation_roles(manifests["validation"])
        folds = group_folds(manifests["train"], partition="train", count=5)
        run.state.update(feature_order=list(feature_order), train_constant_exclusions=list(dropped), parser_failed_rows=int(labeled.parser_failed.sum()))
        write_json(run.report / "data_provenance.json", {"inputs": config["inputs"], "partition_rows": run.state["partition_rows"],
            "zero_partition_overlap": True, "group_strategy": "Feature vector/PDF hash/known related source union",
            "all_19958_labeled_retained": len(labeled) == 19958, "raw_nulls_preserved": True})
        role_frame = manifests["validation"].copy()
        role_frame["role"] = ""
        for name, positions in roles.items():
            role_frame.loc[positions, "role"] = name
        role_frame.to_csv(run.artifacts / "validation_roles.csv", index=False)
        models = {name: [] for name in V3_BRANCHES}
        val_scores = np.zeros((len(validation), len(BRANCHES)))
        oof = np.full((len(train), len(V3_BRANCHES)), np.nan)
        base_selection = validation.iloc[roles["base_selection"]]
        fit_metadata = []
        for column, name in enumerate(V3_BRANCHES):
            for fold, (fit, held) in enumerate(folds):
                run.progress("tabular_fold_started", model=name, fold=fold + 1, fit_rows=len(fit), held_rows=len(held))
                def notify(value):
                    value = dict(value)
                    event = value.pop("event")
                    run.progress(event, model=name, fold=fold + 1, **value)
                model, info = fit_v3_fold(name, config, train.iloc[fit].loc[:, list(feature_order)], train.Label.to_numpy()[fit],
                    base_selection.loc[:, list(feature_order)], base_selection.Label.to_numpy(),
                    run.artifacts / "tabular" / name / f"fold_{fold + 1}", feature_order=feature_order, impute_metadata=True, progress=notify)
                models[name].append(model)
                oof[held, column] = model.predict_proba(train.iloc[held].loc[:, list(feature_order)])
                val_scores[:, column] += model.predict_proba(validation.loc[:, list(feature_order)]) / len(folds)
                fit_metadata.append(info)
                run.progress("tabular_fold_completed", model=name, fold=fold + 1)
        if not np.isfinite(oof).all():
            raise RuntimeError("Every training row needs a finite held-fold probability")
        pd.DataFrame({"sample_id": train.sample_id, "Label": train.Label, **{name: oof[:, i] for i, name in enumerate(V3_BRANCHES)}}).to_csv(run.artifacts / "train_oof_predictions.csv", index=False)
        for i, name in enumerate(V3_BRANCHES):
            run.state["metrics"][name + "/train_oof"] = calibration_metrics(train.Label, oof[:, i])
        cache = root / "data/processed/markov_cache"
        # All cache identities are preverified; Test is not forwarded to a model.
        verified = verify_vision_caches(_vision_samples(labeled, sources) + _vision_samples(unknown, sources), cache)
        sample_map = {sample.sample_id: sample for sample in verified}
        samples = lambda frame: [sample_map[sid] for sid in frame.sample_id]
        vision_config = config["vision"]
        run.state["vision_determinism"] = set_deep_learning_seed(42)
        vision = VisionResNet18().to(memory_format=torch.channels_last)
        run.progress("vision_training_started", train_rows=len(train), base_selection_rows=len(base_selection), max_epochs=vision_config["max_epochs"])
        def vision_notify(value):
            value = dict(value)
            event = value.pop("event")
            run.progress(event, model="vision_resnet18", **value)
        outcome = train_with_validation(vision,
            _vision_loader(samples(train), cache, vision_config["batch_size"], shuffle=True),
            _vision_loader(samples(base_selection), cache, vision_config["batch_size"]), device=torch.device("cpu"),
            **{key: vision_config[key] for key in ("learning_rate", "weight_decay", "max_epochs", "patience", "min_delta")}, progress=vision_notify)
        checkpoint = run.artifacts / "vision_resnet18.pt"
        _save_checkpoint(checkpoint, {"model_state_dict": outcome.best_state_dict, "seed": 42, "architecture": "single_channel_resnet18",
                                     "best_epoch": outcome.best_epoch, "generating_commit": run.commit})
        reloaded = torch.load(checkpoint, map_location="cpu", weights_only=True)
        vision.load_state_dict(reloaded["model_state_dict"], strict=True)
        pd.DataFrame(outcome.history).to_csv(run.report / "vision_training_history.csv", index=False)
        run.state["vision"] = {"best_epoch": outcome.best_epoch, "best_validation_loss": outcome.best_validation_loss,
                               "training_seconds": outcome.training_seconds, "checkpoint": str(checkpoint.relative_to(root)),
                               "checkpoint_sha256": hashlib.sha256(checkpoint.read_bytes()).hexdigest()}
        val_scores[:, -1] = vision_probabilities(vision, _vision_loader(samples(validation), cache, vision_config["batch_size"]))
        pd.DataFrame({"sample_id": validation.sample_id, "Label": validation.Label,
                      **{name: val_scores[:, i] for i, name in enumerate(BRANCHES)}}).to_csv(run.artifacts / "validation_predictions.csv", index=False)
        stack, candidates = fit_validation_v3(manifests["validation"], val_scores, config["meta_regularization_cs"], branches=BRANCHES, roles=roles)
        pd.DataFrame(candidates).to_csv(run.report / "validation_candidates.csv", index=False)
        write_json(run.report / "validation_lock.json", {**stack.lock_metadata(), "feature_order": list(feature_order),
            "train_constant_exclusions": list(dropped), "vision": run.state["vision"], "base_fit_metadata": fit_metadata,
            "missing_policy": methodology["missing_policy"], "referral_policy": methodology["referral_policy"],
            "code_commit": run.commit, "inputs": config["inputs"], "test_evaluations_allowed": 1})
        selected = roles["threshold_selection"]
        run.state["metrics"]["stacking_v3/validation_threshold_selection"] = calibration_metrics(validation.Label.to_numpy()[selected], stack.predict_proba(val_scores[selected]), threshold=stack.threshold)
        run.progress("validation_locked", threshold=stack.threshold, regularization_c=stack.selection["regularization_c"], vision_best_epoch=outcome.best_epoch)
        # Exclusive marker precedes all Test inference. A rerun gets a new run,
        # never access to this invocation's Test through a mutable checkpoint.
        from malpdf.experiments.raw_tri_modal_resume import claim_test_evaluation
        claim_test_evaluation(root, config["inputs"], run.report,
                              hashlib.sha256((run.report / "validation_lock.json").read_bytes()).hexdigest())
        test = frames["test"]
        test_scores = np.column_stack([np.mean([model.predict_proba(test.loc[:, list(feature_order)]) for model in models[name]], axis=0) for name in V3_BRANCHES])
        test_vision = vision_probabilities(vision, _vision_loader(samples(test), cache, vision_config["batch_size"]), progress=lambda rows: run.progress("test_inference_progress", rows=rows, total=len(test)))
        test_scores = np.column_stack((test_scores, test_vision))
        fused = stack.predict_proba(test_scores)
        for i, name in enumerate(BRANCHES):
            run.state["metrics"][name + "/test"] = calibration_metrics(test.Label, test_scores[:, i])
        run.state["metrics"]["stacking_v3/test"] = calibration_metrics(test.Label, fused, threshold=stack.threshold)
        run.state["test_evaluation_count"] = 1
        pure, _ = entropy_routing(test.Label, fused, test.sample_id, threshold=stack.threshold)
        closed, referred = fail_closed_routing(test.Label, fused, test.sample_id, test.parser_failed, threshold=stack.threshold)
        routing = [pure, closed]
        write_json(run.report / "routing_analysis.json", routing)
        pd.DataFrame([{key: value for key, value in row.items() if key != "retained_metrics"} for row in routing]).to_csv(run.report / "routing_analysis.csv", index=False)
        for row in routing:
            run.state["metrics"]["stacking_v3/test_retained_" + row["policy"]] = row["retained_metrics"]
        pd.DataFrame({"sample_id": test.sample_id, "Label": test.Label,
            **{name: test_scores[:, i] for i, name in enumerate(BRANCHES)}, "p_fused": fused,
            "parser_failed": test.parser_failed, "referred": referred,
            "static_decision": np.where(referred, "abstain", np.where(fused >= stack.threshold, "malicious", "benign"))}).to_csv(run.artifacts / "test_predictions.csv", index=False)
        write_json(run.report / "test_metrics.json", {key: value for key, value in run.state["metrics"].items() if "/test" in key})
        unknown_scores = np.column_stack([np.mean([model.predict_proba(unknown.loc[:, list(feature_order)]) for model in models[name]], axis=0) for name in V3_BRANCHES])
        unknown_scores = np.column_stack((unknown_scores, vision_probabilities(vision, _vision_loader(samples(unknown), cache, vision_config["batch_size"], include_labels=False))))
        unknown_fused = stack.predict_proba(unknown_scores)
        # The four-row batch cannot estimate a population entropy percentile;
        # retain parser-forced referrals and expose entropy for manual review.
        unknown_entropy = binary_entropy(unknown_fused) / np.log(2.0)
        pd.DataFrame({"sample_id": unknown.sample_id, "Label": [None] * len(unknown),
                      **{name: unknown_scores[:, i] for i, name in enumerate(BRANCHES)}, "p_fused": unknown_fused,
                      "entropy_bits": unknown_entropy, "parser_failed": unknown.parser_failed,
                      "static_decision": np.where(unknown.parser_failed, "abstain", np.where(unknown_fused >= stack.threshold, "malicious", "benign"))}).to_csv(run.artifacts / "unlabeled_predictions.csv", index=False)
        run.state.update(routing=routing, threshold=stack.threshold,
                         notes="One locked Test evaluation; all 19958 labeled rows retained. Native tree NaNs; RF/FT train-fold imputation with metadata flags. Parser failures force referral. Four unlabeled S3 predictions have no performance metrics.")
        run.state["metrics"]["stacking_v3/unlabeled_prediction"] = {}
        run.progress("experiment_completed", test_rows=len(test), metrics=run.state["metrics"]["stacking_v3/test"], coverage=closed["coverage"])
    return run.state

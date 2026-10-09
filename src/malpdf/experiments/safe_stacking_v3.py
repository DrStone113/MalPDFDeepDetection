"""Immutable Safety-First v3: real PDF measurements and five-fold train ensembles."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import importlib.metadata
from io import BytesIO
import json
from pathlib import Path
import platform
import stat

import numpy as np
import pandas as pd
import torch
import yaml

from malpdf.data.rit_pdfmal import load_rit_pdfmal, sha256_file
from malpdf.data.rit_pdfmal_split import build_deterministic_sample_ids
from malpdf.data.vision_dataset import align_protocol_g_samples, load_vision_source_manifest, vision_validation_groups
from malpdf.evaluation.selective import calibration_metrics
from malpdf.experiments.late_fusion_runner import _input_bytes, _input_spec
from malpdf.experiments.protocol_g_benchmark import load_saved_protocol_g_split
from malpdf.experiments.protocol_p import repository_git_state
from malpdf.experiments.selective_static_ensemble import _current_commit_sha
from malpdf.experiments.vision_runner import _write_json
from malpdf.models.late_fusion import entropy_routing
from malpdf.models.safe_stacking import (
    INTERACTIONS, V3_BRANCHES, V3_FEATURES, fit_validation_v3, safe_feature_view, train_cv_folds, v3_validation_roles,
)
from malpdf.models.v3_base_learners import fit_v3_fold
from malpdf.static.obfuscation import MAX_PDF_BYTES, measure_pdf_obfuscation
from malpdf.static.safety import read_bounded_bytes
from malpdf.static.schema import PROTOCOL_G_DROPPED_CONSTANT_FEATURES


def validate_v3_configuration(config: dict, *, expected_input_features=40) -> None:
    if not isinstance(config, dict) or set(config) != {"seed", "folds", "inputs", "cpu_threads", "models", "training", "meta_regularization_cs"}:
        raise ValueError("Safety-first v3 configuration is incomplete")
    if type(config["seed"]) is not int or config["seed"] != 42 or type(config["folds"]) is not int or config["folds"] != 5:
        raise ValueError("V3 locks Protocol G seed=42 and five group-aware train folds")
    if not isinstance(config["inputs"], dict) or set(config["inputs"]) != {"dataset", "split_manifest", "source_manifest"}:
        raise ValueError("V3 needs locked dataset, saved split, and real PDF source manifest")
    for spec in config["inputs"].values():
        _input_spec(spec)
        if not spec["path"].startswith("data/processed/"):
            raise ValueError("V3 manifests and feature tables must stay in processed data")
    if type(config["cpu_threads"]) is not int or not 1 <= config["cpu_threads"] <= 8:
        raise ValueError("V3 requires bounded CPU threads")
    models = config["models"]
    expected = {
        "xgboost": {"n_estimators", "max_depth", "learning_rate"},
        "lightgbm": {"n_estimators", "num_leaves", "learning_rate", "min_child_samples", "reg_lambda"},
        "catboost": {"iterations", "depth", "learning_rate", "l2_leaf_reg"},
        "random_forest": {"n_estimators", "max_depth", "min_samples_leaf"},
        "ft_transformer": {"input_features", "d_token", "n_blocks", "n_heads", "d_ffn", "attention_dropout", "ffn_dropout"},
    }
    if not isinstance(models, dict) or tuple(models) != V3_BRANCHES:
        raise ValueError("V3 requires exactly the five declared base model families/order")
    for name, keys in expected.items():
        if not isinstance(models[name], dict) or set(models[name]) != keys:
            raise ValueError("Base parameters must follow the explicit bounded v3 schema")
        for key, value in models[name].items():
            if key == "max_depth" and name == "random_forest" and value is None:
                continue
            if type(value) not in (int, float) or not np.isfinite(value):
                raise ValueError("Base parameters must be finite bounded numbers")
            if key in {"n_estimators", "iterations"} and (type(value) is not int or not 1 <= value <= 1000):
                raise ValueError("Tree count is outside the resource cap")
            if key in {"max_depth", "depth", "n_blocks", "n_heads", "input_features", "num_leaves", "min_child_samples", "min_samples_leaf", "d_token", "d_ffn"} and (type(value) is not int or not 1 <= value <= 512):
                raise ValueError("Architecture/tree sizes must be positive bounded integers")
            if key == "learning_rate" and not 0 < value <= 1 or key in {"attention_dropout", "ffn_dropout"} and not 0 <= value <= 0.5 or key in {"reg_lambda", "l2_leaf_reg"} and not 0 <= value <= 100:
                raise ValueError("Base training rates/regularization/dropout exceed their bounds")
    ft = models["ft_transformer"]
    if ft["input_features"] != expected_input_features or ft["n_blocks"] > 4 or ft["d_token"] > 128 or ft["n_heads"] > 8 or ft["d_token"] % ft["n_heads"] or models["catboost"]["depth"] > 10 or models["xgboost"]["max_depth"] > 16 or (models["random_forest"]["max_depth"] or 1) > 32:
        raise ValueError("V3 architectures must retain the declared safety feature inputs within compute caps")
    training = config["training"]
    if not isinstance(training, dict) or set(training) != {"batch_size", "max_epochs", "patience", "learning_rate", "weight_decay", "min_delta"}:
        raise ValueError("V3 FT training configuration is incomplete")
    for key, cap in (("batch_size", 1024), ("max_epochs", 150), ("patience", 150)):
        if type(training[key]) is not int or not 1 <= training[key] <= cap:
            raise ValueError("FT training limits must be positive bounded integers")
    for key in ("learning_rate", "weight_decay", "min_delta"):
        if type(training[key]) not in (int, float) or not np.isfinite(training[key]) or not 0 <= training[key] <= 1:
            raise ValueError("FT training rates/deltas must be finite and bounded")
    if not training["learning_rate"]:
        raise ValueError("FT learning rate must be positive")
    cs = config["meta_regularization_cs"]
    if not isinstance(cs, list) or not 1 <= len(cs) <= 16 or len(set(cs)) != len(cs) or any(type(c) not in (int, float) or not np.isfinite(c) or not 0 < c <= 1000 for c in cs):
        raise ValueError("V3 meta C grid must be a short unique bounded positive list")


def load_v3_configuration(root: Path, path: Path) -> dict:
    config = yaml.safe_load(read_bounded_bytes(path, boundary=root / "configs", max_bytes=128 * 1024))
    validate_v3_configuration(config)
    return config


class PdfSources:
    """Exact source mapping and deferred byte measurement, never PDF execution."""

    def __init__(self, root: Path, spec: dict, manifest: pd.DataFrame):
        self.root = root
        content = _input_bytes(root, spec)
        samples = load_vision_source_manifest(root, root / spec["path"], spec["sha256"])
        _, self.readiness = align_protocol_g_samples(samples, manifest)
        self.measured_partitions = set()
        self.measurements = []
        if not self.readiness["ready"]:
            self.readiness["reason"] = "Measured ObfuscationCount requires real PDF bytes for every Protocol G ID; no proxy, constant fill, foreign cohort or inferred file identity is permitted"
            return
        self.groups = vision_validation_groups(samples, manifest)
        self.rows = pd.read_csv(BytesIO(content)).set_index("sample_id").to_dict("index")
        for row in self.rows.values():
            path = root / row["pdf_relative_path"]
            if not row["pdf_relative_path"].startswith(("data/raw/", "data/processed/")) or any(part.is_symlink() for part in (path, *path.parents)):
                raise ValueError("PDF measurement source must stay under local data without symlinks")
            info = path.stat()
            if not stat.S_ISREG(info.st_mode) or not 5 <= info.st_size <= MAX_PDF_BYTES:
                raise ValueError("PDF source must be a regular file within the 10 MiB cap")
        self.readiness["pdf_paths_verified"] = len(self.rows)

    def measured_frame(self, source: pd.DataFrame, manifest: pd.DataFrame, partition: str, lock: Path) -> pd.DataFrame:
        if not self.readiness["ready"] or partition in self.measured_partitions or not manifest.split.eq(partition).all():
            raise ValueError("PDF measurements require one eligible Protocol G partition")
        if partition == "test" and not lock.is_file():
            raise ValueError("Test PDF feature measurement requires the persisted validation lock")
        self.measured_partitions.add(partition)
        frame = source.loc[manifest.sample_id].reset_index(drop=True).copy()
        counts, by_hash = [], {}
        for identifier in manifest.sample_id:
            row = self.rows[identifier]
            digest = row["pdf_sha256"]
            # Verify every file path even when identical hashes repeat; a second
            # source file cannot inherit a checksum check from another path.
            path = self.root / row["pdf_relative_path"]
            result = measure_pdf_obfuscation(path, boundary=self.root / "data", expected_sha256=digest)
            if digest in by_hash and result != by_hash[digest]:
                raise ValueError("Identical source PDF hashes produced inconsistent measurements")
            by_hash[digest] = result
            counts.append(result["ObfuscationCount"])
            self.measurements.append({"sample_id": identifier, "partition": partition, "pdf_sha256": digest, **result})
        frame["ObfuscationCount"] = counts
        return frame


def _log_v3(root: Path, report: dict) -> None:
    rows = report["metrics"].items() if report["metrics"] else [("safe_stacking_v3/N/A", {})]
    notes = "Label=1 malicious; ECE=10 equal-width malicious-probability bins. Exactly Acroform/Colors/BaseEncoding excluded after train-only zero-variance checks; all remaining source features preserved. script_ratio=(JS+JavaScript)/(1+obj); ObfuscationCount measured from SHA-verified raw PDF escaped name tokens (#HH), never a proxy. Train-only five-fold feature/PDF/family-group CV; no CV-based hyperparameter tuning. Disjoint validation base-selection/meta-fit/Platt-fit/Youden-threshold-selection (~25% each); candidate C selection MCC then malicious F1 then declared order; no refit. Test once after persisted lock; fixed entropy 10% referrals never executed/corrected."
    if not report["metrics"]:
        notes += " Metrics N/A: preflight/failure; no evaluated partition."
    if report.get("error"):
        notes += f" Reason: {report['error']['message']}."
    with (root / "reports/research_log.md").open("a", encoding="utf-8") as output:
        for key, metrics in rows:
            fields = [report["finished_at_utc"], report["run_id"], f"safe stacking v3 {report['mode']} / {report['status']}", "G / 42",
                      *key.split("/", 1), *[metrics.get(name, "N/A") for name in ("f1_malicious", "mcc", "ece", "brier")],
                      f"`{report['code_commit_sha']}`", report["git_worktree"]["status"], f"`{report['report_path']}`", notes]
            output.write("| " + " | ".join(str(value).replace("|", "\\|").replace("\n", " ") for value in fields) + " |\n")


def run_safe_stacking_v3(root: Path, config: dict, *, execute: bool = False, run_id: str | None = None) -> dict:
    validate_v3_configuration(config)
    if type(execute) is not bool:
        raise ValueError("execute must be an explicit boolean")
    root = Path(root).resolve()
    commit, git_state = _current_commit_sha(root), repository_git_state(root)
    identifier = run_id or f"run_{datetime.now(timezone.utc):%Y%m%dT%H%M%S%fZ}_{commit[:12]}"
    if not identifier or any(value not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for value in identifier):
        raise ValueError("Unsafe v3 run identifier")
    directory, artifacts = (root / base / "safe_stacking_v3" / identifier for base in ("reports/experiments", "artifacts"))
    for path in (directory, artifacts):
        if path.exists() or any(part.is_symlink() for part in (path, *path.parents)):
            raise ValueError("V3 run directory exists or contains a symbolic link")
    directory.mkdir(parents=True, exist_ok=False)
    artifacts.mkdir(parents=True, exist_ok=False)
    report = {"run_id": identifier, "mode": "execute" if execute else "dry_run", "status": "started", "code_commit_sha": commit,
              "git_worktree": git_state, "started_at_utc": datetime.now(timezone.utc).isoformat(),
              "report_path": str((directory / "run_summary.json").relative_to(root)), "artifact_directory": str(artifacts.relative_to(root)),
              "metrics": {}, "test_evaluation_count": 0, "completed_base_fits": 0}
    previous_threads = torch.get_num_threads()
    sources = None
    try:
        _write_json(directory / "locked_methodology.json", {"configuration": config, "seed": 42, "folds": 5,
                    "features": list(V3_FEATURES), "only_dropped_features": list(PROTOCOL_G_DROPPED_CONSTANT_FEATURES),
                    "feature_interactions": INTERACTIONS, "obfuscation_scope": "Lexical escaped-name occurrences in raw PDF bytes, including strings/comments/streams; no inflation or active-object claim",
                    "validation": "Disjoint group-aware base-selection/meta-fit/calibration-fit/threshold-selection ~25% each",
                    "cv_policy": "Train only; feature/PDF/family-group stratified five folds, OOF descriptive only; no train-CV tuning",
                    "base_prediction_policy": "Equal mean of the five fold models for each family; no full-train refit",
                    "meta_policy": "Logistic stacking meta-fit only; Platt calibration-fit only; C selection by threshold-selection MCC/F1/order",
                    "threshold_policy": "Youden J only on threshold-selection; tied J -> MCC/F1/closest 0.5/larger threshold",
                    "test_policy": "No test PDF measurement or inference before persisted validation_lock.json; evaluate once",
                    "routing": "Fixed top 10% binary entropy in bits; ties by sample ID; abstentions only",
                    "ece": "10 equal-width malicious-probability bins; p=1 in last bin", "code_commit_sha": commit})
        _write_json(directory / "environment_metadata.json", {"python": platform.python_version(),
                    "packages": {name: importlib.metadata.version(name) for name in ("malpdf", "numpy", "pandas", "scikit-learn", "torch", "xgboost", "lightgbm", "catboost")},
                    "cpu_threads": config["cpu_threads"], "code_commit_sha": commit, "git_worktree": git_state,
                    "code_sha256": {name: sha256_file(root / name) for name in ("pyproject.toml", "configs/safe_stacking_v3.yaml", "scripts/06_optimize_and_stack_v3_safe.py", "src/malpdf/experiments/safe_stacking_v3.py", "src/malpdf/models/safe_stacking.py", "src/malpdf/models/v3_base_learners.py", "src/malpdf/static/obfuscation.py", "src/malpdf/evaluation/selective.py", "src/malpdf/models/late_fusion.py") if (root / name).is_file()}})
        inputs = config["inputs"]
        _input_bytes(root, inputs["dataset"])
        _input_bytes(root, inputs["split_manifest"])
        frame = load_rit_pdfmal(root / inputs["dataset"]["path"])
        _, manifest, split = load_saved_protocol_g_split(frame, inputs["dataset"]["sha256"], root, seed=42, manifest_path=root / inputs["split_manifest"]["path"])
        if sha256_file(root / inputs["dataset"]["path"]) != inputs["dataset"]["sha256"] or split["split_manifest_sha256"] != inputs["split_manifest"]["sha256"]:
            raise ValueError("Protocol G inputs changed during v3 preflight")
        sources = PdfSources(root, inputs["source_manifest"], manifest)
        report["pdf_readiness"] = sources.readiness
        _write_json(directory / "data_provenance.json", {"inputs": inputs, "split_validation": split["hard_validation"], "pdf_readiness": sources.readiness,
                    "raw_pdf_bytes_read_during_preflight": 0, "test_used_for_selection": False})
        if not sources.readiness["ready"]:
            report.update(status="blocked_missing_pdf_source", official_execution_ready=False,
                          error={"type": "MissingRealProtocolGPdfs", "message": sources.readiness["reason"]})
            return report
        source = frame.copy()
        source["sample_id"] = build_deterministic_sample_ids(frame).astype(str)
        source = source.set_index("sample_id")
        parts = {name: manifest.loc[manifest.split.eq(name)].sort_values("sample_id", kind="stable").reset_index(drop=True) for name in ("train", "validation", "test")}
        for part in parts.values():
            part["duplicate_group_id"] = part.sample_id.map(sources.groups)
        roles, folds = v3_validation_roles(parts["validation"]), train_cv_folds(parts["train"])
        report["validation_role_rows"] = {name: len(pos) for name, pos in roles.items()}
        report["fold_rows"] = [{"fit": len(fit), "held": len(held)} for fit, held in folds]
        if any(source.loc[parts["train"].sample_id, name].nunique() != 1 for name in PROTOCOL_G_DROPPED_CONSTANT_FEATURES):
            raise ValueError("The only permitted excluded features must have zero variance on train")
        if not execute:
            report.update(status="dry_run_completed", official_execution_ready=git_state["status"] == "clean")
            return report
        if git_state["status"] != "clean" or len(commit) != 40:
            raise ValueError("Official v3 training/evaluation requires a clean committed worktree")
        torch.set_num_threads(config["cpu_threads"])
        lock_path = directory / "validation_lock.json"
        train_raw = sources.measured_frame(source, parts["train"], "train", lock_path)
        validation_raw = sources.measured_frame(source, parts["validation"], "validation", lock_path)
        train_x = safe_feature_view(train_raw, check_training_constants=True)
        validation_x = safe_feature_view(validation_raw)
        train_y, validation_y = parts["train"].Label.to_numpy(), parts["validation"].Label.to_numpy()
        oof = np.full((len(train_x), len(V3_BRANCHES)), np.nan)
        val_scores = np.zeros((len(validation_x), len(V3_BRANCHES)))
        models, fit_evidence, cv_rows = {name: [] for name in V3_BRANCHES}, [], []
        assignments = np.full(len(train_x), -1)
        role_by_position = {int(index): name for name, positions in roles.items() for index in positions}
        pd.DataFrame({"sample_id": parts["validation"].sample_id, "role": [role_by_position[index] for index in range(len(validation_x))]}).to_csv(artifacts / "validation_roles.csv", index=False)
        selected = roles["base_selection"]
        for fold, (fitting, held) in enumerate(folds):
            assignments[held] = fold
            fit_x = safe_feature_view(train_raw.iloc[fitting], check_training_constants=True)
            for column, name in enumerate(V3_BRANCHES):
                model, info = fit_v3_fold(name, config, fit_x, train_y[fitting], validation_x.iloc[selected], validation_y[selected],
                                           artifacts / f"fold_{fold}" / name)
                models[name].append(model)
                oof[held, column] = model.predict_proba(train_x.iloc[held])
                val_scores[:, column] += model.predict_proba(validation_x) / 5
                info["checkpoint"] = str(Path(info["checkpoint"]).relative_to(root))
                fit_evidence.append({"fold": fold, **info})
                measured = calibration_metrics(train_y[held], oof[held, column], n_bins=10)
                cv_rows.append({"fold": fold, "model": name, **{metric: measured[metric] for metric in ("accuracy", "f1_malicious", "mcc", "brier", "log_loss", "ece")}})
                report["completed_base_fits"] += 1
                _write_json(directory / f"fold_{fold}_{name}.json", {"fold": fold, **info})
        if not np.isfinite(oof).all() or report["completed_base_fits"] != 25:
            raise RuntimeError("All 25 train-only base fits and OOF scores must complete")
        pd.DataFrame({"sample_id": parts["train"].sample_id, "fold": assignments}).to_csv(artifacts / "fold_assignments.csv", index=False)
        pd.DataFrame(cv_rows).to_csv(directory / "cv_fold_metrics.csv", index=False)
        for column, name in enumerate(V3_BRANCHES):
            report["metrics"][f"{name}/train_oof_descriptive"] = calibration_metrics(train_y, oof[:, column], n_bins=10)
        for partition, cohort, scores in (("train_oof", parts["train"], oof), ("validation", parts["validation"], val_scores)):
            pd.DataFrame({"sample_id": cohort.sample_id, "true_label": cohort.Label, **{name: scores[:, column] for column, name in enumerate(V3_BRANCHES)}}).to_parquet(artifacts / f"{partition}_probabilities.parquet", index=False)
        stack, selection = fit_validation_v3(parts["validation"], val_scores, config["meta_regularization_cs"])
        pd.DataFrame(selection).to_csv(directory / "selection_results.csv", index=False)
        _write_json(lock_path, {**stack.lock_metadata(), "locked_at_utc": datetime.now(timezone.utc).isoformat(), "test_evaluations_before_lock": 0,
                    "input_checksums": inputs, "base_fit_evidence": fit_evidence, "feature_order": list(V3_FEATURES), "feature_interactions": INTERACTIONS})
        positions = roles["threshold_selection"]
        for column, name in enumerate(V3_BRANCHES):
            report["metrics"][f"{name}/validation_threshold_selection"] = calibration_metrics(validation_y[positions], val_scores[positions, column], n_bins=10)
        report["metrics"]["safe_stacking_v3/validation_threshold_selection"] = calibration_metrics(validation_y[positions], stack.predict_proba(val_scores)[positions], threshold=stack.threshold, n_bins=10)
        # First actual test feature measurement/inference follows the persisted lock.
        test_raw = sources.measured_frame(source, parts["test"], "test", lock_path)
        test_x, test_y = safe_feature_view(test_raw), parts["test"].Label.to_numpy()
        test_scores = np.column_stack([np.mean([model.predict_proba(test_x) for model in models[name]], axis=0) for name in V3_BRANCHES])
        fused = stack.predict_proba(test_scores)
        for column, name in enumerate(V3_BRANCHES):
            report["metrics"][f"{name}/test"] = calibration_metrics(test_y, test_scores[:, column], n_bins=10)
        report["metrics"]["safe_stacking_v3/test"] = calibration_metrics(test_y, fused, threshold=stack.threshold, n_bins=10)
        report["test_evaluation_count"] = 1
        routing, referred = entropy_routing(test_y, fused, tuple(parts["test"].sample_id), threshold=stack.threshold)
        report["routing"] = routing
        report["metrics"]["safe_stacking_v3/test_retained"] = routing["retained_metrics"]
        row = {key: ("N/A" if value is None else value) for key, value in routing.items() if key != "retained_metrics"}
        row.update({f"retained_{key}": routing["retained_metrics"][key] for key in ("accuracy", "f1_malicious", "mcc", "brier", "log_loss", "ece")})
        pd.DataFrame([row]).to_csv(directory / "routing_analysis.csv", index=False)
        pd.DataFrame({"sample_id": parts["test"].sample_id, "true_label": test_y, "ensemble_probability": fused, "threshold": stack.threshold, "referred": referred,
                      **{name: test_scores[:, column] for column, name in enumerate(V3_BRANCHES)}}).to_parquet(artifacts / "test_predictions.parquet", index=False)
        report["selection"] = stack.selection
        _write_json(directory / "metrics.json", report["metrics"])
        report["status"] = "completed"
    except BaseException as error:
        report["status"] = "interrupted" if isinstance(error, KeyboardInterrupt) else "failed"
        report["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        torch.set_num_threads(previous_threads)
        if sources is not None and sources.measurements:
            pd.DataFrame(sources.measurements).to_csv(artifacts / "measured_obfuscation.csv", index=False)
        report["finished_at_utc"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        with (directory / "model_comparison.csv").open("x", newline="", encoding="utf-8") as output:
            names = ["model", "partition", "accuracy", "f1_malicious", "mcc", "brier", "log_loss", "ece", "threshold"]
            writer = csv.writer(output, lineterminator="\n")
            writer.writerow(names)
            for key, metrics in (report["metrics"].items() or [("safe_stacking_v3/N/A", {})]):
                writer.writerow([*key.split("/", 1), *[metrics.get(name, "N/A") for name in names[2:]]])
        if not (directory / "routing_analysis.csv").exists():
            pd.DataFrame([{"policy": "top_entropy_10_percent", "coverage": "N/A", "fn_catch_rate": "N/A", "status": report["status"],
                           "reason": report.get("error", {}).get("message", "No independent test evaluation")}]).to_csv(directory / "routing_analysis.csv", index=False)
        _write_json(directory / "run_summary.json", report)
        _log_v3(root, report)
    return report

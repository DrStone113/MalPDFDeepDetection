"""Immutable Protocol G v2 evaluation from checksum-locked base probabilities."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
from io import BytesIO
import importlib.metadata
import json
from pathlib import Path
import platform
import stat

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import yaml

from malpdf.data.manifest_validator import validate_sha256
from malpdf.data.rit_pdfmal import load_rit_pdfmal, sha256_file
from malpdf.data.vision_dataset import align_protocol_g_samples, load_vision_source_manifest
from malpdf.evaluation.selective import calibration_metrics
from malpdf.experiments.protocol_g_benchmark import load_saved_protocol_g_split
from malpdf.experiments.protocol_p import repository_git_state
from malpdf.experiments.selective_static_ensemble import _current_commit_sha, _safe_id
from malpdf.experiments.vision_runner import _write_json
from malpdf.models.late_fusion import (
    BASE_BRANCHES, VISION_BRANCHES, FusionPartition, candidate_grid,
    entropy_routing, fit_validation_stack, validation_roles,
)
from malpdf.static.safety import read_bounded_bytes


def _input_spec(spec: dict) -> None:
    if not isinstance(spec, dict) or set(spec) != {"path", "sha256"}:
        raise ValueError("Each fusion input needs an explicit path and SHA-256 lock")
    name = spec["path"]
    if not isinstance(name, str) or not name or Path(name).is_absolute() or ".." in Path(name).parts or "\\" in name:
        raise ValueError("Fusion inputs must be safe repository-relative paths")
    if not name.startswith(("data/processed/", "reports/experiments/", "artifacts/")):
        raise ValueError("Fusion inputs must stay in processed data or experiment evidence")
    validate_sha256(spec["sha256"])


def validate_late_fusion_configuration(configuration: dict) -> None:
    if not isinstance(configuration, dict) or set(configuration) != {"seed", "inputs", "vision", "candidates"}:
        raise ValueError("Fusion configuration needs seed, inputs, vision and candidates")
    if type(configuration["seed"]) is not int or configuration["seed"] != 42:
        raise ValueError("Fusion Protocol G seed is locked to 42")
    inputs = configuration["inputs"]
    if not isinstance(inputs, dict) or set(inputs) != {"dataset", "split_manifest", "validation", "test", "base_provenance", "base_configuration"}:
        raise ValueError("Fusion input checksum locks are incomplete")
    for spec in inputs.values():
        _input_spec(spec)
    vision = configuration["vision"]
    if vision is not None:
        if not isinstance(vision, dict) or set(vision) != {"validation", "test", "provenance"}:
            raise ValueError("Vision needs validation/test probability tables and provenance")
        for spec in vision.values():
            _input_spec(spec)
    candidates = configuration["candidates"]
    if not isinstance(candidates, dict) or set(candidates) != {"regularization_cs", "xgb_weights", "vision_weights"}:
        raise ValueError("Fusion candidate grids are incomplete")
    for name, values in candidates.items():
        if not isinstance(values, list) or not 1 <= len(values) <= 16 or len(set(values)) != len(values):
            raise ValueError("Fusion candidate grids must be short unique lists")
        if any(type(value) not in (int, float) or not np.isfinite(value) for value in values):
            raise ValueError("Fusion candidate grids must be finite numbers")
        if name == "regularization_cs" and any(value <= 0 for value in values):
            raise ValueError("Regularization C must be positive")
        if name != "regularization_cs" and any(not 0 <= value <= 1 for value in values):
            raise ValueError("Weights must be within [0,1]")
    if 0.0 not in candidates["vision_weights"] or 1.0 in candidates["vision_weights"]:
        raise ValueError("Vision grid must include zero and retain a tabular contribution")
    candidate_grid(vision_available=True, **candidates)


def load_late_fusion_configuration(root: Path, path: Path) -> dict:
    content = read_bounded_bytes(path, boundary=root / "configs", max_bytes=128 * 1024)
    configuration = yaml.safe_load(content)
    validate_late_fusion_configuration(configuration)
    return configuration


def _input_bytes(root: Path, spec: dict, *, max_bytes: int = 16 * 1024 * 1024) -> bytes:
    _input_spec(spec)
    content = read_bounded_bytes(root / spec["path"], boundary=root, max_bytes=max_bytes)
    if hashlib.sha256(content).hexdigest() != spec["sha256"]:
        raise ValueError("Fusion input differs from its SHA-256 lock")
    return content


def _check_prediction_path(root: Path, spec: dict) -> None:
    """Check availability/caps without reading test bytes or labels."""
    _input_spec(spec)
    path = root / spec["path"]
    if path.suffix.lower() not in {".csv", ".parquet"} or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("Prediction path must be CSV/Parquet without symbolic links")
    information = path.stat()
    if not stat.S_ISREG(information.st_mode) or not 0 < information.st_size <= 16 * 1024 * 1024:
        raise ValueError("Prediction path must be a nonempty regular file within its size cap")


def _prediction_frame(root: Path, spec: dict, columns: list[str]) -> pd.DataFrame:
    content = _input_bytes(root, spec)
    suffix = Path(spec["path"]).suffix.lower()
    if suffix == ".parquet":
        source = pq.ParquetFile(BytesIO(content))
        size = sum(source.metadata.row_group(index).total_byte_size for index in range(source.metadata.num_row_groups))
        if source.metadata.num_rows > 100_000 or len(source.schema.names) > 32 or size > 64 * 1024 * 1024:
            raise ValueError("Fusion Parquet exceeds decoded resource caps")
        if not set(columns).issubset(source.schema.names):
            raise ValueError("Fusion prediction schema is incomplete")
        frame = source.read(columns=columns).to_pandas()
    elif suffix == ".csv":
        frame = pd.read_csv(BytesIO(content), usecols=columns)
    else:
        raise ValueError("Fusion predictions must be CSV or Parquet")
    if len(frame) > 100_000:
        raise ValueError("Fusion prediction table exceeds its row cap")
    return frame


def _aligned_frame(frame: pd.DataFrame, manifest: pd.DataFrame, *, legacy_ids: bool) -> pd.DataFrame:
    expected = manifest.copy().sort_values("sample_id", kind="stable")
    lookup = {_safe_id(str(value)) if legacy_ids else str(value): str(value) for value in expected.sample_id}
    if len(lookup) != len(expected) or frame.sample_id.isna().any() or frame.sample_id.duplicated().any():
        raise ValueError("Prediction sample IDs are missing, duplicated or ambiguous")
    if set(frame.sample_id) != set(lookup):
        raise ValueError("Prediction sample IDs must exactly match their Protocol G partition")
    frame = frame.copy()
    frame["sample_id"] = frame.sample_id.map(lookup)
    frame = frame.set_index("sample_id").loc[expected.sample_id].reset_index()
    if not np.array_equal(frame.true_label.to_numpy(), expected.Label.to_numpy()):
        raise ValueError("Prediction labels disagree with the locked Protocol G manifest")
    return frame


def _validate_base_provenance(root: Path, configuration: dict) -> dict:
    inputs = configuration["inputs"]
    provenance = json.loads(_input_bytes(root, inputs["base_provenance"], max_bytes=1024 * 1024))
    base_config = json.loads(_input_bytes(root, inputs["base_configuration"], max_bytes=1024 * 1024))
    if provenance.get("experiment") != "selective_static_ensemble_protocol_g_seed42" or provenance.get("dataset_sha256") != inputs["dataset"]["sha256"] or provenance.get("protocol_g_manifest_sha256") != inputs["split_manifest"]["sha256"]:
        raise ValueError("Base probability provenance must bind the reviewed Protocol G v1 run")
    if base_config.get("protocol") != "G" or base_config.get("split_seed") != 42 or base_config.get("model_seed") != 42 or base_config.get("dataset_sha256") != inputs["dataset"]["sha256"] or base_config.get("split_manifest_sha256") != inputs["split_manifest"]["sha256"]:
        raise ValueError("Base model configuration disagrees with Protocol G identity/seed locks")
    if provenance.get("environment", {}).get("git_working_tree", {}).get("status") != "clean" or provenance.get("test_evaluation", {}).get("test_not_used_for_selection") is not True:
        raise ValueError("Base probabilities require clean train-only generating provenance")
    if base_config.get("base_models", {}).get("ft_transformer", {}).get("preprocessing") != "StandardScaler fit on Protocol G train only":
        raise ValueError("FT preprocessing must have been fit on train only")
    return {"code_commit_sha": provenance["code_commit_sha"], "raw_columns_only": True,
            "fit_scope": "Historical reviewed XGB/FT train-only pipeline; v1 calibrated/ensemble columns and validation roles ignored"}


def _vision_groups(root: Path, configuration: dict, manifest: pd.DataFrame) -> dict[str, str] | None:
    vision = configuration["vision"]
    if vision is None:
        return None
    proof = json.loads(_input_bytes(root, vision["provenance"], max_bytes=1024 * 1024))
    expected = {"protocol": "G", "seed": 42, "model": "vision_resnet18", "official_model": True,
                "base_fit_partition": "train", "checkpoint_selection_partition": "validation", "worktree": "clean",
                "dataset_sha256": configuration["inputs"]["dataset"]["sha256"],
                "split_manifest_sha256": configuration["inputs"]["split_manifest"]["sha256"]}
    if any(proof.get(key) != value for key, value in expected.items()):
        raise ValueError("Vision must be an official train-only Protocol G model; smoke checkpoints are ineligible")
    if proof.get("predictions") != {name: vision[name] for name in ("validation", "test")}:
        raise ValueError("Vision provenance does not bind the configured prediction tables")
    source = proof.get("source_manifest")
    _input_spec(source)
    samples = load_vision_source_manifest(root, root / source["path"], source["sha256"])
    _, readiness = align_protocol_g_samples(samples, manifest)
    if not readiness["ready"]:
        raise ValueError("Vision source PDFs must completely match Protocol G IDs/labels/groups")
    # Connected components keep both feature-equivalent and known file/family groups together.
    parent = {str(value): str(value) for value in manifest.sample_id}
    def find(value):
        while parent[value] != value:
            parent[value] = parent[parent[value]]
            value = parent[value]
        return value
    identities = {}
    feature_group = manifest.set_index("sample_id").duplicate_group_id.to_dict()
    for sample in samples:
        keys = [("feature", feature_group[sample.sample_id]), ("pdf", sample.pdf_sha256)]
        if sample.related_group_id is not None:
            keys.append(("related", sample.related_group_id))
        for key in keys:
            if key in identities:
                left, right = find(sample.sample_id), find(identities[key])
                parent[max(left, right)] = min(left, right)
            else:
                identities[key] = sample.sample_id
    return {value: find(value) for value in parent}


def _load_partition(root: Path, configuration: dict, manifest: pd.DataFrame, partition: str,
                    vision_groups: dict[str, str] | None) -> FusionPartition:
    subset = manifest.loc[manifest.split == partition].sort_values("sample_id", kind="stable")
    base = _aligned_frame(_prediction_frame(root, configuration["inputs"][partition], ["sample_id", "true_label", "xgb_probability", "ft_probability"]), subset, legacy_ids=True)
    probabilities = base[["xgb_probability", "ft_probability"]].to_numpy(dtype=float)
    if configuration["vision"] is not None:
        vision = _aligned_frame(_prediction_frame(root, configuration["vision"][partition], ["sample_id", "true_label", "vision_probability"]), subset, legacy_ids=False)
        probabilities = np.column_stack((probabilities, vision.vision_probability))
    ids = tuple(base.sample_id)
    groups = tuple(vision_groups[value] for value in ids) if vision_groups is not None else tuple(subset.duplicate_group_id)
    return FusionPartition(partition, ids, groups, base.true_label.to_numpy(), probabilities,
                           VISION_BRANCHES if configuration["vision"] is not None else BASE_BRANCHES)


def _append_log(root: Path, report: dict) -> None:
    notes = "Protocol G seed=42; Label=1 malicious; ECE: 10 equal-width malicious-probability bins. Meta-fit/calibration-fit/selection are disjoint deterministic validation groups (~25/25/50); Platt uses fused malicious probability. Selection MCC, malicious F1, declared order; no refit or test tuning. Top 10% entropy in bits; ties by sample ID; round(0.1*n) referrals; referrals never corrected or executed."
    notes += f" Vision status={report.get('vision_status', 'not_checked')}."
    if not report["metrics"]:
        notes += " F1/MCC/ECE/Brier N/A: preflight or failure, no model evaluation."
    if report.get("error"):
        notes += f" Error: {report['error']['type']}: {report['error']['message']}."
    rows = report["metrics"].items() if report["metrics"] else [("late_fusion_v2/N/A", {})]
    with (root / "reports/research_log.md").open("a", encoding="utf-8") as output:
        for key, values in rows:
            model, partition = key.split("/", 1)
            fields = [report["finished_at_utc"], report["run_id"], f"late fusion {report['mode']} / {report['status']}", "G / 42", model, partition,
                      *[values.get(name, "N/A") for name in ("f1_malicious", "mcc", "ece", "brier")],
                      f"`{report['code_commit_sha']}`", report["git_worktree"]["status"], f"`{report['report_path']}`", notes]
            output.write("| " + " | ".join(str(value).replace("|", "\\|").replace("\n", " ") for value in fields) + " |\n")


def run_late_fusion(root: Path, configuration: dict, *, execute: bool = False, run_id: str | None = None) -> dict:
    """Preflight by default; a clean official run locks validation before test reads."""
    validate_late_fusion_configuration(configuration)
    if type(execute) is not bool:
        raise ValueError("execute must be an explicit boolean")
    root = Path(root).resolve()
    commit = _current_commit_sha(root)
    git_state = repository_git_state(root)
    identifier = run_id or f"run_{datetime.now(timezone.utc):%Y%m%dT%H%M%S%fZ}_{commit[:12]}"
    if not identifier or identifier in {".", ".."} or any(value not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for value in identifier):
        raise ValueError("Unsafe fusion run identifier")
    directory, artifacts = (root / base / "late_fusion_v2" / identifier for base in ("reports/experiments", "artifacts"))
    for path in (directory, artifacts):
        if path.exists() or any(part.is_symlink() for part in (path, *path.parents)):
            raise ValueError("Fusion run directory exists or contains a symbolic link")
    directory.mkdir(parents=True, exist_ok=False)
    artifacts.mkdir(parents=True, exist_ok=False)
    report = {"run_id": identifier, "mode": "execute" if execute else "dry_run", "status": "started", "started_at_utc": datetime.now(timezone.utc).isoformat(),
              "code_commit_sha": commit, "git_worktree": git_state, "report_path": str((directory / "run_summary.json").relative_to(root)),
              "artifact_directory": str(artifacts.relative_to(root)), "metrics": {}, "test_evaluation_count": 0}
    try:
        _write_json(directory / "locked_methodology.json", {"configuration": configuration, "seed": 42,
                    "validation_roles": "Deterministic group-stratified meta-fit/calibration-fit/selection ~25/25/50; no refit",
                    "selection": "MCC, malicious F1, declared candidate order", "calibration": "Platt on fused malicious-class probability; calibration-fit only",
                    "meta_learner": "LogisticRegression fit only on meta-fit; candidate convex-average weights selected on selection only",
                    "threshold": 0.5, "ece_bins": 10, "ece_convention": "Equal-width malicious-probability bins; p=1 in final bin",
                    "routing": "Fixed top 10% entropy in bits; round(0.1*n), ID ties; no test-label-based policy selection",
                    "test_policy": "Decode/evaluate saved test probabilities once after validation_lock.json; no base-model training or test rerun",
                    "code_commit_sha": commit, "mode": report["mode"]})
        _write_json(directory / "environment_metadata.json", {"python": platform.python_version(), "packages": {name: importlib.metadata.version(name) for name in ("malpdf", "numpy", "pandas", "scikit-learn", "pyarrow", "pyyaml")},
                    "code_commit_sha": commit, "git_worktree": git_state,
                    "code_sha256": {name: sha256_file(root / name) for name in ("src/malpdf/models/late_fusion.py", "src/malpdf/experiments/late_fusion_runner.py", "scripts/04_evaluate_late_fusion.py", "configs/late_fusion_stacking.yaml") if (root / name).is_file()}})
        if execute and (git_state["status"] != "clean" or len(commit) != 40):
            raise ValueError("Official late-fusion evaluation requires a clean committed worktree")
        inputs = configuration["inputs"]
        _input_bytes(root, inputs["dataset"])
        _input_bytes(root, inputs["split_manifest"])
        frame = load_rit_pdfmal(root / inputs["dataset"]["path"])
        _, manifest, split_summary = load_saved_protocol_g_split(frame, inputs["dataset"]["sha256"], root, seed=42, manifest_path=root / inputs["split_manifest"]["path"])
        if sha256_file(root / inputs["dataset"]["path"]) != inputs["dataset"]["sha256"] or split_summary["split_manifest_sha256"] != inputs["split_manifest"]["sha256"]:
            raise ValueError("Protocol G inputs changed during fusion preflight")
        base_provenance = _validate_base_provenance(root, configuration)
        vision_groups = _vision_groups(root, configuration, manifest)
        report["vision_status"] = "verified_official_predictions" if configuration["vision"] is not None else "not_configured; nonzero Vision weights unavailable; smoke model ineligible"
        _check_prediction_path(root, inputs["test"])
        if configuration["vision"] is not None:
            _check_prediction_path(root, configuration["vision"]["test"])
        validation = _load_partition(root, configuration, manifest, "validation", vision_groups)
        roles = validation_roles(validation)
        report["validation_rows"] = len(validation.sample_ids)
        report["validation_role_rows"] = {name: len(values) for name, values in roles.items()}
        grid = candidate_grid(vision_available=configuration["vision"] is not None, **configuration["candidates"])
        report["candidate_count"] = len(grid)
        report["skipped_vision_weights"] = [] if configuration["vision"] is not None else [value for value in configuration["candidates"]["vision_weights"] if value != 0]
        _write_json(directory / "data_provenance.json", {"inputs": inputs, "vision": configuration["vision"], "vision_status": report["vision_status"],
                    "base_models": base_provenance, "split_validation": split_summary["hard_validation"], "validation_role_rows": report["validation_role_rows"],
                    "test_predictions_decoded_during_preflight": False})
        if not execute:
            report["status"] = "dry_run_completed"
            report["official_execution_ready"] = git_state["status"] == "clean"
            return report
        stack, selection_rows, roles = fit_validation_stack(validation, grid)
        pd.DataFrame(selection_rows).to_csv(directory / "selection_results.csv", index=False)
        role_by_position = {int(index): name for name, positions in roles.items() for index in positions}
        pd.DataFrame({"sample_id": validation.sample_ids, "role": [role_by_position[index] for index in range(len(validation.sample_ids))]}).to_csv(artifacts / "validation_roles.csv", index=False)
        _write_json(directory / "validation_lock.json", {**stack.lock_metadata(), "locked_at_utc": datetime.now(timezone.utc).isoformat(), "test_evaluations_before_lock": 0,
                    "input_checksums": inputs, "referral_rate": 0.10})
        def record_metrics(partition, positions=None):
            mask = np.arange(len(partition.sample_ids)) if positions is None else positions
            fused = stack.predict_proba(partition)
            for index, branch in enumerate(partition.branches):
                report["metrics"][f"{branch}/{partition.partition if positions is None else 'validation_selection'}"] = calibration_metrics(partition.labels[mask], partition.probabilities[mask, index], n_bins=10)
            report["metrics"][f"late_fusion_v2/{partition.partition if positions is None else 'validation_selection'}"] = calibration_metrics(partition.labels[mask], fused[mask], n_bins=10)
            return fused
        record_metrics(validation, roles["selection"])
        # Test tables cannot reach any fit/selection function; first decode is after lock.
        test = _load_partition(root, configuration, manifest, "test", vision_groups)
        if set(validation.sample_ids) & set(test.sample_ids) or set(validation.group_ids) & set(test.group_ids):
            raise ValueError("Fusion validation/test IDs or groups overlap")
        test_scores = record_metrics(test)
        report["test_evaluation_count"] = 1
        routing, referred = entropy_routing(test.labels, test_scores, test.sample_ids)
        report["routing"] = routing
        report["metrics"]["late_fusion_v2/test_retained"] = routing["retained_metrics"]
        routing_row = {key: ("N/A" if value is None else value) for key, value in routing.items() if key != "retained_metrics"}
        routing_row.update({f"retained_{key}": routing["retained_metrics"][key] for key in ("f1_malicious", "mcc", "brier", "log_loss", "ece")})
        pd.DataFrame([routing_row]).to_csv(directory / "routing_analysis.csv", index=False)
        pd.DataFrame({"sample_id": test.sample_ids, "true_label": test.labels, "ensemble_probability": test_scores, "referred": referred}).to_parquet(artifacts / "test_predictions.parquet", index=False)
        report["selection"] = stack.selection
        _write_json(directory / "metrics.json", report["metrics"])
        report["status"] = "completed"
    except BaseException as error:
        report["status"] = "interrupted" if isinstance(error, KeyboardInterrupt) else "failed"
        report["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        report["finished_at_utc"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        with (directory / "model_comparison.csv").open("x", newline="", encoding="utf-8") as output:
            names = ["model", "partition", "accuracy", "f1_malicious", "mcc", "brier", "log_loss", "ece"]
            writer = csv.writer(output, lineterminator="\n")
            writer.writerow(names)
            for key, metrics in (report["metrics"].items() or [("late_fusion_v2/N/A", {})]):
                writer.writerow([*key.split("/", 1), *[metrics.get(name, "N/A") for name in names[2:]]])
        _write_json(directory / "run_summary.json", report)
        _append_log(root, report)
    return report

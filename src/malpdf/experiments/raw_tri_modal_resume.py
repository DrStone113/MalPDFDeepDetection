"""Continue the sealed raw-cohort study with GPU probabilities and saved folds."""

import hashlib
import io
import json
from pathlib import Path
import re
import zipfile

import numpy as np
import pandas as pd
import torch

from malpdf.data.kaggle_export import anonymize_rows
from malpdf.evaluation.selective import calibration_metrics
from malpdf.experiments.raw_tri_modal_v3 import (
    BRANCHES, ROLE_ORDER, fail_closed_routing, group_folds, load_locked_cohort,
    safety_feature_order, validate_configuration,
)
from malpdf.models.late_fusion import entropy_routing
from malpdf.models.safe_stacking import V3_BRANCHES, fit_validation_v3
from malpdf.models.v3_base_learners import load_v3_fold
from malpdf.provenance.research_runs import ResearchRun, write_json
from malpdf.reproducibility import set_random_seed
from malpdf.static.safety import read_bounded_bytes


def _json(path, boundary):
    return json.loads(read_bounded_bytes(path, boundary=boundary, max_bytes=1024**2))


def _csv(path, boundary):
    content = read_bounded_bytes(path, boundary=boundary, max_bytes=16 * 1024**2)
    return pd.read_csv(io.BytesIO(content)), hashlib.sha256(content).hexdigest()


def aligned_vision_probabilities(frame, portable, manifest, mapping, *, partition):
    """Require exact partition IDs and return probabilities in saved local order."""
    if (partition not in {"validation", "test"}
            or list(frame) != ["sample_id", "p_malicious"] or frame.empty
            or not frame.sample_id.is_unique or frame.sample_id.isna().any()):
        raise ValueError("Vision CSV needs unique IDs and the malicious-probability schema")
    expected = portable.loc[portable.split.eq(partition), "sample_id"]
    probabilities = frame.p_malicious.to_numpy(dtype=float)
    if (set(frame.sample_id) != set(expected) or not np.isfinite(probabilities).all()
            or (probabilities < 0).any() or (probabilities > 1).any()):
        raise ValueError("Vision probabilities or exact locked partition membership differ")
    reverse = mapping.set_index("sample_id").export_sample_id
    identifiers = reverse.loc[manifest.loc[manifest.split.eq(partition), "sample_id"]]
    return frame.set_index("sample_id").loc[identifiers, "p_malicious"].to_numpy(dtype=float)


def validate_vision_evidence(directory, root, inventory, csv_hashes):
    """Require saved pre-Test Vision selection and checksum evidence."""
    names = ("vision_selection_lock.json", "output_checksums.json", "run_summary.json")
    missing = [name for name in names if not (directory / name).is_file()]
    if missing:
        raise FileNotFoundError("Missing Kaggle provenance: " + ", ".join(missing))
    lock, checks, summary = (_json(directory / name, root / "checkpoints") for name in names)
    if (any(checks.get(name) != digest for name, digest in csv_hashes.items())
            or checks.get("vision_selection_lock.json") != hashlib.sha256(
                read_bounded_bytes(directory / names[0], boundary=root / "checkpoints", max_bytes=1024**2)).hexdigest()
            or lock.get("seed") != 42 or lock.get("selected_role") != "validation_base_selection"
            or lock.get("selection_rows") != inventory["validation_roles"]["base_selection"]
            or lock.get("bundle_metadata_sha256") != inventory["metadata_sha256"]
            or lock.get("test_metrics_computed") is not False or lock.get("test_prediction_passes") != 0
            or summary.get("status") != "completed" or summary.get("test_metrics_computed") is not False
            or summary.get("test_prediction_passes") != 1
            or any(summary.get(k) != lock.get(k) for k in (
                "run_id", "seed", "code_commit", "bundle_metadata_sha256", "best_epoch"
            ))
            or not re.fullmatch(r"[0-9a-f]{64}", lock.get("checkpoint_sha256", ""))
            or checks.get("vision_resnet_best.pt") != lock["checkpoint_sha256"]
            or type(lock.get("best_epoch")) is not int or not 1 <= lock["best_epoch"] <= lock.get("configuration", {}).get("max_epochs", 0)):
        raise ValueError("Kaggle outputs do not prove the same validation-only selected Vision run")


    code_commit = lock.get("code_commit")
    if code_commit != inventory["code_commit"]:
        provenance = lock.get("training_code_provenance")
        matches = []
        for path in (root / "reports/experiments/kaggle_performance").glob("run_*/optimized_code_provenance.json"):
            known = _json(path, root / "reports/experiments/kaggle_performance")
            if known == provenance and known.get("generating_commit") == code_commit:
                matches.append(known)
        if not matches or provenance.get("worktree") != "clean" or provenance.get("base_bundle_code_commit") != inventory["code_commit"]:
            raise ValueError("Vision training code was not sealed in an authorized local handoff")
    return {"run_id": lock["run_id"], "code_commit": code_commit,
            "bundle_metadata_sha256": lock["bundle_metadata_sha256"],
            "checkpoint_sha256": lock["checkpoint_sha256"], "best_epoch": lock["best_epoch"],
            "selected_role": lock["selected_role"], "selection_rows": lock["selection_rows"],
            "csv_sha256": csv_hashes,
            "provenance_sha256": {name: hashlib.sha256(read_bounded_bytes(directory / name,
                boundary=root / "checkpoints", max_bytes=1024**2)).hexdigest() for name in names}}


def load_resume_inputs(root, config, handoff_run, vision_directory, run):
    if not re.fullmatch(r"run_[A-Za-z0-9_-]{1,100}", handoff_run):
        raise ValueError("Unsafe handoff run identifier")
    report = root / "reports/experiments/kaggle_handoff" / handoff_run
    private = root / "artifacts/kaggle_handoff" / handoff_run
    inventory = _json(report / "bundle_inventory.json", root / "reports/experiments/kaggle_handoff")
    export = _json(report / "run_summary.json", root / "reports/experiments/kaggle_handoff")
    plan = _json(private / "local_tabular_reuse_plan.json", private)
    prior_run = plan["prior_run"]
    if not re.fullmatch(r"run_[A-Za-z0-9_-]{1,100}", prior_run):
        raise ValueError("Unsafe saved tabular run identifier")
    prior_report = root / "reports/experiments/raw_tri_modal_v3" / prior_run
    prior_artifacts = root / "artifacts/raw_tri_modal_v3" / prior_run
    prior = _json(prior_report / "run_summary.json", root / "reports/experiments/raw_tri_modal_v3")
    if (export.get("status") != "completed" or export.get("prior_tabular_run") != prior_run
            or plan["input_locks"] != config["inputs"] or prior.get("inputs") != config["inputs"]
            or prior.get("code_commit") != plan["code_commit"] or prior.get("code_worktree", {}).get("status") != "clean"
            or (prior_report / "test_evaluation_started.json").exists() or prior.get("test_evaluation_count", 0)):
        raise ValueError("Reuse requires the same checksum-locked cohort with untouched Test")
    archive = read_bounded_bytes(private / "malpdf-markov-cache.zip", boundary=private, max_bytes=512 * 1024**2)
    if len(archive) != inventory["archive_bytes"] or hashlib.sha256(archive).hexdigest() != inventory["archive_sha256"]:
        raise ValueError("The sealed Kaggle archive changed")
    with zipfile.ZipFile(io.BytesIO(archive)) as source:
        def member(name, cap):
            if source.getinfo(name).file_size > cap:
                raise ValueError("Numeric manifest exceeds its resource cap")
            content = source.read(name)
            digest = inventory["metadata_sha256"] if name == "bundle_metadata.json" else inventory["file_sha256"][name]
            if hashlib.sha256(content).hexdigest() != digest:
                raise ValueError("Sealed bundle metadata/manifest changed")
            return content
        metadata = json.loads(member("bundle_metadata.json", 1024**2))
        portable = pd.read_csv(io.BytesIO(member("manifest.csv", 16 * 1024**2)))
        portable_roles = pd.read_csv(io.BytesIO(member("validation_roles.csv", 16 * 1024**2)))
    if any(metadata.get(k) != v for k, v in inventory.items() if k in metadata):
        raise ValueError("Inventory contradicts the sealed bundle")
    del archive
    labeled, manifest, sources, unknown = load_locked_cohort(root, config)
    role_frame, role_digest = _csv(prior_artifacts / "validation_roles.csv", prior_artifacts)
    if role_digest != plan["validation_roles_sha256"]:
        raise ValueError("Original disjoint validation roles changed")
    val_manifest = manifest.loc[manifest.split.eq("validation")].reset_index(drop=True)
    if (not role_frame.sample_id.is_unique or set(role_frame.sample_id) != set(val_manifest.sample_id)
            or set(role_frame.role) != set(ROLE_ORDER)):
        raise ValueError("Saved validation roles do not exactly cover Validation")
    aligned_roles = role_frame.set_index("sample_id").loc[val_manifest.sample_id]
    if not np.array_equal(aligned_roles.Label, val_manifest.Label) or not np.array_equal(aligned_roles.duplicate_group_id, val_manifest.duplicate_group_id):
        raise ValueError("Saved validation role groups/labels differ")
    roles = {name: np.flatnonzero(aligned_roles.role.to_numpy() == name) for name in ROLE_ORDER}
    expected_portable, expected_mapping, expected_roles = anonymize_rows(labeled, manifest, sources, unknown, role_frame)
    mapping, _ = _csv(private / "private_id_map.csv", private)
    if (not mapping.equals(expected_mapping)
            or not portable_roles.equals(expected_roles)
            or not portable.loc[:, expected_portable.columns].equals(expected_portable)):
        raise ValueError("Opaque Kaggle identity/split mapping contradicts the local cohort")
    scores, csv_hashes = {}, {}
    for partition, name in (("validation", "vision_probs_val.csv"), ("test", "vision_probs_test.csv")):
        frame, digest = _csv(vision_directory / name, root / "checkpoints")
        scores[partition] = aligned_vision_probabilities(frame, portable, manifest, mapping, partition=partition)
        csv_hashes[name] = digest
    expected_paths = {str((prior_artifacts / "tabular" / name / f"fold_{i}" / filename).relative_to(root)): name
                      for name, filename in zip(V3_BRANCHES, ("model.ubj", "model.txt", "model.cbm", "model.joblib", "model.pt"))
                      for i in range(1, 6)}
    if (len(plan["checkpoints"]) != 25 or {p["path"]: p["model"] for p in plan["checkpoints"]} != expected_paths):
        raise ValueError("All five original folds of each tabular family are required")
    for entry in plan["checkpoints"]:
        content = read_bounded_bytes(root / entry["path"], boundary=prior_artifacts, max_bytes=128 * 1024**2)
        if hashlib.sha256(content).hexdigest() != entry["sha256"]:
            raise ValueError("A completed tabular checkpoint changed since GPU handoff")
    run.state.update(prior_tabular_run=prior_run, handoff_run=handoff_run, inputs=config["inputs"],
        partition_rows=manifest.split.value_counts().to_dict(), vision_rows={k: len(v) for k, v in scores.items()},
        tabular_checkpoints_verified=25, validation_role_rows={k: len(v) for k, v in roles.items()},
        test_evaluation_count=0, unknown_rows=len(unknown), unknown_prediction_status="Not requested; unlabeled Vision CSV not imported")
    write_json(run.report / "input_validation.json", {"exact_vision_id_match": True,
        "zero_partition_overlap": True, "partition_rows": run.state["partition_rows"],
        "vision_rows": run.state["vision_rows"], "csv_sha256": csv_hashes,
        "tabular_checkpoints_verified": 25, "validation_role_rows": run.state["validation_role_rows"],
        "unknown_rows_excluded_from_evaluation": len(unknown), "test_metrics_computed": False})
    try:
        run.state["vision"] = validate_vision_evidence(vision_directory, root, inventory, csv_hashes)
    except FileNotFoundError as error:
        run.state["notes"] = ("CSV identities/checksums and 25 original tabular checkpoints verified; "
                              + str(error) + "; no model fitting or Test evaluation performed")
        raise
    except ValueError:
        run.state["notes"] = "Vision provenance rejected; no model fitting or Test evaluation performed; private error evidence retained"
        raise
    return labeled, manifest, roles, scores, plan


def claim_test_evaluation(root, input_locks, report, lock_digest):
    """An exclusive cohort marker survives failure and blocks repeated Test use."""

    for path in (root / "reports/experiments/raw_tri_modal_v3").glob("run_*/test_evaluation_started.json"):
        prior = _json(path.parent / "locked_methodology.json", root / "reports/experiments/raw_tri_modal_v3")
        if prior.get("configuration", {}).get("inputs") == input_locks:
            raise ValueError("This raw cohort Test has already been evaluated")
    directory = root / "artifacts/raw_tri_modal_v3_test_locks"
    if any(p.is_symlink() for p in (directory, *directory.parents)):
        raise ValueError("Unsafe Test lock directory")
    directory.mkdir(exist_ok=True, parents=True)
    key = input_locks["split_manifest"]["sha256"]
    if not re.fullmatch(r"[0-9a-f]{64}", key):
        raise ValueError("Invalid locked split checksum")
    evidence = {"report": str(report.relative_to(root)), "validation_lock_sha256": lock_digest,
                "split_manifest_sha256": key, "allowed_evaluations": 1}

    write_json(directory / (key + ".json"), evidence)
    write_json(report / "test_evaluation_started.json", evidence)


def run_raw_tri_modal_resume(root, code_root, config, handoff_run, vision_directory, *, execute=False, run_id=None):
    methodology = {"configuration": config, "handoff_run": handoff_run,
        "train_policy": "Reuse 25 checksum-pinned local Train-fold models; restore saved preprocessing without fit",
        "validation_policy": "Preserve four saved group-disjoint roles; meta-fit, Platt-fit, MCC/Youden selection only",
        "vision_policy": "Join sealed GPU probabilities by opaque ID; require pre-Test checkpoint selection evidence",
        "test_policy": "One independent Test evaluation after persisted lock; exclusive cohort marker prohibits repeats",
        "referral_policy": "Entropy 10 percent with deterministic ID ties; parser errors force referral; no dynamic execution",
        "unlabeled_policy": "Four unknown labels excluded; no metric or fabricated prediction"}
    with ResearchRun(root, "raw_tri_modal_v3_resume", methodology, code_root=code_root, run_id=run_id) as run:
        validate_configuration(config)
        if execute and run.state["code_worktree"]["status"] != "clean":
            raise ValueError("Official continuation requires clean committed generating code")
        labeled, manifest, roles, vision, plan = load_resume_inputs(root, config, handoff_run, vision_directory, run)
        if not execute:
            run.state["notes"] = "Preflight only; no fit, inference or Test metric computation"
            return run.state
        set_random_seed(42)
        torch.set_num_threads(config["cpu_threads"])
        train = labeled.loc[manifest.split.eq("train")].reset_index(drop=True)
        val = labeled.loc[manifest.split.eq("validation")].reset_index(drop=True)
        order, removed = safety_feature_order(train)
        folds = group_folds(manifest.loc[manifest.split.eq("train")].reset_index(drop=True), partition="train", count=5)
        models = {name: [] for name in V3_BRANCHES}
        val_scores = np.zeros((len(val), len(BRANCHES)))
        fit_metadata = []
        pinned = {p["path"]: p["sha256"] for p in plan["checkpoints"]}
        for column, name in enumerate(V3_BRANCHES):
            for i, (fit, _) in enumerate(folds, 1):
                entries = [p for p in pinned if Path(p).parent.name == f"fold_{i}" and Path(p).parent.parent.name == name]
                checkpoint = root / entries[0]
                model, info = load_v3_fold(checkpoint, pinned[entries[0]], train.iloc[fit].loc[:, list(order)],
                    config, boundary=root / "artifacts/raw_tri_modal_v3" / plan["prior_run"], base_selection_rows=len(roles["base_selection"]))
                models[name].append(model)
                fit_metadata.append(info)
                val_scores[:, column] += model.predict_proba(val.loc[:, list(order)]) / 5
                run.progress("tabular_fold_reused", model=name, fold=i)
        val_scores[:, -1] = vision["validation"]
        val_manifest = manifest.loc[manifest.split.eq("validation")].reset_index(drop=True)
        stack, candidates = fit_validation_v3(val_manifest, val_scores, config["meta_regularization_cs"], branches=BRANCHES, roles=roles)
        pd.DataFrame(candidates).to_csv(run.report / "validation_candidates.csv", index=False)
        pd.DataFrame({"sample_id": val.sample_id, "Label": val.Label,
            **{name: val_scores[:, i] for i, name in enumerate(BRANCHES)}}).to_csv(run.artifacts / "validation_predictions.csv", index=False)
        write_json(run.report / "validation_lock.json", {**stack.lock_metadata(), "feature_order": list(order),
            "train_constant_exclusions": list(removed), "vision": run.state["vision"],
            "base_fit_metadata": [{k: v for k, v in info.items() if k != "checkpoint"} for info in fit_metadata],
            "prior_tabular_run": plan["prior_run"], "input_locks": config["inputs"], "code_commit": run.commit})
        selected = roles["threshold_selection"]
        run.state["metrics"]["stacking_v3/validation_threshold_selection"] = calibration_metrics(
            val.Label.to_numpy()[selected], stack.predict_proba(val_scores[selected]), threshold=stack.threshold)
        lock_digest = hashlib.sha256((run.report / "validation_lock.json").read_bytes()).hexdigest()
        claim_test_evaluation(root, config["inputs"], run.report, lock_digest)
        test = labeled.loc[manifest.split.eq("test")].reset_index(drop=True)
        test_scores = np.column_stack([np.mean([model.predict_proba(test.loc[:, list(order)])
            for model in models[name]], axis=0) for name in V3_BRANCHES] + [vision["test"]])
        fused = stack.predict_proba(test_scores)
        for i, name in enumerate(BRANCHES):
            run.state["metrics"][name + "/test"] = calibration_metrics(test.Label, test_scores[:, i])
        run.state["metrics"]["stacking_v3/test"] = calibration_metrics(test.Label, fused, threshold=stack.threshold)
        run.state["test_evaluation_count"] = 1
        pure, _ = entropy_routing(test.Label, fused, test.sample_id, threshold=stack.threshold)
        closed, referred = fail_closed_routing(test.Label, fused, test.sample_id, test.parser_failed, threshold=stack.threshold)
        routing = [pure, closed]
        write_json(run.report / "routing_analysis.json", routing)
        pd.DataFrame([{k: v for k, v in row.items() if k != "retained_metrics"} for row in routing]).to_csv(run.report / "routing_analysis.csv", index=False)
        for row in routing:
            run.state["metrics"]["stacking_v3/test_retained_" + row["policy"]] = row["retained_metrics"]
        pd.DataFrame({"sample_id": test.sample_id, "Label": test.Label,
            **{name: test_scores[:, i] for i, name in enumerate(BRANCHES)}, "p_fused": fused,
            "parser_failed": test.parser_failed, "referred": referred,
            "static_decision": np.where(referred, "abstain", np.where(fused >= stack.threshold, "malicious", "benign"))
        }).to_csv(run.artifacts / "test_predictions.csv", index=False)
        write_json(run.report / "test_metrics.json", {k: v for k, v in run.state["metrics"].items() if "/test" in k})
        run.state.update(threshold=stack.threshold, routing=routing, feature_order=list(order),
            train_constant_exclusions=list(removed), tabular_models_refitted=0, vision_models_refitted=0,
            notes="25 original Tabular folds reused; GPU Vision probabilities verified. Meta/Platt/Youden use disjoint saved Validation roles only. One Test evaluation; ECE=10 equal-width bins; referrals do not count as corrected predictions. Four unlabeled S3 rows excluded.")
        run.progress("experiment_completed", test_rows=len(test), metrics=run.state["metrics"]["stacking_v3/test"])
    return run.state

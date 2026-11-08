"""Frozen v3 transfer: byte verification, overlap exclusions and unresolved-label evidence."""

import hashlib
import io
import json
from pathlib import Path
import re
import subprocess

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression

from malpdf.data.cic_normalization import (
    bounded_archive_checksum, extract_cic_rows, inventory_local_pdfs, locked_bytes,
    plan_cic_rows, validate_external_features,
)
from malpdf.data.raw_cohort import RAW_FEATURES
from malpdf.data.raw_downloads import DownloadLimits
from malpdf.data.cic_archives import extract_nested_cic_archive
from malpdf.data.rit_pdfmal_split import build_duplicate_group_ids
from malpdf.models.safe_stacking import V3Stack
from malpdf.provenance.research_runs import ResearchRun, write_json
from malpdf.static.safety import read_bounded_bytes

BRANCHES = ("xgboost", "lightgbm", "catboost", "random_forest", "ft_transformer", "vision_resnet18")


def restore_frozen_stack(lock):
    """Restore finite saved coefficients; never call fit or select a threshold."""
    if (lock.get("seed") != 42 or tuple(lock.get("branches", [])) != BRANCHES
            or lock.get("test_used_for_fitting_or_selection") is not False
            or lock.get("refit_after_selection") is not False
            or not 0 <= lock.get("threshold", -1) <= 1
            or lock.get("referral_rate") != 0.1 or lock.get("ece_bins") != 10):
        raise ValueError("Frozen Validation lock is invalid")
    restored = []
    for key, width in (("meta_learner", 6), ("platt_calibrator", 1)):
        state = lock[key]
        coef, intercept = np.asarray(state["coefficients"], float), np.asarray(state["intercept"], float)
        if (coef.shape != (1, width) or intercept.shape != (1,) or state["classes"] != [0, 1]
                or not np.isfinite(coef).all() or not np.isfinite(intercept).all()
                or not np.isfinite(state["C"]) or state["C"] <= 0):
            raise ValueError("Frozen classifier parameters are invalid")
        model = LogisticRegression(C=state["C"], random_state=42)
        model.coef_, model.intercept_ = coef.copy(), intercept.copy()
        model.classes_, model.n_features_in_, model.n_iter_ = np.array([0, 1]), width, np.array([0])
        restored.append(model)
    return V3Stack(*restored, lock["threshold"], lock["selection"], lock["validation_roles"], BRANCHES)


def extract_cic_archives(root, raw, run, *, archive_files=()):
    """Inspect manually acquired local ZIPs only; this pipeline makes no HTTP requests."""
    if not archive_files:
        return 0
    if len(archive_files) > 3 or len(set(map(str, archive_files))) != len(archive_files):
        raise ValueError("Provide at most three distinct manually acquired CIC ZIPs")
    destination = raw / run.identifier
    if (not destination.is_relative_to(root / "data/raw") or ".." in destination.parts
            or any(path.is_symlink() for path in (destination, *destination.parents))):
        raise ValueError("Unsafe acquisition directory")
    limits = DownloadLimits(max_download_bytes=1024**3, max_total_download_bytes=3 * 1024**3,
                            max_total_pdf_bytes=4 * 1024**3, max_archive_members=20_000)
    archives = []
    total = 0
    for path in archive_files:
        path = Path(path)
        path = path.absolute() if path.is_absolute() else (root / path).absolute()
        if subprocess.run(["git", "-C", str(root), "check-ignore", "-q", "--", str(path)]).returncode:
            raise ValueError("Local CIC ZIPs must be gitignored")
        checksum = bounded_archive_checksum(path, root / "data/raw", limits.max_download_bytes)
        total += checksum["bytes"]
        if total > limits.max_total_download_bytes:
            raise ValueError("Local CIC ZIPs exceed their total byte cap")
        archives.append((path, checksum))
    destination.mkdir(parents=True, exist_ok=False, mode=0o700)
    accepted, evidence = 0, []
    ledger = {"boundary": root / "data/raw", "members": 0, "pdf_bytes": 0,
              "container_bytes": 0, "container_count": 0, "seen_archives": set()}
    for index, (archive, checksum) in enumerate(archives, 1):
        write_json(run.artifacts / f"archive_{index}_checksum.json", {"path": str(archive.relative_to(root)), **checksum})
        def record(entry):
            with (run.artifacts / f"archive_{index}_members.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(entry) + "\n")
        summary = extract_nested_cic_archive(archive, destination, limits, ledger, record=record,
            progress=lambda **counts: run.progress("cic_nested_extraction", **counts))
        if bounded_archive_checksum(archive, root / "data/raw", limits.max_download_bytes) != checksum:
            raise ValueError("Local CIC ZIP changed during extraction")
        write_json(run.report / f"archive_{index}_summary.json", summary)
        accepted += summary["accepted"]
        evidence.append({"archive_index": index, **summary})
        run.progress("cic_local_zip_extracted", archive_index=index, **summary)
    write_json(run.report / "acquisition_summary.json", {"archives": evidence, "network_requests": 0})
    return accepted


def exclude_source_feature_groups(source_features, candidates, feature_order):
    """Exclude exact model-input equivalence independently of labels or row order."""
    combined = pd.concat([source_features.loc[:, feature_order], candidates.loc[:, feature_order]], ignore_index=True).astype(float)
    combined["Label"] = 0
    groups = build_duplicate_group_ids(combined)
    contained = groups.iloc[len(source_features):].isin(set(groups.iloc[:len(source_features)]))
    return contained.to_numpy()


def claim_external_evaluation(root, run, lock_sha256, identities):
    """Stable byte/label cohort lock refuses reruns even after IDs or ordering change."""
    if (len(lock_sha256) != 64 or any(c not in "0123456789abcdef" for c in lock_sha256)
            or identities.empty or not identities.pdf_sha256.is_unique
            or not identities.pdf_sha256.str.fullmatch(r"[0-9a-f]{64}").all()
            or not identities.Label.isin([0, 1]).all()):
        raise ValueError("External cohort identities/labels are invalid")
    content = identities[["pdf_sha256", "Label"]].sort_values("pdf_sha256").to_dict("records")
    cohort_key = hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()
    markers = root / "artifacts/cic_external_evaluation_locks"
    if any(path.is_symlink() for path in (markers, *markers.parents)):
        raise ValueError("Unsafe external evaluation marker directory")
    markers.mkdir(parents=True, exist_ok=True)
    marker = markers / (lock_sha256 + "_" + cohort_key + ".json")
    write_json(marker, {"report": str(run.report.relative_to(root)), "allowed_evaluations": 1})
    write_json(run.report / "external_evaluation_started.json", {"cohort_key": cohort_key, "marker": str(marker.relative_to(root))})


def _evaluate_frozen(root, run, config, reference, lock, features, cache):
    """One external inference pass with original folds, imputation and Vision weights."""
    import torch
    from malpdf.data.markov_arrays import MAX_CACHE_BYTES, load_markov_npy
    from malpdf.deep_learning.training import set_deep_learning_seed
    from malpdf.evaluation.selective import calibration_metrics
    from malpdf.experiments.raw_tri_modal_v3 import group_folds, fail_closed_routing
    from malpdf.models.late_fusion import entropy_routing
    from malpdf.models.v3_base_learners import load_v3_fold
    from malpdf.models.vision_resnet import VisionResNet18
    from malpdf.reproducibility import set_random_seed

    validate_external_features(features)
    set_random_seed(42)
    set_deep_learning_seed(42)
    torch.set_num_threads(2)
    train_features = pd.read_csv(io.BytesIO(locked_bytes(root, reference["inputs"]["dataset"], "data/processed")))
    manifest = pd.read_csv(io.BytesIO(locked_bytes(root, reference["inputs"]["split_manifest"], "data/processed")))
    train = train_features.set_index("sample_id").loc[manifest.loc[manifest.split.eq("train"), "sample_id"]].reset_index()
    train_manifest = manifest.loc[manifest.split.eq("train")].reset_index(drop=True)
    folds = group_folds(train_manifest, partition="train", count=5)
    plan_path = root / "artifacts/kaggle_handoff" / reference["handoff_run"] / "local_tabular_reuse_plan.json"
    plan = json.loads(read_bounded_bytes(plan_path, boundary=root / "artifacts/kaggle_handoff", max_bytes=1024**2))
    if plan["prior_run"] != reference["prior_tabular_run"] or len(plan["checkpoints"]) != 25:
        raise ValueError("Original 25-fold model plan is unavailable")
    training_config = json.loads(read_bounded_bytes(root / config["reference"]["directory"] / "locked_methodology.json",
        boundary=root / "reports/experiments", max_bytes=1024**2))["configuration"]

    saved_hashes = {(info["model"], i % 5 + 1): info["checkpoint_sha256"]
                    for i, info in enumerate(lock["base_fit_metadata"])}
    models = {}
    for name in BRANCHES[:-1]:
        models[name] = []
        for i, (fit, _) in enumerate(folds, 1):
            entries = [entry for entry in plan["checkpoints"] if entry["model"] == name
                       and Path(entry["path"]).parent.name == f"fold_{i}"]
            if len(entries) != 1 or entries[0]["sha256"] != saved_hashes[(name, i)]:
                raise ValueError("Saved fold identity differs from the original lock")
            entry = entries[0]
            model, _ = load_v3_fold(root / entry["path"], entry["sha256"], train.iloc[fit].loc[:, lock["feature_order"]],
                training_config, boundary=root / "artifacts/raw_tri_modal_v3" / plan["prior_run"],
                base_selection_rows=lock["validation_roles"]["base_selection"]["rows"])
            models[name].append(model)
    directory = root / config["vision_directory"]
    content = read_bounded_bytes(directory / "vision_resnet_best.pt", boundary=root / "checkpoints", max_bytes=64 * 1024**2)
    if hashlib.sha256(content).hexdigest() != lock["vision"]["checkpoint_sha256"]:
        raise ValueError("Original Vision checkpoint checksum differs")
    state = torch.load(io.BytesIO(content), map_location="cpu", weights_only=True)
    if (state["architecture"] != "single_channel_resnet18" or state["seed"] != 42
            or state["best_epoch"] != lock["vision"]["best_epoch"]
            or any(not torch.isfinite(value).all() for value in state["model_state_dict"].values())):
        raise ValueError("Original Vision checkpoint metadata differs")
    vision = VisionResNet18().eval()
    vision.load_state_dict(state["model_state_dict"], strict=True)
    stack = restore_frozen_stack(lock)
    identities = features[["sample_id", "Label"]].merge(cache[["sample_id", "pdf_sha256"]], on="sample_id", validate="one_to_one")
    claim_external_evaluation(root, run, config["reference"]["validation_lock_sha256"], identities)
    scores = np.column_stack([np.mean([model.predict_proba(features.loc[:, lock["feature_order"]])
        for model in models[name]], axis=0) for name in BRANCHES[:-1]] + [np.zeros(len(features))])
    paths = cache.set_index("sample_id")
    with torch.inference_mode():
        for start in range(0, len(features), 16):
            matrices = []
            for identifier in features.sample_id.iloc[start:start + 16]:
                row = paths.loc[identifier]
                data = read_bounded_bytes(root / row.cache_relative_path, boundary=root / "data/processed/markov_cache", max_bytes=MAX_CACHE_BYTES)
                if hashlib.sha256(data).hexdigest() != row.npy_sha256:
                    raise ValueError("External Markov checksum changed")
                matrices.append(load_markov_npy(data))
            batch = torch.from_numpy(np.stack(matrices)).unsqueeze(1)
            scores[start:start + len(batch), -1] = vision.predict_proba(batch).flatten().numpy()
    fused = stack.predict_proba(scores)
    metrics = calibration_metrics(features.Label, fused, threshold=stack.threshold)
    pure, _ = entropy_routing(features.Label, fused, features.sample_id, threshold=stack.threshold)
    closed, referred = fail_closed_routing(features.Label, fused, features.sample_id, features.parser_failed, threshold=stack.threshold)
    write_json(run.report / "routing_analysis.json", [pure, closed])
    pd.DataFrame([{k: v for k, v in row.items() if k != "retained_metrics"} for row in (pure, closed)]).to_csv(
        run.report / "routing_analysis.csv", index=False)
    run.state["metrics"]["stacking_v3/cic_independent_external"] = metrics
    run.state["metrics"]["stacking_v3/cic_retained"] = closed["retained_metrics"]
    pd.DataFrame({"sample_id": features.sample_id, "Label": features.Label, "p_fused": fused,
                  "referred": referred}).to_csv(run.artifacts / "external_predictions.csv", index=False)
    run.state.update(external_evaluation_count=1, base_models_refitted=0, meta_models_refitted=0,
                     threshold=stack.threshold, routing=[pure, closed])

    baseline = reference["metrics"]["stacking_v3/test"]
    pd.DataFrame([{"cohort": "original_protocol_g_test", "status": "copied_saved_evidence", **baseline},
                  {"cohort": "cic_independent_external", "status": "evaluated_once", **metrics}]).to_csv(
        run.report / "cross_dataset_comparison.csv", index=False)


def run_cic_cross_dataset(root, code_root, config, *, archive_files=(),
                          audit_conflicts=False, evaluate=False):
    if config["seed"] != 42 or type(config["workers"]) is not int or not 1 <= config["workers"] <= 2:
        raise ValueError("Locked seed and bounded parser workers are required")
    methodology = {"configuration": config, "audit_conflicts": audit_conflicts, "evaluate": evaluate,
        "label_policy": "Keep both original labels and provenance. Static evidence is not ground truth; unresolved conflicts remain excluded.",
        "overlap_policy": "Exclude every known source identity across all original partitions, including agreeing labels; also exclude source-equivalent feature vectors.",
        "feature_policy": "Same v3 isolated parser, all 43 raw columns retained; frozen 40-feature input; raw nulls/parser flags preserved.",
        "model_policy": "Restore frozen 25 Train-fold models and Vision checkpoint; no fitting, calibration or threshold tuning on CIC.",
        "cohort_policy": "Require all usable independent target identities to have verified raw bytes before evaluation; no available-only subset selection.",
        "referral_policy": "Frozen entropy 10% policy; parser errors force referral; no dynamic execution or corrected-prediction credit."}
    with ResearchRun(root, "cic_normalization_v3", methodology, code_root=code_root) as run:
        if evaluate and run.state["code_worktree"]["status"] != "clean":
            raise ValueError("Official external evaluation requires clean committed code")
        spec = config["reference"]
        directory = root / spec["directory"]
        reference = json.loads(locked_bytes(root, {"path": str((directory / "run_summary.json").relative_to(root)),
            "sha256": spec["summary_sha256"]}, "reports/experiments"))
        lock = json.loads(locked_bytes(root, {"path": str((directory / "validation_lock.json").relative_to(root)),
            "sha256": spec["validation_lock_sha256"]}, "reports/experiments"))
        restore_frozen_stack(lock)
        if reference["status"] != "completed" or reference["test_evaluation_count"] != 1:
            raise ValueError("Completed original v3 evidence is required")
        target = pd.read_parquet(io.BytesIO(locked_bytes(root, config["target"], "data/raw")))
        source = pd.read_csv(io.BytesIO(locked_bytes(root, reference["inputs"]["source_manifest"], "data/processed")), keep_default_na=False)
        plan = plan_cic_rows(target, source)
        raw = root / config["raw_directory"]
        downloaded = extract_cic_archives(root, raw, run, archive_files=archive_files)
        local = inventory_local_pdfs(root, raw, max_files=40_000)
        plan["pdf_relative_path"] = plan.pdf_sha256.map(local).fillna("")
        plan["target_pdf_byte_verified"] = plan.pdf_relative_path.ne("")
        available = plan.exclusion_reason.eq("") & plan.pdf_relative_path.ne("")
        audit = plan.label_conflict & plan.source_overlap if audit_conflicts else pd.Series(False, index=plan.index)
        plan.loc[audit & plan.pdf_relative_path.eq(""), "pdf_relative_path"] = plan.loc[audit, "source_pdf_relative_path"]


        selected = plan.loc[plan.pdf_relative_path.ne("")].copy()
        data = root / "data/processed/cic_normalization" / run.identifier
        if any(path.is_symlink() for path in (data, *data.parents)):
            raise ValueError("Unsafe normalized output path")
        data.mkdir(parents=True, exist_ok=False)
        plan.to_csv(data / "normalization_manifest.csv", index=False)
        fields = ["sample_id", "cic_identifier", "pdf_sha256", "target_pdf_byte_verified", "Label", "target_label_source",
                  "source_sample_id", "source_Label", "source_label_source", "ground_truth_status", "exclusion_reason"]
        plan.loc[plan.source_overlap, fields].to_csv(data / "label_audit.csv", index=False)
        features = cache = None
        if len(selected):
            features, cache = extract_cic_rows(root, selected, data / "static_extraction", workers=config["workers"],
                progress=lambda **counts: run.progress("cic_static_preparation", **counts))
        independent = plan.loc[plan.exclusion_reason.eq("")].copy()
        missing = int(independent.pdf_relative_path.eq("").sum())
        evidence = {"target_rows": len(plan), "known_source_overlap": int(plan.source_overlap.sum()),
            "unresolved_label_conflicts": int(plan.label_conflict.sum()), "unsupported_identifiers": int(plan.pdf_sha256.eq("").sum()),
            "independent_identity_candidates": len(independent), "independent_raw_missing": missing,
            "raw_pdf_members_extracted": downloaded, "network_requests": 0, "local_raw_pdf_hashes": len(local),
            "conflict_rows_reparsed_for_audit": int(audit.sum()), "features_and_cache_prepared": len(selected),
            "target_labels_changed": 0, "ground_truth_adjudications": 0, "source_inspection": config["source_inspection"],
            "outputs": str(data.relative_to(root)), "related_sample_limit": "Known exact identities and model-input feature groups checked; unknown family relationships are not asserted."}
        if features is not None:
            evidence.update(raw_feature_columns=len(RAW_FEATURES), frozen_model_feature_columns=len(lock["feature_order"]),
                parser_failure_rows=int(features.parser_failed.sum()),
                raw_missing_cells=int(features.loc[:, list(RAW_FEATURES)].isna().sum().sum()),
                cache_created=int(cache.status.eq("created").sum()), cache_reused=int(cache.status.eq("reused").sum()))
        eligible = None
        if features is not None and available.any():
            eligible = features.set_index("sample_id").loc[plan.loc[available, "sample_id"]].reset_index()
            source_features = pd.read_csv(io.BytesIO(locked_bytes(root, reference["inputs"]["all_features"], "data/processed")))
            contained = exclude_source_feature_groups(source_features, eligible, lock["feature_order"])
            evidence["source_feature_group_overlap_excluded"] = int(contained.sum())
            excluded_ids = eligible.loc[contained, "sample_id"]
            plan.loc[plan.sample_id.isin(excluded_ids), "exclusion_reason"] = "source_feature_group_overlap"
            eligible = eligible.loc[~contained].reset_index(drop=True)
        plan.to_csv(data / "final_eligibility_manifest.csv", index=False)
        write_json(run.report / "normalization_summary.json", evidence)
        run.state.update(**evidence, external_evaluation_count=0, original_test_reevaluations=0,
            notes="CIC labels preserved; static evidence cannot adjudicate ground truth. Every known source overlap excluded, including agreeing labels. Conflicting local source bytes may be reparsed for audit only; never included in external metrics. Original models, calibration, threshold and Test preserved.")
        if missing or eligible is None or eligible.empty:
            run.state.update(status="blocked", notes=run.state["notes"] +
                f" Independent raw PDFs missing={missing}; no usable verified external cohort, metrics/routing N/A. Manually acquired raw-CIC ZIPs or a local corpus are required.")
            pd.DataFrame([{"cohort": "cic_independent_external", "status": "blocked", **{key: "N/A" for key in
                ("accuracy", "f1_malicious", "mcc", "brier", "log_loss", "ece")}}]).to_csv(
                    run.report / "cross_dataset_comparison.csv", index=False)
        elif evaluate:
            if set(eligible.Label) != {0, 1}:
                raise ValueError("External cohort must retain both malicious and benign labels")
            write_json(run.report / "locked_external_cohort.json", {"source_lock": spec,
                "rows": len(eligible), "feature_order": lock["feature_order"], "threshold": lock["threshold"],
                "identity_digest": hashlib.sha256(eligible[["sample_id", "Label"]].to_csv(index=False).encode()).hexdigest()})
            _evaluate_frozen(root, run, config, reference, lock, eligible, cache)
        else:
            run.state["notes"] += " Preparation only; external inference not requested."
    return run.state


def evaluate_prepared_cic(root, code_root, config, prepared_run, *, allow_input_referrals=False):
    """Lock a separately reported valid-PDF cohort; reuse measured data without reparsing."""
    if not re.fullmatch(r"run_[A-Za-z0-9_-]{1,100}", prepared_run):
        raise ValueError("Unsafe preparation run identifier")
    methodology = {"configuration": config, "prepared_run": prepared_run,
        "allow_input_referrals": allow_input_referrals,
        "scope": "Independent verified valid PDFs only; metrics do not cover the whole CIC table.",
        "cohort_policy": "All byte-verified independent rows passing fixed PDF caps; exclude every source identity and exact model-input feature group before scoring.",
        "input_failures": "Report missing/refused raw inputs separately with mandatory referral; no invented features, probabilities, ground truth or corrected-prediction credit.",
        "model_policy": "Frozen original folds, Train-only preprocessing, Vision, Validation-only meta/Platt/Youden; zero refits.",
        "routing_policy": "Entropy/parser 10% on modelable cohort, plus separate forced input referrals; report combined coverage explicitly.",
        "label_policy": "Preserve publisher labels; static tokens and archive names do not adjudicate ground truth."}
    with ResearchRun(root, "cic_valid_pdf_evasion_v3", methodology, code_root=code_root) as run:
        if run.state["code_worktree"]["status"] != "clean":
            raise ValueError("Official external evaluation requires clean committed code")
        prep_path = root / "reports/experiments/cic_normalization_v3" / prepared_run / "run_summary.json"
        prep_bytes = read_bounded_bytes(prep_path, boundary=root / "reports/experiments", max_bytes=1024**2)
        prepared = json.loads(prep_bytes)
        if (prepared["status"] not in {"completed", "blocked"} or prepared["external_evaluation_count"] != 0
                or prepared["original_test_reevaluations"] != 0 or prepared["target_labels_changed"] != 0):
            raise ValueError("Unscored unchanged-label preparation is required")
        measured = root / prepared["outputs"]
        files = {"features": measured / "static_extraction/raw_v3_features.csv",
                 "cache": measured / "static_extraction/cache_manifest.csv",
                 "plan": measured / "final_eligibility_manifest.csv"}
        payloads = {key: read_bounded_bytes(path, boundary=root / "data/processed", max_bytes=32 * 1024**2)
                    for key, path in files.items()}
        pins = {key: {"path": str(files[key].relative_to(root)), "sha256": hashlib.sha256(value).hexdigest()}
                for key, value in payloads.items()}
        plan = pd.read_csv(io.BytesIO(payloads["plan"]), keep_default_na=False)
        features = pd.read_csv(io.BytesIO(payloads["features"]))
        cache = pd.read_csv(io.BytesIO(payloads["cache"]))
        if (len(plan) != prepared["target_rows"] or not plan.sample_id.is_unique
                or not features.sample_id.is_unique or not cache.sample_id.is_unique
                or not plan.Label.isin([0, 1]).all()):
            raise ValueError("Prepared input identities or labels are invalid")
        spec = config["reference"]
        directory = root / spec["directory"]
        reference = json.loads(locked_bytes(root, {"path": str((directory / "run_summary.json").relative_to(root)),
            "sha256": spec["summary_sha256"]}, "reports/experiments"))
        lock = json.loads(locked_bytes(root, {"path": str((directory / "validation_lock.json").relative_to(root)),
            "sha256": spec["validation_lock_sha256"]}, "reports/experiments"))
        restore_frozen_stack(lock)
        if reference["status"] != "completed" or reference["test_evaluation_count"] != 1:
            raise ValueError("Completed original v3 reference is required")
        target = pd.read_parquet(io.BytesIO(locked_bytes(root, config["target"], "data/raw")))
        sources = pd.read_csv(io.BytesIO(locked_bytes(root, reference["inputs"]["source_manifest"], "data/processed")), keep_default_na=False)
        authoritative = plan_cic_rows(target, sources).set_index("sample_id")
        columns = ["Label", "pdf_sha256", "source_overlap", "cic_identifier"]
        if (set(authoritative.index) != set(plan.sample_id)
                or not authoritative.loc[plan.sample_id, columns].reset_index(drop=True).equals(plan.loc[:, columns].reset_index(drop=True))
                or (plan.source_overlap & plan.exclusion_reason.eq("")).any()
                or not plan.target_pdf_byte_verified.isin([True, False]).all()):
            raise ValueError("Prepared cohort differs from locked publisher identities, labels or source exclusions")
        selection = plan.exclusion_reason.eq("")
        input_failures = plan.loc[selection & ~plan.target_pdf_byte_verified].copy()
        ids = plan.loc[selection & plan.target_pdf_byte_verified, "sample_id"]
        if len(input_failures) and not allow_input_referrals:
            raise ValueError("Incomplete full cohort requires a separately declared valid-PDF/referral study")
        eligible = features.set_index("sample_id").loc[ids].reset_index()
        truth = plan.set_index("sample_id").loc[ids, "Label"].to_numpy()
        if not np.array_equal(eligible.Label.to_numpy(), truth):
            raise ValueError("Measured rows and preserved publisher labels differ")
        source = pd.read_csv(io.BytesIO(locked_bytes(root, reference["inputs"]["all_features"], "data/processed")))


        contained = exclude_source_feature_groups(source, eligible, lock["feature_order"])
        additional_exclusions = int(contained.sum())
        eligible.loc[contained].to_csv(run.artifacts / "additional_source_feature_exclusions.csv", index=False)
        eligible = eligible.loc[~contained].reset_index(drop=True)
        ids = eligible.sample_id
        if set(eligible.Label) != {0, 1} or eligible.empty:
            raise ValueError("External cohort needs both malicious and benign labels")
        cached = cache.set_index("sample_id").loc[ids].reset_index()
        hashes = plan.set_index("sample_id").loc[ids, "pdf_sha256"].to_numpy()
        if not np.array_equal(cached.pdf_sha256.to_numpy(), hashes):
            raise ValueError("Prepared Markov identities differ from verified PDF bytes")
        validate_external_features(eligible)
        write_json(run.report / "locked_external_cohort.json", {"prepared_run": prepared_run,
            "prepared_summary_sha256": hashlib.sha256(prep_bytes).hexdigest(), "inputs": pins,
            "reference": spec, "evaluated_rows": len(eligible), "input_referrals": len(input_failures),
            "additional_source_feature_group_exclusions_after_CSV_loading": additional_exclusions,
            "labels": {str(label): int(count) for label, count in eligible.Label.value_counts().items()},
            "feature_order": lock["feature_order"], "threshold": lock["threshold"], "seed": 42,
            "metrics_scope": "Verified independent valid PDFs only; no metrics on unavailable inputs or whole CIC table"})
        run.state.update(evaluated_rows=len(eligible), input_referrals=len(input_failures),
            source_identity_exclusions=int(plan.source_overlap.sum()),
            source_feature_group_exclusions=int(plan.exclusion_reason.eq("source_feature_group_overlap").sum()) + additional_exclusions,
            unsupported_identifiers=int(plan.exclusion_reason.eq("unsupported_identifier_requires_publisher_mapping").sum()),
            notes="Separately locked valid-PDF CIC cohort only; source identities and feature groups excluded. Publisher labels retained but not independently adjudicated. Input refusals have no probabilities or F1/MCC credit. Original Test not rerun; all base/meta/calibration/threshold state frozen.")
        _evaluate_frozen(root, run, config, reference, lock, eligible, cached)
        input_failures.to_csv(run.artifacts / "mandatory_input_referrals.csv", index=False)
        routed = run.state["routing"][1]
        denominator = len(eligible) + len(input_failures)
        write_json(run.report / "input_referral_analysis.json", {"evaluated_valid_pdf_rows": len(eligible),
            "unscored_input_referrals": len(input_failures), "valid_pdf_referrals": routed["referred_count"],
            "combined_referral_rate": (len(input_failures) + routed["referred_count"]) / denominator,
            "combined_static_coverage": (len(eligible) - routed["referred_count"]) / denominator,
            "scope_denominator": denominator, "input_referrals_counted_as_corrected": False,
            "input_failure_probabilities_and_FN_catch": "N/A: no model predictions for unavailable inputs"})
    return run.state

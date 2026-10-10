"""Fixed CIC development profiling; reuse the engine, manifests and provenance."""

from collections import Counter, defaultdict
from dataclasses import asdict
from datetime import datetime, timezone
import csv
import hashlib
import importlib.metadata
import io
import json
import math
from pathlib import Path
import re
import subprocess
from time import perf_counter
import os
import resource

import numpy as np
import yaml

from malpdf.provenance.research_runs import ResearchRun, write_json
from malpdf.reproducibility import set_random_seed
from malpdf.static.code_inspector import CodeInspectionLimits, CODE_INSPECTION_SCHEMA_VERSION, SECURITY_NAMES
from malpdf.static.lab_guard import require_offline_lab
from malpdf.static.profiling import STAGES, PROFILE_VERSION, StageTimings
from malpdf.static.safety import read_bounded_bytes


def clean_code(root):
    if subprocess.check_output(["git", "-C", str(root), "status", "--porcelain"], text=True).strip():
        raise ValueError("Official CIC job requires clean committed code")


def restore_profile_model(root, source):
    root = Path(root).absolute()
    clean_code(root)
    from malpdf.inference.deployment import restore_verified_deployment_model
    with ResearchRun(root, "cic_model_restore", {"protocol": "restore checksum-pinned existing deployment JSON", "test_access": False,
            "fitting": False, "pdf_access": False}) as run:
        result = restore_verified_deployment_model(root, source)
        write_json(run.report / "restoration.json", result)
        run.state["notes"] = "Existing deployment JSON restored/verified by manifest SHA,38-feature order and saved configuration; no fitting/PDF/Test access. Artifact stays ignored."
    return run.state


SUPPLIED_G_MODEL_ID = "xgb-rit-supplied-g-drop3constant-v1"


def snapshot_protocol_g_model(root, source, destination):
    """Freeze the user's trusted Windows estimator as native JSON, without fitting."""
    import joblib
    import pandas as pd
    from xgboost import XGBClassifier
    from malpdf.inference.deployment import _assert_saved_xgboost_structure, deployment_model_configuration
    from malpdf.inference.schema import DEPLOYMENT_FEATURE_ORDER, DEPLOYMENT_FEATURE_SCHEMA, EXPECTED_DATASET_SHA256
    root, source, destination = Path(root).absolute(), Path(source).absolute(), Path(destination).absolute()
    if source != root / "artifacts/models/xgboost__G-drop3constant.joblib":
        raise ValueError("Select the trusted Windows G-drop3constant artifact at its controlled local path")
    if (destination.exists() or not destination.is_relative_to(root / "artifacts/cic_static_prepare")
            or any(part.is_symlink() for part in (destination, *destination.parents))):
        raise ValueError("Refusing to overwrite or escape the new prepared-run model snapshot")
    content = read_bounded_bytes(source, boundary=root / "artifacts/models", max_bytes=64 * 1024**2)
    model = joblib.load(io.BytesIO(content))
    if type(model) is not XGBClassifier or not np.array_equal(model.classes_, [0, 1]):
        raise ValueError("Saved estimator must be a binary XGBClassifier with Label=1 malicious")
    if tuple(model.get_booster().feature_names or ()) != DEPLOYMENT_FEATURE_ORDER:
        raise ValueError("Saved estimator differs from the required 38-feature order")
    configuration = deployment_model_configuration()
    parameters = model.get_params()
    for name, expected in configuration["parameters"].items():
        observed = parameters.get(name)
        if name == "missing" and expected == "NaN":
            matches = isinstance(observed, (float, np.floating)) and np.isnan(observed)
        else:
            matches = observed == expected
        if not matches:
            raise ValueError(f"Saved estimator differs from the fixed configuration: {name}")
    _assert_saved_xgboost_structure(model)
    probe = pd.DataFrame([np.zeros(38), np.ones(38)], columns=DEPLOYMENT_FEATURE_ORDER)
    original = model.predict_proba(probe)
    destination.parent.mkdir(parents=True, exist_ok=True)
    model.save_model(str(destination))
    spec = {"model_id": SUPPLIED_G_MODEL_ID, "artifact_relative_path": str(destination.relative_to(root)),
        "artifact_sha256": hashlib.sha256(destination.read_bytes()).hexdigest(), "feature_schema": DEPLOYMENT_FEATURE_SCHEMA,
        "feature_order": list(DEPLOYMENT_FEATURE_ORDER), "threshold": 0.5, "model_configuration": configuration,
        "training_dataset": {"sha256": EXPECTED_DATASET_SHA256,
            "fit_scope": "user-reported original Protocol G Train; training lineage not independently verified"},
        "source": {"relative_path": str(source.relative_to(root)), "sha256": hashlib.sha256(content).hexdigest(),
            "bytes": len(content), "trust": "user supplied original locally trained Windows artifact",
            "historical_model_checksum_available": False},
        "conversion": "native XGBoost JSON; no fitting; exact probability parity on two synthetic numeric probe rows"}
    try:
        frozen, _ = load_profile_model(root, spec)
        if not np.array_equal(original, frozen.predict_proba(probe)):
            raise ValueError("Native snapshot changed the saved estimator's probe probabilities")
    except Exception:
        destination.unlink()
        raise
    return spec


def profile_model_bytes(root, spec):
    """Check the locked identity and bounded native snapshot before model loading."""
    from malpdf.inference.deployment import deployment_model_configuration
    from malpdf.inference.schema import DEPLOYMENT_FEATURE_ORDER, DEPLOYMENT_FEATURE_SCHEMA, EXPECTED_DATASET_SHA256
    expected = {"model_id": SUPPLIED_G_MODEL_ID, "feature_schema": DEPLOYMENT_FEATURE_SCHEMA,
        "feature_order": list(DEPLOYMENT_FEATURE_ORDER), "threshold": 0.5, "model_configuration": deployment_model_configuration()}
    if any(spec.get(key) != value for key, value in expected.items()) or spec.get("training_dataset", {}).get("sha256") != EXPECTED_DATASET_SHA256:
        raise ValueError("Prepared inference model contract changed")
    path = Path(spec["artifact_relative_path"])
    if path.is_absolute() or ".." in path.parts or not path.is_relative_to("artifacts/cic_static_prepare"):
        raise ValueError("Prepared model snapshot outside its private boundary")
    content = read_bounded_bytes(root / path, boundary=root / "artifacts/cic_static_prepare", max_bytes=64 * 1024**2)
    if hashlib.sha256(content).hexdigest() != spec["artifact_sha256"]:
        raise ValueError("Prepared inference model checksum changed")
    return content


def load_profile_model(root, spec):
    from xgboost import XGBClassifier
    from malpdf.inference.deployment import _assert_saved_xgboost_structure
    from malpdf.inference.schema import DEPLOYMENT_FEATURE_ORDER
    content = profile_model_bytes(root, spec)
    model = XGBClassifier()
    model.load_model(bytearray(content))
    if tuple(model.get_booster().feature_names or ()) != DEPLOYMENT_FEATURE_ORDER or not np.array_equal(model.classes_, [0, 1]):
        raise ValueError("Native snapshot changed the binary 38-feature model contract")
    _assert_saved_xgboost_structure(model)
    return model, spec


def checked_table(root, spec):
    content = read_bounded_bytes(root / spec["path"], boundary=root / "data/processed", max_bytes=32 * 1024**2)
    if hashlib.sha256(content).hexdigest() != spec["sha256"]:
        raise ValueError("Saved manifest checksum changed")
    return list(csv.DictReader(io.StringIO(content.decode("utf-8"))))


def select_subset(manifest, sources, count=32, seed=42):
    """Row selection changes no partition/group; choose without parser outcomes."""
    if seed != 42 or type(count) is not int or not 8 <= count <= 256 or count % 2:
        raise ValueError("Invalid fixed subset budget")
    indexed = {row["sample_id"]: row for row in sources}
    if len(indexed) != len(sources) or len({row["sample_id"] for row in manifest}) != len(manifest):
        raise ValueError("Repeated manifest identity")
    assignments = defaultdict(set)
    for row in manifest:
        source = indexed.get(row["sample_id"])
        if source is None or source["Label"] != row["Label"] or row["split"] not in {"train", "validation", "test"}:
            raise ValueError("Manifest/source labels or split invalid")
        for key in ("duplicate_group_id",):
            assignments[(key, row[key])].add(row["split"])
        for key in ("pdf_sha256", "related_group_id"):
            assignments[(key, source[key])].add(row["split"])
    if any(len(splits) != 1 for splits in assignments.values()):
        raise ValueError("Saved file or related/equivalent group crosses partitions")
    chosen = []
    for partition in ("train", "validation"):
        for label in ("0", "1"):
            cell = [row for row in manifest if row["cohort"] == "cic" and row["split"] == partition and row["Label"] == label]
            cell.sort(key=lambda row: hashlib.sha256(f"{seed}:{row['sample_id']}".encode()).hexdigest())
            if len(cell) < count // 2:
                raise ValueError("Insufficient samples in a CIC development stratum")
            for row in cell[:count // 2]:
                source = indexed[row["sample_id"]]
                path = Path(source["pdf_relative_path"])
                if path.is_absolute() or ".." in path.parts or not path.is_relative_to("data/raw/cic_pdf"):
                    raise ValueError("CIC PDF path outside its raw boundary")
                if re.fullmatch(r"[0-9a-f]{64}", source["pdf_sha256"]) is None:
                    raise ValueError("Invalid saved PDF identity")
                chosen.append({**row, **{name: source[name] for name in ("pdf_sha256", "pdf_relative_path", "related_group_id")}})
    return chosen


def source_fingerprint(root, limits):
    import platform
    from xml.parsers import expat
    paths = ("static/analyzer.py", "static/pdf_parser.py", "static/rit_reference.py", "static/raw_scan.py",
             "static/code_inspector.py", "static/js_ast.py", "static/xfa_xml.py", "static/profiling.py", "static/profile_worker.py",
             "static/schema.py", "static/result.py", "static/safety.py", "static/lab_guard.py", "static/parser_diagnostics.py",
             "experiments/cic_static_benchmark.py", "experiments/cic_static_accuracy.py",
             "inference/predictor.py", "inference/schema.py", "inference/deployment.py")
    paths += ("static/recovery.py", "static/evidence.py", "inference/evidence_policy.py", "experiments/cic_v8.py")
    return {"profile_version": PROFILE_VERSION, "code_schema": CODE_INSPECTION_SCHEMA_VERSION,
            "evidence_schema": "pdf-evidence-v8",
            "limits": asdict(limits), "backends": {**{name: importlib.metadata.version(name) for name in ("pypdf", "PyMuPDF", "esprima")},
                                                   "python": platform.python_version(), "expat": expat.EXPAT_VERSION},
            "sources": {path: hashlib.sha256((root / "src/malpdf" / path).read_bytes()).hexdigest() for path in paths}}


def verify_label_provenance(rows, normalized):
    indexed = defaultdict(list)
    for row in normalized:
        indexed[row["pdf_sha256"]].append(row)
    for row in rows:
        aliases = indexed[row["pdf_sha256"]]
        matches = [item for item in aliases if item["pdf_relative_path"] == row["pdf_relative_path"]
                   and item["target_pdf_byte_verified"] == "True" and item["target_label_source"]]
        if not matches or {item["Label"] for item in aliases} != {row["Label"]}:
            raise ValueError("CIC publisher label/path provenance differs from normalized manifest")
        row["label_source"] = matches[0]["target_label_source"]
    return rows


def baseline_method(root, identifier):
    if not re.fullmatch(r"run_[A-Za-z0-9_-]{1,100}", identifier or ""):
        raise ValueError("Unsafe baseline-run identifier")
    directory = root / "reports/experiments/cic_static_profile" / identifier
    state = json.loads(read_bounded_bytes(directory / "run_summary.json", boundary=root / "reports/experiments", max_bytes=1024**2))
    if state["status"] != "completed":
        raise ValueError("Baseline profile did not complete")
    return json.loads(read_bounded_bytes(directory / "locked_methodology.json", boundary=root / "reports/experiments", max_bytes=1024**2))


def reuse_baseline_model(root, baseline, destination):
    """Copy the verified native snapshot byte-for-byte; never unpickle or fit."""
    spec = baseline.get('inference_model')
    if spec is None:
        return None
    content = profile_model_bytes(root, spec)
    with destination.open('xb') as output:
        output.write(content)
    copied = {**spec, 'artifact_relative_path': str(destination.relative_to(root))}
    profile_model_bytes(root, copied)
    return copied


def prepare_cic_profile(root, config, *, baseline_run=None, model_file=None):
    root = Path(root).absolute()
    clean_code(root)
    cfg = yaml.safe_load(Path(config).read_text())
    if cfg["seed"] != 42 or cfg["workers"] != 1 or not 1 <= cfg["warm_repeats"] <= 3 or cfg["threshold"] != 0.5:
        raise ValueError("Locked seed/worker/threshold/warm budget changed")
    limits = CodeInspectionLimits(**cfg["limits"])
    method = {"protocol": "fixed CIC Train/dev diagnostic subset preparation", "configuration": cfg,
              "baseline_run": baseline_run,
              "model_request": "existing user-supplied Windows G-drop3constant estimator, no fitting" if model_file else "existing deployment JSON if available",
              "selection": "seed42 SHA-256 rank of saved identity within class/partition; no PDF reads or parser-driven selection",
              "split": "saved partitions/groups unchanged; no Test identities selected", "test_access": False,
              "interpretation": "balanced diagnostic pilot; Validation previously exposed, not an independent Test"}
    with ResearchRun(root, "cic_static_prepare", method) as run:
        rows = select_subset(checked_table(root, cfg["split_manifest"]), checked_table(root, cfg["source_manifest"]),
                             cfg["samples_per_partition"], cfg["seed"])
        verify_label_provenance(rows, checked_table(root, cfg["normalization_manifest"]))
        subset = run.artifacts / "subset.csv"
        with subset.open("x", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=list(rows[0]))
            writer.writeheader(); writer.writerows(rows)
        subset_digest = hashlib.sha256(subset.read_bytes()).hexdigest()
        if baseline_run is not None:
            baseline = baseline_method(root, baseline_run)
            if cfg != baseline["configuration"] or subset_digest != baseline["subset_sha256"]:
                raise ValueError("Baseline configuration/subset changed: preserve the same64 rows, labels and partitions")
        fingerprint = source_fingerprint(root, limits)
        destination = run.artifacts / 'frozen_protocol_g.json'
        inference_model = (snapshot_protocol_g_model(root, model_file, destination) if model_file else
                           reuse_baseline_model(root, baseline, destination) if baseline_run else None)
        if inference_model is not None:
            write_json(run.report / "inference_model.json", inference_model)
        lock = {"configuration": cfg, "subset_path": str(subset.relative_to(root)), "baseline_run": baseline_run,
                "inference_model": inference_model,
                "subset_sha256": subset_digest, "rows": len(rows),
                "fingerprint": fingerprint, "created_at_utc": datetime.now(timezone.utc).isoformat()}
        from malpdf.experiments.cic_v8 import V7_RUN, baseline_evidence_checksums, locked_v8_design
        if baseline_run == V7_RUN:
            if not cfg['compare_models'] or inference_model is None:
                raise ValueError('V8 acceptance requires fixed model/regression comparisons')
            lock['v8_design'] = locked_v8_design()
            lock['baseline_evidence_checksums'] = baseline_evidence_checksums(root)
        write_json(run.artifacts / "job_lock.json", lock)
        counts = Counter((row["split"], row["Label"]) for row in rows)
        write_json(run.report / "subset_summary.json", {"rows": len(rows),
            "class_partition_counts": {f"{split}/{label}": n for (split, label), n in counts.items()},
            "subset_checksum": lock["subset_sha256"], "sample_identities": "private ignored artifacts only",
            "metadata_checksums": {name: cfg[name]["sha256"] for name in ("split_manifest", "source_manifest", "normalization_manifest")},
            "actual_pdf_hash_verification": "deferred to offline worker; no PDF bytes read here"})
        run.state.update(status="completed", job_lock_sha256=hashlib.sha256((run.artifacts / "job_lock.json").read_bytes()).hexdigest(),
            rows=len(rows), notes="Metadata-only fixed CIC Train/dev selection; labels/paths copied from saved manifests. No PDF bytes, fitting, or Test evaluation. Job must run from console in disconnected LAB.")
    return run.state


def load_job(root, identifier):
    if not re.fullmatch(r"run_[A-Za-z0-9_-]{1,100}", identifier or ""):
        raise ValueError("Unsafe prepared-run identifier")
    summary = root / "reports/experiments/cic_static_prepare" / identifier / "run_summary.json"
    state = json.loads(read_bounded_bytes(summary, boundary=root / "reports/experiments", max_bytes=1024**2))
    path = root / "artifacts/cic_static_prepare" / identifier / "job_lock.json"
    content = read_bounded_bytes(path, boundary=root / "artifacts/cic_static_prepare", max_bytes=1024**2)
    if state["status"] != "completed" or hashlib.sha256(content).hexdigest() != state["job_lock_sha256"]:
        raise ValueError("Prepared job lock changed or incomplete")
    lock = json.loads(content)
    subset = read_bounded_bytes(root / lock["subset_path"], boundary=root / "artifacts/cic_static_prepare", max_bytes=1024**2)
    if hashlib.sha256(subset).hexdigest() != lock["subset_sha256"]:
        raise ValueError("Fixed subset changed")
    cfg = lock["configuration"]
    expected = select_subset(checked_table(root, cfg["split_manifest"]), checked_table(root, cfg["source_manifest"]), cfg["samples_per_partition"])
    verify_label_provenance(expected, checked_table(root, cfg["normalization_manifest"]))
    rows = list(csv.DictReader(io.StringIO(subset.decode())))
    if rows != expected or len(rows) != lock["rows"]:
        raise ValueError("Subset no longer matches the saved manifest")
    if lock.get("baseline_run"):
        baseline = baseline_method(root, lock["baseline_run"])
        if cfg != baseline["configuration"] or lock["subset_sha256"] != baseline["subset_sha256"]:
            raise ValueError("Baseline configuration/subset changed")
    limits = CodeInspectionLimits(**cfg["limits"])
    if source_fingerprint(root, limits) != lock["fingerprint"]:
        raise ValueError("Extractor/config changed: prepare a new job; never reuse the old cache")
    if lock.get("inference_model") is not None:
        profile_model_bytes(root, lock["inference_model"])
    if lock.get('v8_design') is not None:
        from malpdf.experiments.cic_v8 import locked_v8_design, baseline_evidence_checksums
        if lock['v8_design'] != locked_v8_design() or lock['baseline_evidence_checksums'] != baseline_evidence_checksums(root):
            raise ValueError('Sealed v8 design or baseline evidence changed')
    return rows, lock, limits


def static_result(profile):
    from malpdf.static.result import StaticInspectionResult, StructuredExtractionIssue
    from malpdf.static.schema import implementation_statuses
    data = profile.get("static")
    if data is None:
        return None
    return StaticInspectionResult(input=data["input"], parser=data["parser"], features=data["features"],
        compatibility=dict(implementation_statuses()), diagnostics={},
        errors=[StructuredExtractionIssue(row["code"], "redacted", row["fatal"]) for row in data["errors"]])


def distribution(values):
    known = [value for value in values if value is not None and math.isfinite(value)]
    return {"measured": len(known), "unavailable": len(values) - len(known),
            "p50": float(np.percentile(known, 50)) if known else None,
            "p95": float(np.percentile(known, 95)) if known else None,
            "sum": float(sum(known)) if known else None}


def summarize_profiles(records, planned):
    summary = {}
    for mode in ("cold", "warm"):
        selected = [row for row in records if row["cache_mode"] == mode]
        expected = planned[mode]
        statuses = Counter(row["status"] for row in selected)
        errors = Counter(error for row in selected for error in row["errors"])
        reasons = Counter(reason for row in selected for reason in row.get("reasons", []))
        failures = Counter((name, failure["stage"], failure["exception_type"], failure["reason"])
            for row in selected for name, diagnostic in (
                ("structural", (row.get("static") or {}).get("parser", {}).get("diagnostics")),
                ("javascript", (row.get("code") or {}).get("parser_diagnostics")))
            for failure in (diagnostic or {}).get("failures", []))
        summary[mode] = {"planned": expected, "recorded": len(selected), "not_started": expected - len(selected),
            "unique_pdf_samples": len({row["sample_id"] for row in selected}),
            "status_counts": dict(statuses), "error_counts_overlapping": dict(errors),
            "analysis_reason_counts_overlapping": dict(reasons),
            "parser_failure_categories": {"/".join(key): count for key, count in failures.items()},
            "parser_disagreement_files": sum(bool((row.get("static") or {}).get("parser", {}).get("success"))
                and "pdf_parser_failure" in (row.get("code") or {}).get("errors", []) for row in selected),
            "reference_parser_repaired_files": sum((row.get("static") or {}).get("reference_parser_repaired") is True for row in selected),
            "ast_error_files": sum(bool(row.get("code") and any(source["extraction_status"] == "complete" and source["ast_status"] != "complete"
                for source in row["code"].get("script_sources", []))) for row in selected),
            "cache_hits": sum(row["cache_hit"] for row in selected),
            "inference_available": sum(row.get("prediction", {}).get("available", False) for row in selected),
            "inference_executed": sum(row.get("inference_executed", False) for row in selected),
            "prediction_unavailable_reason_counts": dict(Counter(row.get("prediction", {}).get("reason") for row in selected
                if not row.get("prediction", {}).get("available", False))),
            "total_seconds": distribution([row["total_seconds"] for row in selected]),
            "stages_seconds": {name: distribution([row["timings"][name] for row in selected]) for name in STAGES},
            "overhead_seconds": distribution([row["overhead_seconds"] for row in selected]),
            "peak_worker_rss_bytes": max((row["peak_rss_bytes"] for row in selected), default=None),
            "peak_family_rss_sampled_bytes": max((row["peak_family_rss_sampled_bytes"] for row in selected), default=None),
            "rss_lower_bound_records": sum(row["rss_quality"] == "sampled_lower_bound" for row in selected)}
    return summary


def compare_saved_baseline(run, records, lock):
    """Pair saved evidence only; never reread the baseline's raw PDFs."""
    identifier = lock.get("baseline_run")
    if not identifier:
        return
    root = run.root
    baseline = baseline_method(root, identifier)
    if baseline["subset_sha256"] != lock["subset_sha256"] or baseline["configuration"] != lock["configuration"]:
        raise ValueError("Baseline cohort/configuration changed")
    path = root / "artifacts/cic_static_profile" / identifier / "per_file.jsonl"
    data = read_bounded_bytes(path, boundary=root / "artifacts/cic_static_profile", max_bytes=32 * 1024**2)
    before = [json.loads(line) for line in data.decode().splitlines()]
    before = {row["sample_id"]: row for row in before if row["cache_mode"] == "cold"}
    after = {row["sample_id"]: row for row in records if row["cache_mode"] == "cold"}
    if len(before) != lock["rows"] or set(before) != set(after) or any(
            (old["pdf_sha256"], old["split"], old["Label"]) !=
            (after[key]["pdf_sha256"], after[key]["split"], after[key]["Label"]) for key, old in before.items()):
        raise ValueError("Before/after evidence does not retain the same PDFs, labels and partitions")
    transitions = Counter((before[key]["status"], after[key]["status"]) for key in before)
    old_version = baseline.get("fingerprint", {}).get("profile_version")
    new_version = lock.get("fingerprint", {}).get("profile_version")
    same_v2 = old_version == new_version == "cic-static-profile-v2"
    timing_reason = ("both v2 profiles separate predict_proba from gate checks" if same_v2 else
        "profile-v1 inference included refusals; v2 separates predict_proba from gate checks"
        if {old_version, new_version} == {"cic-static-profile-v1", "cic-static-profile-v2"} else
        "matching inference measurement definitions have not been verified")
    write_json(run.report / "baseline_comparison.json", {"baseline_run": identifier, "same_subset_sha256": lock["subset_sha256"],
        "paired_cold_samples": len(before), "status_transitions": {" -> ".join(key): count for key, count in transitions.items()},
        "before_status_counts": dict(Counter(row["status"] for row in before.values())),
        "after_status_counts": dict(Counter(row["status"] for row in after.values())),
        "inference_time_comparable": same_v2, "reason": timing_reason,
        "timing_comparability_scope": "measurement definitions only; host load and OS page cache are uncontrolled",
        "memory_scope": ("both v2 profiles prefer current-process VmHWM; family peaks are sampled; this is not extraction-only RSS"
                         if same_v2 else "v2 prefers current-process VmHWM; earlier rusage peaks and new peaks are not an extraction-only memory comparison"),
        "model_metrics_scope": "C0/C1 use the same eligible rows within each run; changes in eligibility across runs require coverage/class denominators"})
    with (run.artifacts / "baseline_file_pairs.csv").open("x", newline="") as output:
        fields = ("sample_id", "before_status", "after_status", "before_errors", "after_reasons")
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        for key in before:
            writer.writerow(dict(sample_id=key, before_status=before[key]["status"], after_status=after[key]["status"],
                before_errors=";".join(before[key]["errors"]), after_reasons=";".join(after[key]["reasons"])))


def advanced_features(profile):
    from malpdf.static.js_ast import CALL_NAMES
    code = profile.get("code")
    structural = None if code is None else code.get("structural_indicators")
    ast = None if code is None else code.get("ast")
    values = {"structure_" + name[1:]: None if structural is None else structural.get(name[1:]) for name in sorted(SECURITY_NAMES)}
    values.update({"ast_" + name: None if ast is None else ast[name] for name in ("node_count", "max_depth", "loops", "computed_members")})
    values.update({"call_" + name: None if ast is None else ast["named_calls"][name] for name in sorted(CALL_NAMES)})
    values["scripts_found"] = None if code is None else code["scripts_found"]
    values["ast_complete"] = None if code is None else int(code["ast_complete"])
    return values


def compare_cic_features(run, records, configuration):
    """Locked RF pilot; both models see the same rows; unavailable stays refusal."""
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.impute import SimpleImputer
    from sklearn.pipeline import make_pipeline
    from malpdf.evaluation.selective import calibration_metrics
    from malpdf.static.schema import RIT_FEATURES
    cold = [row for row in records if row["cache_mode"] == "cold"]
    eligible = []
    for row in cold:
        result = static_result(row)
        eligible.append(bool(result is not None and result.parser.get("success") and result.parser.get("structural_complete")
            and not result.parser.get("resource_limit_reached") and not result.errors and result.protocol_g_drop3constant_gate().passed))
    train = np.array([row["split"] == "train" and good for row, good in zip(cold, eligible)])
    dev = np.array([row["split"] == "validation" and good for row, good in zip(cold, eligible)])
    labels = np.array([int(row["Label"]) for row in cold])
    planned = Counter(int(row["Label"]) for row in cold if row["split"] == "validation")
    if not train.any() or set(labels[train]) != {0, 1} or not dev.any() or set(labels[dev]) != {0, 1}:
        write_json(run.report / "feature_comparison.json", {"status": "insufficient_coverage_or_classes", "planned_dev": dict(planned),
            "train_available": int(train.sum()), "dev_available": int(dev.sum()), "metrics": None})
        return
    output = {}
    predictions = {}
    matrices = {}
    for name in ("C0_rit_baseline", "C1_rit_plus_structure_ast"):
        rows = []
        for row in cold:
            base = {feature: None if row.get("static") is None else row["static"]["features"].get(feature) for feature in RIT_FEATURES}
            if name.startswith("C1"):
                base.update(advanced_features(row))
            rows.append([np.nan if value is None else value for value in base.values()])
        values = np.asarray(rows, dtype=float)
        vector_keys = [json.dumps([None if np.isnan(value) else float(value) for value in row]) for row in values]
        overlap = set(key for key, mask in zip(vector_keys, train) if mask) & set(key for key, mask in zip(vector_keys, dev) if mask)
        if overlap:
            write_json(run.report / "feature_comparison.json", {"status": "feature_equivalence_crosses_saved_partitions",
                "variant": name, "overlapping_vectors": len(overlap), "metrics": None,
                "scope": "feature equivalence is not PDF identity; saved split unchanged and no samples silently removed"})
            return
        matrices[name] = values
    for name, values in matrices.items():
        model = make_pipeline(SimpleImputer(strategy="median", add_indicator=True, keep_empty_features=True),
            RandomForestClassifier(**configuration["rf"], random_state=42, n_jobs=1))
        start = perf_counter(); model.fit(values[train], labels[train]); fit_seconds = perf_counter() - start
        probabilities = model.predict_proba(values[dev])[:, 1]
        metrics = calibration_metrics(labels[dev], probabilities, threshold=configuration["threshold"])
        predicted = probabilities >= configuration["threshold"]
        tp = int(((labels[dev] == 1) & predicted).sum())
        fp = int(((labels[dev] == 0) & predicted).sum())
        positives, negatives = int((labels[dev] == 1).sum()), int((labels[dev] == 0).sum())
        output[name] = {"threshold": configuration["threshold"], "fit_seconds": fit_seconds,
            "train_available": int(train.sum()), "dev_planned": sum(planned.values()), "dev_available": int(dev.sum()),
            "coverage": float(dev.sum() / sum(planned.values())), "refusals": sum(planned.values()) - int(dev.sum()),
            "true_positives": tp, "false_positives": fp, "malicious_classified": positives, "benign_classified": negatives,
            "malicious_planned": planned[1], "benign_planned": planned[0],
            "malicious_coverage": positives / planned[1], "benign_coverage": negatives / planned[0],
            "recall_malicious_classified": tp / positives, "fpr_classified": fp / negatives,
            "detected_fraction_all_malicious": tp / planned[1], "false_positive_fraction_all_benign": fp / planned[0],
            "metrics_classified": metrics, "feature_count": values.shape[1]}
        run.state["metrics"][name + "/cic_development_classified"] = metrics
        predictions[name] = probabilities.tolist()
    write_json(run.report / "feature_comparison.json", {"status": "completed", "models": output,
        "scope": "balanced fixed Train/dev pilot; train-only imputation; fixed threshold0.5, no tuning/Test access; refusals excluded from classified metrics and retained in coverage/all-class denominators"})
    write_json(run.artifacts / "development_predictions.json", {"predictions": predictions,
        "sample_ids": [row["sample_id"] for row, chosen in zip(cold, dev) if chosen]})


def run_cic_profile(root, prepared_run, *, lab_attested=False, model_file=None):
    root = Path(root).absolute()
    # This guard precedes every metadata/model/PDF operation in run mode.
    try:
        lab = require_offline_lab(lab_attested)
        clean_code(root)
        rows, lock, limits = load_job(root, prepared_run)
        if lock.get("inference_model") is not None and model_file is not None:
            raise ValueError("Prepared inference model is locked; a run cannot override it")
        if lock.get('v8_design') is not None:
            from malpdf.experiments.cic_v8 import claim_v8_attempt
            claim_v8_attempt(root, prepared_run)
    except Exception:
        with ResearchRun(root, "cic_static_refused", {"protocol": "CIC offline job preflight",
            "prepared_run": prepared_run, "test_access": False, "pdf_access": False}) as refused:
            refused.state["notes"] = "Preflight refused before model/PDF access; dirty/unavailable LAB/config provenance recorded; no samples or metrics evaluated."
            raise
    cfg = lock["configuration"]
    from malpdf.static.profile_worker import profile_pdf
    from malpdf.static.profile_worker import resident_bytes
    from malpdf.inference.predictor import StaticScanSession
    from malpdf.inference.deployment import load_verified_deployment_model, restore_verified_deployment_model, DeploymentError
    method = {"protocol": "fixed CIC Train/dev static diagnosis and feature pilot", "configuration": cfg,
        "baseline_run": lock.get("baseline_run"),
        "inference_model": lock.get("inference_model"),
        "prepared_run": prepared_run, "subset_sha256": lock["subset_sha256"], "fingerprint": lock["fingerprint"], "lab_checks": lab,
        "cache": "cold=fresh application feature cache; warm=complete-profile reuse after fresh PDF checksum verification; OS page cache uncontrolled",
        "timing_scope": "exclusive stage timings; inference=predict_proba only, null if not called; inference_gate=compatibility/feature/model checks and response validation; implicit xref/object/content decoding, XML traversal and reference text extraction remain in parse_pdf; stream_decode covers explicit JS/XFA streams; residual overhead includes startup/cache/IPC and any unfinished stage; RF ablation fitting is outside file timings",
        "ablation": "C0 same RIT41 definitions; C1 adds resolved structure/JS AST; RF settings and threshold0.5 locked before development evaluation; same saved partitions and refusals",
        "observed_evidence_ablation": "Reuse fixed P0 RIT41 fallback / P1 observed structure-AST / P2 parser flags on identical known-input Train/dev rows; original RF budget/seed42/threshold0.5; Train-only median imputation; all failures/refusals retained; no selection/deployment; strict C0/C1 have different eligibility",
        "dataset_scope": "CIC PDF only; RIT CSV unchanged, no AST fabrication or dataset merging", "test_access": False}
    if lock.get('v8_design') is not None:
        method.update(v8_design=lock['v8_design'], baseline_evidence_checksums=lock['baseline_evidence_checksums'])
    method['config_hash'] = hashlib.sha256(json.dumps(cfg,sort_keys=True).encode()).hexdigest()
    with ResearchRun(root, "cic_static_profile", method) as run:
        set_random_seed(42)
        write_json(run.report / "static_package_versions.json", lock["fingerprint"]["backends"])
        cache = run.artifacts / "cache"; cache.mkdir()
        records = []
        planned = {"cold": len(rows), "warm": len(rows) * cfg["warm_repeats"]}
        readouts = {}
        start_run = perf_counter()
        model_start = perf_counter()
        model_error_code = None
        restoration = None
        try:
            if model_file is not None:
                restoration = restore_verified_deployment_model(root, model_file)
            loaded = load_profile_model(root, lock["inference_model"]) if lock.get("inference_model") is not None else load_verified_deployment_model(root)
            loaded[0].set_params(n_jobs=1)
            model_status = "verified_loaded"
        except Exception as error:
            loaded = None
            model_status = "unavailable_" + type(error).__name__
            model_error_code = getattr(error, "code", "model_load_failed")
        model_setup_seconds = perf_counter() - model_start

        def loader(_root):
            if loaded is None:
                raise DeploymentError(model_status)
            return loaded

        session = StaticScanSession(repository_root=root, inspector=lambda key, limits=None: readouts[key], model_loader=loader)
        try:
            for mode, repeats in (("cold", 1), ("warm", cfg["warm_repeats"])):
                for repeat in range(repeats):
                    for index, row in enumerate(rows):
                        require_offline_lab(lab_attested)
                        start = perf_counter()
                        key = hashlib.sha256(json.dumps({"pdf_sha256": row["pdf_sha256"], "extractor": lock["fingerprint"]}, sort_keys=True).encode()).hexdigest()
                        cache_path = cache / (key + ".json")
                        profile = profile_pdf(root / row["pdf_relative_path"], boundary=root / "data/raw/cic_pdf",
                            digest=row["pdf_sha256"], limits=limits, cache_path=cache_path if mode == "warm" else None,
                            cache_key=key, include_v8=True)
                        result = static_result(profile)
                        if result is not None:
                            readouts[index] = result
                            inference_timings = StageTimings()
                            session.timings = inference_timings
                            prediction = session.scan_many([index], explain=False)[0].prediction
                            for name in ("inference_gate", "inference"):
                                profile["timings"][name] = inference_timings.seconds[name]
                            profile["prediction"] = {name: prediction[name] for name in ("available", "malicious_probability", "predicted_label")}
                            profile["prediction"]["reason"] = (None if prediction["available"] else
                                "extraction_incomplete" if not result.parser.get("success") or not result.parser.get("structural_complete") or result.parser.get("resource_limit_reached") or any(issue.fatal for issue in result.errors) else
                                "feature_gate_failed" if not result.protocol_g_drop3constant_gate().passed else
                                model_error_code if loaded is None else "prediction_failed")
                            readouts.pop(index)
                        else:
                            profile["prediction"] = {"available": False, "malicious_probability": None, "predicted_label": None, "reason": "static_result_unavailable"}
                        profile["inference_executed"] = profile["timings"]["inference"] is not None
                        profile.update(total_seconds=perf_counter() - start, cache_mode=mode, repeat=repeat,
                            sample_id=row["sample_id"], pdf_relative_path=row["pdf_relative_path"], pdf_sha256=row["pdf_sha256"], Label=row["Label"], split=row["split"])
                        measured = sum(value for value in profile["timings"].values() if value is not None)
                        profile["overhead_seconds"] = max(0.0, profile["total_seconds"] - measured)
                        profile["peak_family_rss_sampled_bytes"] = max(profile["peak_family_rss_sampled_bytes"], resident_bytes(os.getpid()))
                        records.append(profile)
                        with (run.artifacts / "per_file.jsonl").open("a") as output:
                            output.write(json.dumps(profile, allow_nan=False) + "\n")
                        if profile["status"] != "complete":
                            with (run.artifacts / "failures.jsonl").open("a") as output:
                                output.write(json.dumps(profile, allow_nan=False) + "\n")
                        inventory = run.artifacts / "per_file_inventory.csv"
                        fields = ("sample_id", "pdf_relative_path", "split", "Label", "cache_mode", "repeat", "status", "last_stage", "worker_exit_code", "errors", "reasons", "inference_executed")
                        exists = inventory.exists()
                        with inventory.open("a", newline="") as output:
                            writer = csv.DictWriter(output, fieldnames=fields)
                            if not exists:
                                writer.writeheader()
                            writer.writerow({name: ";".join(profile[name]) if name in {"errors", "reasons"} else profile[name] for name in fields})
                        if mode == "cold" and profile["status"] == "complete" and not cache_path.exists():
                            value = {name: profile[name] for name in ("profile_version", "status", "errors", "reasons", "static", "code")}
                            if 'analysis_v8' in profile:
                                value['analysis_v8'] = profile['analysis_v8']
                            checksum = hashlib.sha256(json.dumps(value, sort_keys=True, allow_nan=False).encode()).hexdigest()
                            write_json(cache_path, {"key": key, "profile_sha256": checksum, "profile": value})
                        run.progress("file_completed", cache_mode=mode, processed=len(records), planned=sum(planned.values()), status=profile["status"])
            if cfg["compare_models"]:
                require_offline_lab(lab_attested)
                compare_cic_features(run, records, cfg)
                from malpdf.experiments.cic_static_accuracy import compare_profile_evidence
                compare_profile_evidence(run, records, cfg)
            compare_saved_baseline(run, records, lock)
            from malpdf.experiments.cic_v8 import compare_v8_run
            compare_v8_run(run, records, lock)
            run.state["status"] = "completed"
            if lock.get('v8_design') is not None:
                run.state['release_status'] = 'pending_evidence_review'
        finally:
            summary = summarize_profiles(records, planned)
            summary["run_wall_seconds"] = perf_counter() - start_run
            summary["model_setup"] = {"seconds": model_setup_seconds, "status": model_status,
                "error_code": model_error_code,
                "restoration": restoration,
                "model_id": loaded[1]["model_id"] if loaded else None,
                "artifact_sha256": loaded[1]["artifact_sha256"] if loaded else None,
                "training_provenance": loaded[1]["training_dataset"] if loaded else None,
                "requested_n_jobs": 1,
                "scope": "checksum-verified frozen RIT model recorded by identity; inference timing only, no CIC accuracy claim; setup excluded from per-file inference"}
            summary["peak_parent_rss_bytes"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
            summary["memory_scope"] = "worker current-process VmHWM when returned, rusage fallback explicitly tagged; killed worker polling lower bound; concurrent parent+worker RSS sum sampled and may double count shared pages"
            summary["failure_inventory"] = "private artifacts/per_file.jsonl and failures.jsonl; no samples silently discarded"
            summary["os_cache"] = "uncontrolled; cold/warm refer to application cache"
            summary["stage_scope"] = method["timing_scope"]
            write_json(run.report / "pipeline_summary.json", summary)
            run.state['evidence_paths'] = {'pipeline': str((run.report/'pipeline_summary.json').relative_to(root)),
                'per_file': str((run.artifacts/'per_file.jsonl').relative_to(root))}
            if lock.get('v8_design') is not None:
                run.state['evidence_paths'].update(comparison=str((run.report/'v7_v8_comparison.json').relative_to(root)),
                    parser_comparison=str((run.report/'parser_comparison.json').relative_to(root)),
                    c1_error_analysis=str((run.artifacts/'c1_error_analysis.json').relative_to(root)))
                run.state.update(config_hash=method['config_hash'], dataset_manifest_hash=lock['subset_sha256'])
            run.state["notes"] = "CIC Train/dev only, one worker; all planned samples retained in coverage/refusal denominators. Full per-file identities/errors stay in LAB artifacts. Stage timings distinguish explicit JS decoding from implicit backend decoding. Balanced pilot and previously exposed Validation, no independent Test/improvement claim. RIT CSV unchanged."
    return run.state

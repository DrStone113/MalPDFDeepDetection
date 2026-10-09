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
from malpdf.static.profiling import STAGES, PROFILE_VERSION
from malpdf.static.safety import read_bounded_bytes


def clean_code(root):
    if subprocess.check_output(["git", "-C", str(root), "status", "--porcelain"], text=True).strip():
        raise ValueError("Official CIC job requires clean committed code")


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
    paths = ("static/analyzer.py", "static/pdf_parser.py", "static/rit_reference.py", "static/raw_scan.py",
             "static/code_inspector.py", "static/js_ast.py", "static/profiling.py", "static/profile_worker.py",
             "static/schema.py", "static/result.py", "static/safety.py", "static/lab_guard.py",
             "experiments/cic_static_benchmark.py", "inference/predictor.py", "inference/schema.py", "inference/deployment.py")
    return {"profile_version": PROFILE_VERSION, "code_schema": CODE_INSPECTION_SCHEMA_VERSION,
            "limits": asdict(limits), "backends": {name: importlib.metadata.version(name) for name in ("pypdf", "PyMuPDF", "esprima")},
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


def prepare_cic_profile(root, config):
    root = Path(root).absolute()
    clean_code(root)
    cfg = yaml.safe_load(Path(config).read_text())
    if cfg["seed"] != 42 or cfg["workers"] != 1 or not 1 <= cfg["warm_repeats"] <= 3 or cfg["threshold"] != 0.5:
        raise ValueError("Locked seed/worker/threshold/warm budget changed")
    limits = CodeInspectionLimits(**cfg["limits"])
    method = {"protocol": "fixed CIC Train/dev diagnostic subset preparation", "configuration": cfg,
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
        fingerprint = source_fingerprint(root, limits)
        lock = {"configuration": cfg, "subset_path": str(subset.relative_to(root)),
                "subset_sha256": hashlib.sha256(subset.read_bytes()).hexdigest(), "rows": len(rows),
                "fingerprint": fingerprint, "created_at_utc": datetime.now(timezone.utc).isoformat()}
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
    limits = CodeInspectionLimits(**cfg["limits"])
    if source_fingerprint(root, limits) != lock["fingerprint"]:
        raise ValueError("Extractor/config changed: prepare a new job; never reuse the old cache")
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
        summary[mode] = {"planned": expected, "recorded": len(selected), "not_started": expected - len(selected),
            "unique_pdf_samples": len({row["sample_id"] for row in selected}),
            "status_counts": dict(statuses), "error_counts_overlapping": dict(errors),
            "ast_error_files": sum(bool(row.get("code") and any(source["extraction_status"] == "complete" and source["ast_status"] != "complete"
                for source in row["code"].get("script_sources", []))) for row in selected),
            "cache_hits": sum(row["cache_hit"] for row in selected),
            "inference_available": sum(row.get("prediction", {}).get("available", False) for row in selected),
            "total_seconds": distribution([row["total_seconds"] for row in selected]),
            "stages_seconds": {name: distribution([row["timings"][name] for row in selected]) for name in STAGES},
            "overhead_seconds": distribution([row["overhead_seconds"] for row in selected]),
            "peak_worker_rss_bytes": max((row["peak_rss_bytes"] for row in selected), default=None),
            "peak_family_rss_sampled_bytes": max((row["peak_family_rss_sampled_bytes"] for row in selected), default=None),
            "rss_lower_bound_records": sum(row["rss_quality"] == "sampled_lower_bound" for row in selected)}
    return summary


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


def run_cic_profile(root, prepared_run, *, lab_attested=False):
    root = Path(root).absolute()
    # This guard precedes every metadata/model/PDF operation in run mode.
    try:
        lab = require_offline_lab(lab_attested)
        clean_code(root)
        rows, lock, limits = load_job(root, prepared_run)
    except Exception:
        with ResearchRun(root, "cic_static_refused", {"protocol": "CIC offline job preflight",
            "prepared_run": prepared_run, "test_access": False, "pdf_access": False}) as refused:
            refused.state["notes"] = "Preflight refused before model/PDF access; dirty/unavailable LAB/config provenance recorded; no samples or metrics evaluated."
            raise
    cfg = lock["configuration"]
    from malpdf.static.profile_worker import profile_pdf
    from malpdf.static.profile_worker import resident_bytes
    from malpdf.inference.predictor import StaticScanSession
    from malpdf.inference.deployment import load_verified_deployment_model, DeploymentError
    method = {"protocol": "fixed CIC Train/dev static diagnosis and feature pilot", "configuration": cfg,
        "prepared_run": prepared_run, "subset_sha256": lock["subset_sha256"], "fingerprint": lock["fingerprint"], "lab_checks": lab,
        "cache": "cold=fresh application feature cache; warm=complete-profile reuse after fresh PDF checksum verification; OS page cache uncontrolled",
        "timing_scope": "exclusive stage timings; implicit xref/object/content decoding and reference text extraction remain inside parse_pdf; stream_decode covers explicit JS streams only; worker startup/cache/IPC overhead reported separately",
        "ablation": "C0 same RIT41 definitions; C1 adds resolved structure/JS AST; RF settings and threshold0.5 locked before development evaluation; same saved partitions and refusals",
        "dataset_scope": "CIC PDF only; RIT CSV unchanged, no AST fabrication or dataset merging", "test_access": False}
    with ResearchRun(root, "cic_static_profile", method) as run:
        set_random_seed(42)
        write_json(run.report / "static_package_versions.json", lock["fingerprint"]["backends"])
        cache = run.artifacts / "cache"; cache.mkdir()
        records = []
        planned = {"cold": len(rows), "warm": len(rows) * cfg["warm_repeats"]}
        readouts = {}
        start_run = perf_counter()
        model_start = perf_counter()
        try:
            loaded = load_verified_deployment_model(root)
            loaded[0].set_params(n_jobs=1)
            model_status = "verified_loaded"
        except Exception as error:
            loaded = None
            model_status = "unavailable_" + type(error).__name__
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
                            digest=row["pdf_sha256"], limits=limits, cache_path=cache_path if mode == "warm" else None, cache_key=key)
                        result = static_result(profile)
                        if result is not None:
                            readouts[index] = result
                            infer_start = perf_counter()
                            prediction = session.scan_many([index], explain=False)[0].prediction
                            profile["timings"]["inference"] = perf_counter() - infer_start
                            profile["prediction"] = {name: prediction[name] for name in ("available", "malicious_probability", "predicted_label")}
                            readouts.pop(index)
                        else:
                            profile["prediction"] = {"available": False, "malicious_probability": None, "predicted_label": None}
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
                        fields = ("sample_id", "pdf_relative_path", "split", "Label", "cache_mode", "repeat", "status", "last_stage", "worker_exit_code", "errors")
                        exists = inventory.exists()
                        with inventory.open("a", newline="") as output:
                            writer = csv.DictWriter(output, fieldnames=fields)
                            if not exists:
                                writer.writeheader()
                            writer.writerow({name: ";".join(profile[name]) if name == "errors" else profile[name] for name in fields})
                        if mode == "cold" and profile["status"] == "complete" and not cache_path.exists():
                            value = {name: profile[name] for name in ("status", "errors", "static", "code")}
                            checksum = hashlib.sha256(json.dumps(value, sort_keys=True, allow_nan=False).encode()).hexdigest()
                            write_json(cache_path, {"key": key, "profile_sha256": checksum, "profile": value})
                        run.progress("file_completed", cache_mode=mode, processed=len(records), planned=sum(planned.values()), status=profile["status"])
            if cfg["compare_models"]:
                require_offline_lab(lab_attested)
                compare_cic_features(run, records, cfg)
            run.state["status"] = "completed"
        finally:
            summary = summarize_profiles(records, planned)
            summary["run_wall_seconds"] = perf_counter() - start_run
            summary["model_setup"] = {"seconds": model_setup_seconds, "status": model_status,
                "requested_n_jobs": 1,
                "scope": "verified frozen RIT deployment; inference timing only, no CIC accuracy claim; setup excluded from per-file inference"}
            summary["peak_parent_rss_bytes"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
            summary["memory_scope"] = "worker kernel HWM when returned; killed worker polling lower bound; concurrent parent+worker RSS sum sampled, may double count shared pages"
            summary["failure_inventory"] = "private artifacts/per_file.jsonl and failures.jsonl; no samples silently discarded"
            summary["os_cache"] = "uncontrolled; cold/warm refer to application cache"
            summary["stage_scope"] = method["timing_scope"]
            write_json(run.report / "pipeline_summary.json", summary)
            run.state["notes"] = "CIC Train/dev only, one worker; all planned samples retained in coverage/refusal denominators. Full per-file identities/errors stay in LAB artifacts. Stage timings distinguish explicit JS decoding from implicit backend decoding. Balanced pilot and previously exposed Validation, no independent Test/improvement claim. RIT CSV unchanged."
    return run.state

"""One-shot V9 diagnostic campaign; metadata preparation never opens a PDF.

Only the two explicitly guarded run functions inspect original PDF bytes. Saved
models are byte-copied during preparation and unpickled only inside the offline
LAB after provenance, memory and clean-code checks. There is no fitting path.
"""

from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import io
import json
import math
from pathlib import Path
import platform
import re
from time import perf_counter

from malpdf.experiments.cic_static_benchmark import (
    checked_table, clean_code, select_subset, verify_label_provenance,
)
from malpdf.experiments.cic_v8 import V7_RUN, baseline_records, v8_feature_values
from malpdf.provenance.research_runs import ResearchRun, write_json
from malpdf.static.code_inspector import CodeInspectionLimits, _worker_count, worker_memory_budget
from malpdf.static.lab_guard import require_offline_lab
from malpdf.static.safety import read_bounded_bytes


V8_RUN = "run_20261010T181946430830Z_3c5f90ef33fb"
CAMPAIGN_ID = "v9-one-shot-evidence-first-v1"
POLICY_ID = "c1-v9-frozen-ml-linked-evidence-v1"
PREPARE_STUDY = "cic_v9_prepare"
INTEGRATION_STUDY = "cic_v9_integration"
FINAL_STUDY = "cic_v9_final"
VALIDATION_STUDY = "cic_v9_validation"
MAX_METADATA_BYTES = 32 * 1024**2
PARITY_ATOL = 1e-12
LIMITS = CodeInspectionLimits(wall_seconds=20, cpu_seconds=12,
    memory_bytes=1024**3, max_file_bytes=10 * 1024**2)


def _identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"run_[A-Za-z0-9_-]{1,100}", value):
        raise ValueError("Unsafe V9 run identity")
    return value


def _content(root, relative, *, maximum=MAX_METADATA_BYTES):
    root, relative = Path(root).absolute(), Path(relative)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts or relative.parts[0] not in {"reports", "artifacts", "data"}:
        raise ValueError("V9 evidence outside its controlled boundary")
    if relative.suffix not in {".json", ".jsonl", ".csv", ".joblib"} or (
            relative.parts[0] == "data" and not relative.is_relative_to("data/processed")):
        raise ValueError("Metadata operation cannot read raw PDF/sample bytes")
    return read_bounded_bytes(root / relative, boundary=root / relative.parts[0], max_bytes=maximum)


def _json(root, relative):
    return json.loads(_content(root, relative))


def _sha(content):
    return hashlib.sha256(content).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def v9_source_fingerprint(root):
    """Seal executable sources, regression sources, dependencies and all caps.

    Reports and ignored data are intentionally excluded: committing immutable
    integration/validation evidence must not invalidate identical generating code.
    """
    root = Path(root).absolute()
    paths = [root / "pyproject.toml", root / "AGENTS.md"]
    for folder in ("src/malpdf", "scripts", "tests", "configs"):
        paths.extend(path for path in (root / folder).rglob("*")
                     if path.is_file() and path.suffix in {".py", ".yaml", ".desktop"})
    if any(path.is_symlink() for path in paths):
        raise ValueError("Symbolic-link source cannot be sealed")
    packages = ("pypdf", "PyMuPDF", "esprima", "numpy", "pandas", "scipy", "scikit-learn", "joblib")
    return {"schema": "pdf-evidence-v9", "policy": POLICY_ID, "limits": asdict(LIMITS),
        "raw_chunk_bytes": 64 * 1024, "raw_artifact_bytes": 10 * 1024**2,
        "graph_metadata_bytes": 2 * 1024**2, "workers": 1,
        "python": platform.python_version(),
        "backends": {name: importlib.metadata.version(name) for name in packages},
        "sources": {str(path.relative_to(root)): _sha(path.read_bytes()) for path in sorted(set(paths))}}


def _baseline_metadata(root):
    """Load existing private JSON/CSV only; retain all64 locked assignments."""
    old, _, baseline = baseline_records(root)
    cfg = baseline["configuration"]
    expected = select_subset(checked_table(root, cfg["split_manifest"]),
        checked_table(root, cfg["source_manifest"]), cfg["samples_per_partition"])
    verify_label_provenance(expected, checked_table(root, cfg["normalization_manifest"]))
    expected_by_id = {row["sample_id"]: row for row in expected}
    if len(expected_by_id) != 64:
        raise ValueError("V9 requires the original locked64 identities")
    for row in old:
        selected = expected_by_id.get(row["sample_id"])
        if selected is None or any(str(selected[name]) != str(row[name]) for name in ("pdf_sha256", "pdf_relative_path", "Label", "split")):
            raise ValueError("V7 baseline no longer matches Protocol G metadata")
    v8_report = Path("reports/experiments/cic_static_profile") / V8_RUN
    v8_summary = _json(root, v8_report / "run_summary.json")
    v8_lock = _json(root, v8_report / "locked_methodology.json")
    if v8_summary["status"] != "completed" or v8_lock["test_access"] is not False or v8_lock["subset_sha256"] != baseline["subset_sha256"]:
        raise ValueError("Invalid fixed V8 diagnostic outcome")
    v8_artifacts = Path("artifacts/cic_static_profile") / V8_RUN
    current = [json.loads(line) for line in _content(root, v8_artifacts / "per_file.jsonl").decode().splitlines() if line]
    cold = [row for row in current if row["cache_mode"] == "cold"]
    if len(cold) != 64 or len({row["sample_id"] for row in cold}) != 64:
        raise ValueError("V8 saved identity count changed")
    for row in cold:
        selected = expected_by_id.get(row["sample_id"])
        if selected is None or any(str(selected[name]) != str(row[name]) for name in ("pdf_sha256", "pdf_relative_path", "Label", "split")):
            raise ValueError("V7/V8 saved label, path or partition mismatch")
    return expected, old, cold, baseline


def integration_rows(rows, saved_v8):
    """The three historic overlay AttributeErrors, selected from saved metadata."""
    ids = {row["sample_id"] for row in saved_v8
           if row.get("status") == "worker_error" and "AttributeError" in row.get("errors", [])}
    selected = [row for row in rows if row["sample_id"] in ids]
    if len(selected) != 3 or len(ids) != 3:
        raise ValueError("Integration must retain exactly the three recorded AttributeError inputs")
    return selected


def _saved_evidence_specs(root, cfg):
    """Pin aggregate baseline and private per-file evidence without uploading it."""
    paths = []
    for identifier in (V7_RUN, V8_RUN):
        report = Path("reports/experiments/cic_static_profile") / identifier
        artifacts = Path("artifacts/cic_static_profile") / identifier
        paths.extend([report / "run_summary.json", report / "locked_methodology.json", artifacts / "per_file.jsonl"])
    paths.extend([Path("artifacts/cic_static_profile") / V7_RUN / "observed_development_predictions.json",
                  Path("artifacts/cic_static_profile") / V8_RUN / "c1_v8_decisions.json"])
    paths.extend(Path(cfg[name]["path"]) for name in ("split_manifest", "source_manifest", "normalization_manifest"))
    return {str(path): _sha(_content(root, path)) for path in paths}


def _verify_specs(root, specs):
    for relative, digest in specs.items():
        if _sha(_content(root, relative)) != digest:
            raise ValueError("Sealed saved evidence changed")


def _freeze_models(root, run):
    """Checksum/copy trusted saved bytes. This function never imports joblib."""
    from malpdf.experiments.cic_static_accuracy import PROFILE_VARIANTS, profile_feature_values
    models = {}
    for name in ("C1_v8", *PROFILE_VARIANTS):
        origin = V8_RUN if name == "C1_v8" else V7_RUN
        relative = Path("reports/experiments/cic_static_profile") / origin / (name + "_manifest.json")
        manifest_bytes = _content(root, relative)
        manifest = json.loads(manifest_bytes)
        order = list(v8_feature_values({})) if name == "C1_v8" else list(profile_feature_values({}, name))
        if (manifest.get("feature_order") != order or manifest.get("threshold") != .5 or manifest.get("seed") != 42
                or manifest.get("train_rows", manifest.get("training_rows")) != (31 if name == "C1_v8" else 32)):
            raise ValueError("Frozen model manifest changed")
        if name == "C1_v8" and (len(order) != 173 or manifest.get("model_id") != "c1-v8-fixed-rf-evidence-v1"):
            raise ValueError("Frozen C1 identity changed")
        expected_source = Path("artifacts/cic_static_profile") / origin / (name + ".joblib")
        if manifest.get("artifact_path", manifest.get("artifact_relative_path")) != str(expected_source):
            raise ValueError("Frozen model source outside the fixed historic run")
        content = _content(root, expected_source, maximum=64 * 1024**2)
        if _sha(content) != manifest["artifact_sha256"]:
            raise ValueError("Frozen model checksum changed")
        target = run.artifacts / (name + ".joblib")
        with target.open("xb") as handle:
            handle.write(content)
        manifest_target = run.artifacts / (name + "_manifest.json")
        with manifest_target.open("xb") as handle:
            handle.write(manifest_bytes)
        models[name] = {"manifest": manifest, "source_manifest": str(relative),
            "source_manifest_sha256": _sha(manifest_bytes),
            "snapshot_path": str(target.relative_to(root)), "artifact_sha256": _sha(content),
            "snapshot_manifest_path": str(manifest_target.relative_to(root))}
    return models


def _verify_model_specs(root, specs):
    for spec in specs.values():
        if _sha(_content(root, spec["source_manifest"])) != spec["source_manifest_sha256"]:
            raise ValueError("Original frozen manifest changed")
        if _json(root, spec["snapshot_manifest_path"]) != spec["manifest"]:
            raise ValueError("Snapshot manifest changed")
        relative = Path(spec["snapshot_path"])
        if not relative.is_relative_to("artifacts/cic_v9_prepare") or _sha(_content(root, relative, maximum=64 * 1024**2)) != spec["artifact_sha256"]:
            raise ValueError("Frozen snapshot changed or escaped private preparation")


def prepare_v9(root):
    """Create the metadata-only three-file integration job from clean code."""
    root = Path(root).absolute()
    clean_code(root)
    with ResearchRun(root, PREPARE_STUDY, {"protocol": "V9 metadata-only locked LAB integration preparation",
            "campaign": CAMPAIGN_ID, "test_access": False, "pdf_access": False, "fitting": False}) as run:
        rows, _, saved_v8, baseline = _baseline_metadata(root)
        selected = integration_rows(rows, saved_v8)
        fingerprint = v9_source_fingerprint(root)
        if fingerprint["backends"]["pypdf"] != "6.18.1":
            raise ValueError("V9 requires the pinned security-fixed pypdf6.18.1")
        models = _freeze_models(root, run)
        from malpdf.inference.evidence_policy_v9 import build_dependency_ledger
        ledger = build_dependency_ledger(models["C1_v8"]["manifest"]["feature_order"])
        write_json(run.report / "dependency_ledger.json", {"columns": ledger,
            "missingness": "not_verified_until_offline_frozen_load", "model_columns": 173,
            "scope": "frozen feature semantics; no feature/model/threshold selection"})
        lock = {"campaign": CAMPAIGN_ID, "kind": "integration", "rows": selected,
            "all_rows": rows, "subset_sha256": baseline["subset_sha256"], "baseline_v7": V7_RUN,
            "baseline_v8": V8_RUN, "configuration": baseline["configuration"], "fingerprint": fingerprint,
            "models": models, "evidence_checksums": _saved_evidence_specs(root, baseline["configuration"]),
            "ledger_sha256": _sha((run.report / "dependency_ledger.json").read_bytes()),
            "created_at_utc": datetime.now(timezone.utc).isoformat()}
        write_json(run.artifacts / "job_lock.json", lock)
        run.state.update(status="completed", kind="integration", rows=3,
            job_lock_sha256=_sha((run.artifacts / "job_lock.json").read_bytes()),
            notes="Metadata only; three historic AttributeError rows. Model bytes copied and checksum verified, never loaded; no PDF/Test/fitting access.")
    return run.state


def load_v9_job(root, identifier, *, kind=None):
    """Validate prepared metadata and model bytes without unpickling or PDF reads."""
    root, identifier = Path(root).absolute(), _identifier(identifier)
    report = Path("reports/experiments") / PREPARE_STUDY / identifier
    summary = _json(root, report / "run_summary.json")
    content = _content(root, Path("artifacts") / PREPARE_STUDY / identifier / "job_lock.json")
    if summary["status"] != "completed" or _sha(content) != summary["job_lock_sha256"]:
        raise ValueError("V9 prepared lock changed or incomplete")
    lock = json.loads(content)
    if lock.get("campaign") != CAMPAIGN_ID or (kind is not None and lock.get("kind") != kind):
        raise ValueError("V9 prepared campaign/kind mismatch")
    if lock["fingerprint"] != v9_source_fingerprint(root):
        raise ValueError("V9 source/backend/budget changed; fresh integration is required")
    _verify_specs(root, lock["evidence_checksums"])
    _verify_model_specs(root, lock["models"])
    expected, _, saved_v8, baseline = _baseline_metadata(root)
    selected = integration_rows(expected, saved_v8) if lock["kind"] == "integration" else expected
    if lock["all_rows"] != expected or lock["rows"] != selected or lock["subset_sha256"] != baseline["subset_sha256"]:
        raise ValueError("V9 saved manifest/identity/label/split changed")
    ledger_report = Path(lock.get("ledger_path", str(report / "dependency_ledger.json")))
    if _sha(_content(root, ledger_report)) != lock["ledger_sha256"]:
        raise ValueError("V9 dependency ledger changed")
    return lock["rows"], lock, LIMITS


def assess_integration(profile, previous):
    """Require actual retained stage evidence; generic exception relabeling fails."""
    from malpdf.experiments.cic_static_accuracy import profile_input_available
    analysis = profile.get("analysis_v9") or {}
    reasons = []
    if not profile_input_available(profile, LIMITS.max_file_bytes):
        reasons.append("primary_checkpoint_unavailable")
    if (profile.get("static") or {}).get("input", {}).get("sha256") != previous["pdf_sha256"]:
        reasons.append("primary_snapshot_identity_unverified")
    if profile.get("worker_cleanup_complete") is not True:
        reasons.append("worker_cleanup_unverified")
    if profile.get("status") in {"worker_error", "timeout", "resource_limit_or_signal", "input_error"}:
        reasons.append("worker_did_not_finish_integration")
    if (analysis.get("schema_version", analysis.get("schema")) != "pdf-evidence-v9"
            or analysis.get("document_sha256") != previous["pdf_sha256"]):
        reasons.append("v9_graph_identity_unverified")
    graph_kinds = {"catalog", "page", "pages", "annotation", "field", "form", "action", "stream", "pdf_object",
        "filespec", "embedded_stream", "array", "script", "script_extraction", "payload", "xfa_packet", "xfa_event"}
    completed_graph = [item for item in analysis.get("observations", []) if item.get("kind") in graph_kinds
        and item.get("backend") in {"pypdf", "MuPDF"} and item.get("status") in {"observed", "verified"}
        and item.get("locator") and item.get("document_sha256") == previous["pdf_sha256"]]
    if not completed_graph or not analysis.get("capability_checks") or not analysis.get("backend_results"):
        reasons.append("completed_graph_checkpoint_missing")
    if analysis.get("original_bytes_changed") is not False or analysis.get("active_content_executed") is not False:
        reasons.append("immutable_static_inspection_unverified")
    generic = {"AttributeError", "worker_error", "backend_exception", "parser_exception", "code_exception", "unknown_backend_failure",
        "graph_backend_failure", "graph_backend_attribute_error", "graph_open_failure", "recovery_backend_failure",
        "recovery_backend_attribute_error", "script_analysis_failure", "script_ast_attribute_error",
        "payload_analysis_failure", "graph_reference_failure", "xfa_xml_failure"}
    nodes = {item.get("id"): item for item in analysis.get("observations", [])}
    failures = [item for item in nodes.values() if item.get("kind") == "stage_failure"]
    for result in analysis.get("backend_results", []):
        codes = set(result.get("reason_codes", [])) | {result.get("error_code")}
        if codes & generic or any(isinstance(code, str) and "attribute_error" in code.lower() for code in codes):
            reasons.append("generic_backend_failure_not_resolved")
        if result.get("status") in {"failed", "unavailable", "error"} and (not result.get("stage") or not result.get("reason_codes")):
            reasons.append("backend_failure_stage_unlocalized")
        if result.get("stage") == "graph_or_script":
            summaries = {None, "recovered_scope_not_complete", "catalog_enumeration_incomplete"}
            for code in codes - summaries:
                matching = [failure for failure in failures if failure.get("backend") == result.get("backend")
                    and code in failure.get("reason_codes", []) and failure.get("capability")
                    and failure.get("affected_ids") and all(identifier in nodes and nodes[identifier].get("locator")
                        and nodes[identifier].get("document_sha256") == previous["pdf_sha256"] for identifier in failure["affected_ids"])]
                if not matching:
                    reasons.append("backend_failure_stage_unlocalized")
    for backend in (profile.get("analysis_v8") or {}).get("backends", []):
        error_code = backend.get("error_code")
        if error_code in generic or isinstance(error_code, str) and "attribute_error" in error_code.lower():
            reasons.append("legacy_overlay_generic_failure_not_resolved")
    if set(profile.get("errors", [])) & generic:
        reasons.append("historic_attribute_error_not_resolved")
    return {"passed": not reasons, "reason_codes": sorted(set(reasons)),
        "primary_measurements_changed": (profile.get("static") or {}).get("features") != (previous.get("static") or {}).get("features"),
        "observations_retained": len(analysis.get("observations", [])),
        "backend_stage_failures": analysis.get("backend_results", []),
        "source_hash_verified": (profile.get("static") or {}).get("input", {}).get("sha256") == previous["pdf_sha256"]}


def _guarded_preflight(root, prepared_run, kind):
    """Audit every zero-input refusal while leaving the campaign claim unused."""
    try:
        lab = require_offline_lab(True)
        clean_code(root)
        rows, lock, limits = load_v9_job(root, prepared_run, kind=kind)
        _worker_count(1, limits)
        if kind == "final":
            if v9_campaign_outcome(root) is not None:
                raise ValueError("V9 final campaign already claimed; inspect saved outcome")
            _verify_prerequisites(root, lock)
        return rows, lock, limits, lab
    except Exception:
        with ResearchRun(root, "cic_v9_refused", {"protocol": "V9 zero-input offline preflight",
                "prepared_run": prepared_run, "kind": kind, "test_access": False, "pdf_access": False}) as run:
            run.state["notes"] = "Preflight refused; no PDF/model load and no final campaign claim consumed."
            raise


def _attestation(root, prepared_run, kind, attested):
    if attested is not True:
        with ResearchRun(root, "cic_v9_refused", {"protocol": "V9 zero-input attestation refusal",
                "prepared_run": prepared_run, "kind": kind, "test_access": False, "pdf_access": False}) as run:
            run.state["notes"] = "No offline console attestation; no PDF/model access or campaign claim."
            raise ValueError("Explicit disconnected console LAB attestation required")
    return _guarded_preflight(root, prepared_run, kind)


def _profile(root, row, run, *, cache_path=None, cache_key=None, cache_mode="integration"):
    from malpdf.static.profile_worker import profile_pdf
    path = Path(row["pdf_relative_path"])
    if path.is_absolute() or ".." in path.parts or not path.is_relative_to("data/raw/cic_pdf"):
        raise ValueError("Locked PDF path outside CIC raw boundary")
    started = perf_counter()
    result = profile_pdf(root / path, boundary=root / "data/raw/cic_pdf", digest=row["pdf_sha256"],
        limits=LIMITS, cache_path=cache_path, cache_key=cache_key, analysis_version="v9",
        raw_artifact_dir=run.artifacts / "raw_streams" / cache_mode / row["pdf_sha256"])
    result.update({name: row[name] for name in ("sample_id", "pdf_relative_path", "pdf_sha256", "Label", "split")},
                  total_seconds=perf_counter() - started)
    measured = sum(value for value in result.get("timings", {}).values() if value is not None)
    result["overhead_seconds"] = max(0., result["total_seconds"] - measured)
    return result


def _append_private(path, record):
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, allow_nan=False) + "\n")


def run_v9_integration(root, prepared_run, *, lab_attested=False):
    root = Path(root).absolute()
    rows, lock, limits, lab = _attestation(root, prepared_run, "integration", lab_attested)
    method = {"protocol": "V9 bounded three-file offline extraction integration", "test_access": False,
        "prepared_run": prepared_run, "fingerprint": lock["fingerprint"], "lab_checks": lab,
        "fitting": False, "model_loading": False, "detector_quality_evaluation": False}
    with ResearchRun(root, INTEGRATION_STUDY, method) as run:
        records, assessments = [], []
        _, _, old_v8, _ = _baseline_metadata(root)
        previous = {row["sample_id"]: row for row in old_v8}
        try:
            for row in rows:
                require_offline_lab(lab_attested)
                _worker_count(1, limits)
                profile = _profile(root, row, run)
                records.append(profile)
                _append_private(run.artifacts / "per_file.jsonl", profile)
                assessment = assess_integration(profile, previous[row["sample_id"]])
                assessments.append({"sha256": row["pdf_sha256"], "sample_id": row["sample_id"], **assessment})
                _append_private(run.artifacts / "integration_assessments.jsonl", assessments[-1])
                run.progress("integration_file_completed", processed=len(records), planned=3, passed=assessment["passed"])
            if v9_source_fingerprint(root) != lock["fingerprint"]:
                raise ValueError("Generating source/backend changed during integration")
            result = {"status": "passed" if all(item["passed"] for item in assessments) else "blocked",
                "recorded": len(records), "planned": 3, "fingerprint": lock["fingerprint"],
                "failure_reason_counts": dict(Counter(code for item in assessments for code in item["reason_codes"])),
                "primary_measurement_change_count": sum(item["primary_measurements_changed"] for item in assessments),
                "private_assessments_path": str((run.artifacts / "integration_assessments.jsonl").relative_to(root)),
                "scope": "extraction integration only; no probabilities, model fitting or detector-quality metrics"}
            write_json(run.report / "integration_evidence.json", result)
            run.state.update(status="completed", integration_status=result["status"], recorded=len(records),
                notes="Three-file extraction integration; partial evidence remains partial. Detector metrics unavailable by design.")
        finally:
            write_json(run.report / "partial_inventory.json", {"recorded": len(records), "planned": 3,
                "status_counts": dict(Counter(row["status"] for row in records)), "probabilities_evaluated": 0})
    return run.state


def _prerequisite(root, study, identifier, filename):
    report = Path("reports/experiments") / study / _identifier(identifier)
    summary = _json(root, report / "run_summary.json")
    value = _json(root, report / filename)
    if summary["status"] != "completed" or value.get("status") != "passed":
        raise ValueError("V9 prerequisite did not pass")
    if value.get("fingerprint") != v9_source_fingerprint(root):
        raise ValueError("V9 prerequisite source/backend/budget fingerprint changed")
    return {"run_id": identifier, "study": study, "evidence_path": str(report / filename),
        "evidence_sha256": _sha(_content(root, report / filename)),
        "summary_path": str(report / "run_summary.json"), "summary_sha256": _sha(_content(root, report / "run_summary.json"))}, value


def _validated_prerequisites(root, integration_run, validation_run):
    integration, actual = _prerequisite(root, INTEGRATION_STUDY, integration_run, "integration_evidence.json")
    validation, checks = _prerequisite(root, VALIDATION_STUDY, validation_run, "validation_evidence.json")
    if actual.get("recorded") != 3 or actual.get("planned") != 3:
        raise ValueError("V9 integration was incomplete")
    expected_checks = {name: 0 for name in ("pytest", "pip_check", "diff_check", "source_integrity", "ignore_check")}
    if (checks.get("checks") != expected_checks or checks.get("python_major_minor") != "3.11"
            or checks.get("cpu_only") is not True or checks.get("clean_generating_code") is not True):
        raise ValueError("V9 required fresh Python3.11 CPU regression checks not verified")
    return {"integration": integration, "validation": validation}


def _verify_prerequisites(root, lock):
    pinned = lock["prerequisites"]
    current = _validated_prerequisites(root, pinned["integration"]["run_id"], pinned["validation"]["run_id"])
    if pinned != current:
        raise ValueError("V9 sealed prerequisite evidence changed")


def seal_v9_final(root, integration_run, validation_run):
    """Metadata-only final seal after successful matching integration/regression."""
    root = Path(root).absolute()
    clean_code(root)
    with ResearchRun(root, PREPARE_STUDY, {"protocol": "V9 one-shot final metadata seal",
            "campaign": CAMPAIGN_ID, "test_access": False, "pdf_access": False, "fitting": False}) as run:
        if v9_campaign_outcome(root) is not None:
            raise ValueError("V9 final already attempted; a new preparation cannot grant another attempt")
        prerequisites = _validated_prerequisites(root, integration_run, validation_run)
        rows, _, _, baseline = _baseline_metadata(root)
        models = _freeze_models(root, run)
        from malpdf.inference.evidence_policy_v9 import build_dependency_ledger
        write_json(run.report / "dependency_ledger.json", {"columns": build_dependency_ledger(models["C1_v8"]["manifest"]["feature_order"]),
            "missingness": "not_verified_until_offline_frozen_load", "model_columns": 173})
        lock = {"campaign": CAMPAIGN_ID, "kind": "final", "rows": rows, "all_rows": rows,
            "subset_sha256": baseline["subset_sha256"], "configuration": baseline["configuration"],
            "baseline_v7": V7_RUN, "baseline_v8": V8_RUN, "fingerprint": v9_source_fingerprint(root),
            "models": models, "prerequisites": prerequisites,
            "evidence_checksums": _saved_evidence_specs(root, baseline["configuration"]),
            "ledger_sha256": _sha((run.report / "dependency_ledger.json").read_bytes()),
            "created_at_utc": datetime.now(timezone.utc).isoformat(), "final_attempts": 1,
            "threshold": .5, "retraining": False, "deployment": False}
        write_json(run.artifacts / "job_lock.json", lock)
        run.state.update(status="completed", kind="final", rows=64,
            job_lock_sha256=_sha((run.artifacts / "job_lock.json").read_bytes()),
            notes="Matching integration/regression sealed; original models/threshold/splits immutable. No PDFs or pickle loading during seal.")
    return run.state


def _claim_path(root):
    path = Path(root).absolute() / "artifacts/cic_v9_campaign/final_attempt.json"
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("Unsafe V9 campaign claim path")
    return path


def claim_v9_campaign(root, prepared_run, final_run):
    """One atomic campaign-wide claim. Interrupted/failed claims stay forever."""
    path = _claim_path(root)
    prepared_run, final_run = _identifier(prepared_run), _identifier(final_run)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        write_json(path, {"campaign": CAMPAIGN_ID, "prepared_run": prepared_run, "final_run": final_run,
            "claimed_at_utc": datetime.now(timezone.utc).isoformat(),
            "policy": "one final attempt across all prepared jobs; never delete, retry or resume a consumed claim"})
    except FileExistsError as error:
        raise ValueError("V9 final campaign already attempted; preserve saved outcome") from error


def v9_campaign_outcome(root):
    """Saved final status remains readable when executable sources later change."""
    path = _claim_path(root)
    if not path.exists():
        return None
    marker = _json(root, path.relative_to(Path(root).absolute()))
    if marker.get("campaign") != CAMPAIGN_ID:
        raise ValueError("Invalid V9 campaign marker")
    report = Path("reports/experiments") / FINAL_STUDY / _identifier(marker["final_run"]) / "run_summary.json"
    result = {"status": "claimed_without_final_outcome", "report_path": None,
        "prepared_run": _identifier(marker["prepared_run"]), "final_run": marker["final_run"]}
    if (Path(root) / report).exists():
        summary = _json(root, report)
        result.update(status=summary["status"], report_path=str(report),
                      recorded=summary.get("recorded", 0), release_status=summary.get("release_status"))
    return result


def load_frozen_models(root, specs, *, lab_attested=False):
    """Offline-only trusted pickle loading with exact original sklearn contract."""
    require_offline_lab(lab_attested)
    _verify_model_specs(root, specs)
    import joblib
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.impute import SimpleImputer
    from sklearn.pipeline import Pipeline
    loaded, missingness = {}, {}
    for name, spec in specs.items():
        model = joblib.load(io.BytesIO(_content(root, spec["snapshot_path"], maximum=64 * 1024**2)))
        order, manifest = spec["manifest"]["feature_order"], spec["manifest"]
        if (type(model) is not Pipeline or len(model.steps) != 2
                or type(model.steps[0][1]) is not SimpleImputer or type(model.steps[1][1]) is not RandomForestClassifier
                or not np.array_equal(model.classes_, [0, 1]) or list(model.feature_names_in_) != order):
            raise ValueError("Frozen binary pipeline/feature order changed")
        imputer, forest = model.steps[0][1], model.steps[1][1]
        if (imputer.strategy != "median" or imputer.add_indicator is not True or imputer.keep_empty_features is not True
                or len(imputer.statistics_) != len(order) or not np.isfinite(imputer.statistics_).all()
                or forest.random_state != 42 or forest.n_jobs != 1):
            raise ValueError("Frozen Train-only preprocessing/model contract changed")
        if any(forest.get_params()[key] != value for key, value in manifest["configuration"].items()):
            raise ValueError("Frozen RF configuration changed")
        indices = list(imputer.indicator_.features_)
        if any(type(index) not in (int, np.int64, np.int32) or not 0 <= index < len(order) for index in indices):
            raise ValueError("Frozen missing-indicator contract changed")
        missingness[name] = [order[int(index)] for index in indices]
        loaded[name] = model
    return loaded, missingness


def frozen_probability(model, values, order):
    """Infer with exact original columns and nulls; no fitting or interpretation change."""
    import numpy as np
    import pandas as pd
    if list(values) != list(order):
        raise ValueError("Frozen feature order mismatch")
    matrix = pd.DataFrame([[values[name] for name in order]], columns=order, dtype=float)
    if np.isinf(matrix.to_numpy()).any():
        raise ValueError("Nonfinite frozen model observation")
    probability = model.predict_proba(matrix)
    if probability.shape != (1, 2) or not np.isfinite(probability).all() or not np.all((0 <= probability) & (probability <= 1)):
        raise ValueError("Invalid frozen model probabilities")
    return float(probability[0, 1])


def probability_parity(before, after, *, input_unchanged):
    valid = all(type(value) in (float, int) and math.isfinite(value) and 0 <= value <= 1 for value in (before, after))
    exact = valid and abs(before - after) <= PARITY_ATOL and int(before >= .5) == int(after >= .5)
    return {"input_unchanged": input_unchanged, "probability_parity": exact if input_unchanged else None,
        "hard_label_changed": int(before >= .5) != int(after >= .5) if valid else None,
        "absolute_difference": abs(before - after) if valid else None,
        "regression": bool(input_unchanged and not exact)}


def v9_decision_metrics(decisions):
    """Actual labels determine classification; calibration has its own ML cohort."""
    from malpdf.evaluation.binary import evaluate_binary_predictions
    from malpdf.evaluation.selective import expected_calibration_error
    from sklearn.metrics import brier_score_loss
    planned = Counter(item["Label"] for item in decisions)
    chosen = [item for item in decisions if item.get("predicted_label") is not None]
    scored = [item for item in decisions if type(item.get("malicious_probability")) in (float, int)
        and math.isfinite(item["malicious_probability"]) and 0 <= item["malicious_probability"] <= 1]
    counts = Counter(item["Label"] for item in chosen)
    tp = sum(item["Label"] == 1 and item["predicted_label"] == 1 for item in chosen)
    fp = sum(item["Label"] == 0 and item["predicted_label"] == 1 for item in chosen)
    ratio = lambda left, right: left / right if right else None
    actual = evaluate_binary_predictions([item["Label"] for item in chosen],
        [item["predicted_label"] for item in chosen]) if chosen else None
    calibration = None
    if scored:
        truth, probabilities = [item["Label"] for item in scored], [item["malicious_probability"] for item in scored]
        calibration = {"rows": len(scored), "class_counts": dict(Counter(truth)),
            "ece": expected_calibration_error(truth, probabilities, n_bins=10),
            "brier": float(brier_score_loss(truth, probabilities, pos_label=1)),
            "ece_convention": "10 equal-width bins; p=1 in last bin", "scope": "all valid frozen ML probabilities, including abstentions"}
    return {"planned": len(decisions), "classified": len(chosen), "inconclusive": len(decisions) - len(chosen),
        "planned_class_counts": dict(planned), "classified_class_counts": dict(counts),
        "coverage": ratio(len(chosen), len(decisions)), "true_positives": tp, "false_positives": fp,
        "conditional_recall": ratio(tp, counts[1]), "conditional_fpr": ratio(fp, counts[0]),
        "end_to_end_detected_fraction": ratio(tp, planned[1]), "end_to_end_false_positive_fraction": ratio(fp, planned[0]),
        "actual_label_metrics": actual, "probability_metrics": calibration,
        "abstention_policy": "unscored; quarantine; never counted as detection or benign"}


def _cache_key(row, fingerprint):
    return _sha(_canonical({"sha256": row["pdf_sha256"], "fingerprint": fingerprint}))


def run_v9_final(root, prepared_run, *, lab_attested=False):
    """The sole final64 cold/warm attempt, with frozen inference and honest refusals."""
    root = Path(root).absolute()
    rows, lock, limits, lab = _attestation(root, prepared_run, "final", lab_attested)
    method = {"protocol": "same64 exposed CIC Train/dev V9 one-shot frozen diagnostic",
        "campaign": CAMPAIGN_ID, "prepared_run": prepared_run, "fingerprint": lock["fingerprint"],
        "prerequisites": lock["prerequisites"], "models": lock["models"], "threshold": .5,
        "fitting": False, "test_access": False, "deployment": False, "lab_checks": lab,
        "subset_sha256": lock["subset_sha256"], "configuration": lock["configuration"],
        "cache": "cold fresh application cache; warm complete-profile cache only after immutable PDF rehash; OS cache uncontrolled"}
    with ResearchRun(root, FINAL_STUDY, method) as run:
        records, decisions, paired, regressions = [], [], [], []
        run.state["notes"] = "LAB diagnosis only; fixed original artifacts/173 columns/threshold. No fitting/calibration/tuning/Test."
        try:
            # Loading and admission precede the sole claim. Failures at this point
            # still produce an immutable failed run but consume no PDF attempt.
            models, missingness = load_frozen_models(root, lock["models"], lab_attested=lab_attested)
            _worker_count(1, limits)
            run.state["parser_memory_admission"] = worker_memory_budget(limits)
            require_offline_lab(lab_attested)
            _verify_prerequisites(root, lock)
            if v9_source_fingerprint(root) != lock["fingerprint"]:
                raise ValueError("Source/backend changed before final claim")
            claim_v9_campaign(root, prepared_run, run.identifier)
            from malpdf.inference.evidence_policy_v9 import build_dependency_ledger, verify_model_inputs, evidence_decision_v9
            from malpdf.experiments.cic_static_accuracy import PROFILE_VARIANTS, profile_feature_values, profile_input_available
            from malpdf.experiments.cic_static_benchmark import summarize_profiles
            c1_manifest = lock["models"]["C1_v8"]["manifest"]
            write_json(run.report / "effective_dependency_ledger.json", {"columns": build_dependency_ledger(
                c1_manifest["feature_order"], missing_supported=missingness["C1_v8"]), "frozen_artifact_sha256": c1_manifest["artifact_sha256"]})
            old_v7, _, _ = baseline_records(root)
            _, _, old_v8, _ = _baseline_metadata(root)
            v7_by_id, v8_by_id = ({item["sample_id"]: item for item in history} for history in (old_v7, old_v8))
            original_c1 = _json(root, Path("artifacts/cic_static_profile") / V8_RUN / "c1_v8_decisions.json")
            original_decisions = {item["sample_id"]: item for item in original_c1}
            saved_legacy = _json(root, Path("artifacts/cic_static_profile") / V7_RUN / "observed_development_predictions.json")
            score_legacy = {name: dict(zip(saved_legacy["sample_ids"], scores)) for name, scores in saved_legacy["probabilities"].items()}
            cache = run.artifacts / "cache"
            cache.mkdir(mode=0o700)
            for mode in ("cold", "warm"):
                for row in rows:
                    require_offline_lab(lab_attested)
                    _worker_count(1, limits)
                    key = _cache_key(row, lock["fingerprint"])
                    cache_path = cache / (key + ".json")
                    profile = _profile(root, row, run, cache_path=cache_path if mode == "warm" else None, cache_key=key, cache_mode=mode)
                    profile.update(cache_mode=mode, repeat=0)
                    # Persist the completed extraction before any model or
                    # policy operation can fail; it is never rerun for metrics.
                    records.append(profile)
                    _append_private(run.artifacts / "per_file.jsonl", profile)
                    if mode == "cold":
                        available = profile_input_available(profile, limits.max_file_bytes)
                        analysis = profile.get("analysis_v9") or {}
                        contract = verify_model_inputs(profile, c1_manifest["feature_order"], analysis,
                            missing_supported=missingness["C1_v8"])
                        probability = frozen_probability(models["C1_v8"], v8_feature_values(profile), c1_manifest["feature_order"]) if available else None
                        if row["split"] == "validation":
                            identity = {**c1_manifest, "feature_count": 173}
                            decision = evidence_decision_v9(probability, analysis, input_available=available,
                                model_identity=identity, model_contract=contract)
                            decision.update(sample_id=row["sample_id"], sha256=row["pdf_sha256"], Label=int(row["Label"]))
                            decisions.append(decision)
                            _append_private(run.artifacts / "c1_decisions.jsonl", decision)
                        prior = v8_by_id[row["sample_id"]]
                        previous_probability = (original_decisions.get(row["sample_id"]) or {}).get("malicious_probability")
                        c1_same = v8_feature_values(prior) == v8_feature_values(profile)
                        c1_parity = probability_parity(previous_probability, probability, input_unchanged=c1_same) if previous_probability is not None else {"input_unchanged": c1_same, "probability_parity": None, "regression": False}
                        variants = {}
                        for variant in PROFILE_VARIANTS:
                            order = lock["models"][variant]["manifest"]["feature_order"]
                            values = profile_feature_values(profile, variant)
                            score = frozen_probability(models[variant], values, order) if available else None
                            before = score_legacy[variant].get(row["sample_id"])
                            unchanged = profile_feature_values(v7_by_id[row["sample_id"]], variant) == values
                            parity = probability_parity(before, score, input_unchanged=unchanged) if before is not None else {"input_unchanged": unchanged, "probability_parity": None, "regression": False}
                            variants[variant] = {"probability": score, **parity}
                            if parity["regression"] or not unchanged or (before is not None and score is None):
                                regressions.append({"sample_id": row["sample_id"], "sha256": row["pdf_sha256"],
                                    "variant": variant, "reason": "unchanged-input_probability_regression" if parity["regression"]
                                    else "legacy_measurement_changed_review_required" if not unchanged else "numeric_eligibility_lost"})
                        if c1_parity["regression"]:
                            regressions.append({"sample_id": row["sample_id"], "variant": "C1_v8", "reason": "unchanged-input_probability_regression"})
                        pair = {"sample_id": row["sample_id"], "sha256": row["pdf_sha256"], "Label": int(row["Label"]), "partition": row["split"],
                            "v7_status": v7_by_id[row["sample_id"]]["status"], "v8_status": (prior.get("analysis_v8") or {}).get("status"),
                            "v9_status": analysis.get("status", "unavailable"), "v9_legacy_status": profile["status"],
                            "observations": len(analysis.get("observations", [])), "edges": len(analysis.get("edges", [])),
                            "verified_recovered_object_ids": [item["id"] for item in analysis.get("observations", [])
                                if item.get("backend") == "MuPDF" and item.get("document_sha256") == row["pdf_sha256"]
                                and type(item.get("object_number")) is int and type(item.get("generation")) is int
                                and item.get("status") == "observed" and (item.get("projection") or {}).get("projection_complete") is True],
                            "usable_script_ids": [item["id"] for item in analysis.get("observations", [])
                                if item.get("kind") == "script" and item.get("extraction_status") == "complete"
                                and item.get("ast_status") == "complete" and item.get("decoded_validated") is True],
                            "usable_payload_ids": [item["id"] for item in analysis.get("observations", [])
                                if item.get("kind") == "payload" and item.get("extraction_status") == "complete"
                                and item.get("decoded_validated") is True],
                            "verified_edge_counts": dict(Counter(item.get("kind") for item in analysis.get("edges", []) if item.get("status") == "verified")),
                            "resource_usage": {name: profile.get(name) for name in ("total_seconds", "worker_seconds", "peak_rss_bytes", "peak_family_rss_sampled_bytes")},
                            "verified_witnesses": [item for item in analysis.get("witnesses", []) if item.get("status") == "verified"],
                            "capability_checks": analysis.get("capability_checks", []), "backend_stage_failures": analysis.get("backend_results", []),
                            "conflicts": analysis.get("conflicts", []), "model_contract": contract,
                            "c1_input_parity": c1_parity, "legacy_frozen_predictions": variants,
                            "v8_c1_decision": original_decisions.get(row["sample_id"]),
                            "v9_c1_decision": decisions[-1] if row["split"] == "validation" else None,
                            "old_partial_reason_review_required": row["split"] == "validation" and (prior.get("analysis_v8") or {}).get("status") == "partial"}
                        paired.append(pair)
                        _append_private(run.artifacts / "paired_evidence.jsonl", pair)
                        if profile["status"] == "complete" and analysis.get("complete") is True and not cache_path.exists():
                            names = ("profile_version", "status", "errors", "reasons", "static", "code", "analysis_v8", "analysis_v9")
                            value = {name: profile[name] for name in names if name in profile}
                            encoded = json.dumps(value, sort_keys=True, allow_nan=False).encode()
                            if len(encoded) <= 2 * 1024**2:
                                write_json(cache_path, {"key": key, "profile_sha256": _sha(encoded), "profile": value})
                    run.progress("final_file_completed", cache_mode=mode, processed=len(records), planned=128, status=profile["status"])
            if v9_source_fingerprint(root) != lock["fingerprint"]:
                raise ValueError("Source/backend changed during final attempt")
            metric = v9_decision_metrics(decisions)
            write_json(run.artifacts / "legacy_regressions.json", regressions)
            write_json(run.report / "c1_comparison.json", {"policy": POLICY_ID, "threshold": .5, "model": metric,
                "baseline_v7": V7_RUN, "baseline_v8": V8_RUN, "fitting": False, "deployment": False})
            actual, calibration = metric["actual_label_metrics"], metric["probability_metrics"]
            if actual is not None:
                run.state["metrics"]["C1_v9_frozen/cic_development_classified"] = actual
            if calibration is not None:
                run.state["metrics"]["C1_v9_frozen/cic_development_valid_probability"] = {"ece": calibration["ece"], "brier": calibration["brier"]}
            legacy_metrics = {}
            for variant in PROFILE_VARIANTS:
                scored_rows = [{"Label": item["Label"], "malicious_probability": item["legacy_frozen_predictions"][variant]["probability"],
                    "predicted_label": None if item["legacy_frozen_predictions"][variant]["probability"] is None else
                        int(item["legacy_frozen_predictions"][variant]["probability"] >= .5)}
                    for item in paired if item["partition"] == "validation"]
                legacy_metrics[variant] = v9_decision_metrics(scored_rows)
                actual_legacy = legacy_metrics[variant]["actual_label_metrics"]
                calibration_legacy = legacy_metrics[variant]["probability_metrics"]
                if actual_legacy is not None:
                    run.state["metrics"][variant + "_v7_frozen/cic_development_known_input"] = {
                        **actual_legacy, **({"ece": calibration_legacy["ece"], "brier": calibration_legacy["brier"]} if calibration_legacy else {})}
            write_json(run.report / "legacy_frozen_metrics.json", {"models": legacy_metrics,
                "source": "v7 original32 Train artifacts, no refitting", "threshold": .5, "quality_scope": "exposed Validation only"})
            statuses = Counter(item["v9_status"] for item in paired)
            from malpdf.experiments.cic_static_benchmark import distribution
            cold = [item for item in records if item["cache_mode"] == "cold"]
            write_json(run.report / "resource_usage.json", {"scope": "cold full process, family RSS sampled; OS cache/host load uncontrolled",
                "measurements": {name: {"v7": distribution([item.get(name) for item in old_v7]),
                    "v8": distribution([item.get(name) for item in old_v8]), "v9": distribution([item.get(name) for item in cold])}
                    for name in ("total_seconds", "worker_seconds", "peak_rss_bytes", "peak_family_rss_sampled_bytes")}})
            write_json(run.report / "graph_coverage.json", {"paired_files": len(paired),
                "verified_recovered_objects": sum(len(item["verified_recovered_object_ids"]) for item in paired),
                "recovery_identity_scope": "backend-local original snapshot and exact object/generation; no verified historical/cross-backend revision identity claim",
                "files_with_usable_script_ast": sum(bool(item["usable_script_ids"]) for item in paired),
                "files_with_usable_payload": sum(bool(item["usable_payload_ids"]) for item in paired),
                "files_with_verified_witness": sum(bool(item["verified_witnesses"]) for item in paired),
                "witness_family_counts": dict(Counter(witness["family"] for item in paired for witness in item["verified_witnesses"])),
                "capability_state_counts": dict(Counter(check.get("backend", "unknown") + "/" + check["capability"] + "/" + check["status"]
                    for item in paired for check in item["capability_checks"])),
                "semantics": "usable syntax and model eligibility; no threat-family exploit-detection claim"})
            old_partials = [item for item in paired if item["old_partial_reason_review_required"]]
            unsafe = any((row.get("analysis_v9") or {}).get("original_bytes_changed") is not False
                or (row.get("analysis_v9") or {}).get("active_content_executed") is not False for row in records)
            summary = {"status": "completed_measurement", "release_status": "blocked" if regressions or unsafe else "technical_review_required",
                "paired_samples": len(paired), "status_counts": dict(statuses), "c1": metric,
                "legacy_unexplained_regressions": len(regressions), "safety_evidence_incomplete": unsafe,
                "old_partial_reviews": len(old_partials), "old_partial_review_expected": 21,
                "old_partial_reason_counts": dict(Counter(reason for item in old_partials for reason in
                    (item["v9_c1_decision"] or {}).get("reason_codes", (item["v9_c1_decision"] or {}).get("reasons", [])))),
                "private_per_file_path": str((run.artifacts / "paired_evidence.jsonl").relative_to(root)),
                "scope": "exposed diagnostic cohort; eligibility graphs do not prove malware behavior; no forced classification/generalization claim"}
            if len(old_partials) != 21:
                summary["release_status"] = "blocked"
            write_json(run.report / "v9_acceptance.json", summary)
            run.state.update(status="completed", recorded=len(records), release_status=summary["release_status"])
        finally:
            from malpdf.experiments.cic_static_benchmark import summarize_profiles
            pipeline = summarize_profiles(records, {"cold": 64, "warm": 64})
            write_json(run.report / "pipeline_summary.json", pipeline)
            write_json(run.report / "partial_decision_inventory.json", {"saved_decisions": len(decisions),
                "planned_development_decisions": 32, "status": "complete" if len(decisions) == 32 else "partial",
                "metric_scope": "Quality metrics withheld when the planned final measurement is incomplete; saved decisions remain private evidence."})
            run.state["recorded"] = len(records)
    return run.state


def latest_v9_job(root, *, kind="integration"):
    """Choose newest matching metadata preparation, never a favorable result."""
    candidates = []
    for path in (Path(root) / "reports/experiments" / PREPARE_STUDY).glob("run_*/run_summary.json"):
        summary = _json(root, path.relative_to(root))
        if summary.get("status") == "completed" and summary.get("kind") == kind:
            try:
                load_v9_job(root, path.parent.name, kind=kind)
            except ValueError:
                continue
            candidates.append(path.parent.name)
    if not candidates:
        raise ValueError("No matching prepared V9 job; metadata preparation required")
    return sorted(candidates)[-1]


def latest_v9_prerequisite(root, study, filename):
    candidates = []
    for path in (Path(root) / "reports/experiments" / study).glob("run_*/run_summary.json"):
        try:
            _prerequisite(root, study, path.parent.name, filename)
        except (ValueError, FileNotFoundError, KeyError):
            continue
        candidates.append(path.parent.name)
    if not candidates:
        raise ValueError("No passed V9 prerequisite matching the current source/backend/budgets")
    return sorted(candidates)[-1]

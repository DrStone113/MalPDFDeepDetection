"""Offline profiling tests use synthetic manifests and benign generated PDFs."""

from dataclasses import replace
import base64
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import multiprocessing
import os
import time
import re
import zlib

import pytest
from pypdf import PdfWriter
from pypdf.generic import ArrayObject, DictionaryObject, EncodedStreamObject, NameObject
from pypdf.generic import IndirectObject

from malpdf.experiments import cic_static_benchmark as study
from malpdf.static.analyzer import StaticPDFAnalyzer
from malpdf.static.code_inspector import CodeInspectionLimits, _inspect_code_bytes, _script_text
from malpdf.static.lab_guard import require_offline_lab
from malpdf.static.profile_worker import profile_pdf
from malpdf.static.profiling import StageTimings, STAGES


def fixture_pdf(script=b'var n=1; util["pri"+"ntf"]("fixture");', filters=()):
    writer = PdfWriter()
    writer.add_blank_page(72, 72)
    if script is not None:
        payload = EncodedStreamObject()
        data = script
        for name in reversed(filters):
            if name in {"/FlateDecode", "/Fl"}:
                data = zlib.compress(data)
            elif name in {"/ASCIIHexDecode", "/AHx"}:
                data = data.hex().encode() + b">"
            else:
                data = base64.a85encode(data, adobe=True)
        payload._data = data
        if filters:
            payload[NameObject("/Filter")] = ArrayObject([NameObject(name) for name in filters])
        writer._root_object[NameObject("/OpenAction")] = writer._add_object(DictionaryObject({
            NameObject("/S"): NameObject("/JavaScript"), NameObject("/JS"): writer._add_object(payload)}))
    output = io.BytesIO(); writer.write(output)
    return output.getvalue()


def test_exclusive_nested_stage_times_and_unknowns(monkeypatch):
    ticks = iter([0.0, 1.0, 2.0, 4.0])
    monkeypatch.setattr("malpdf.static.profiling.perf_counter", lambda: next(ticks))
    timer = StageTimings()
    with timer.stage("parse_pdf"):
        with timer.stage("stream_decode"):
            pass
    assert timer.seconds["parse_pdf"] == 3.0
    assert timer.seconds["stream_decode"] == 1.0
    assert timer.seconds["js_ast"] is None


@pytest.mark.parametrize("filters", [("/ASCIIHexDecode",), ("/AHx",), ("/ASCII85Decode",), ("/A85",),
    ("/ASCIIHexDecode", "/FlateDecode"), ("/ASCII85Decode", "/FlateDecode")])
def test_ascii_streams_and_filter_chains_recover_js_without_execution(filters):
    timer = StageTimings()
    result = _inspect_code_bytes(fixture_pdf(filters=filters), CodeInspectionLimits(), timings=timer)
    assert result["complete"] and result["schema_version"] == "pdf-code-inspection-v4"
    assert result["ast"]["named_calls"]["util.printf"] == 1
    assert timer.seconds["stream_decode"] > 0 and timer.seconds["js_ast"] > 0
    assert not result["active_content_executed"]


@pytest.mark.parametrize("filter_name,data,error", [
    ("/ASCIIHexDecode", b"zz>", "invalid_asciihex_stream"),
    ("/ASCII85Decode", b"bad", "invalid_ascii85_stream"),
    ("/ASCIIHexDecode", b"41" * 2000 + b">", "script_byte_limit"),
    ("/ASCII85Decode", b"z" * 1000 + b"~>", "script_byte_limit"),
])
def test_ascii_decoders_keep_corruption_and_output_caps_explicit(filter_name, data, error):
    payload = EncodedStreamObject(); payload._data = data
    payload[NameObject("/Filter")] = NameObject(filter_name)
    with pytest.raises(ValueError, match=error):
        _script_text(payload, replace(CodeInspectionLimits(), max_script_bytes=1024))


@pytest.mark.parametrize("field,value", [("uid", 0), ("ssh_session", True), ("connected_interfaces", ["eth0"]),
    ("unknown_interfaces", ["eth1"]), ("shared_mounts", ["/mnt/shared"])])
def test_lab_guard_rejects_connected_shared_root_or_ssh(field, value):
    state = {"uid": 1000, "ssh_session": False, "connected_interfaces": [], "unknown_interfaces": [], "shared_mounts": []}
    state[field] = value
    with pytest.raises(ValueError, match="Offline LAB required"):
        require_offline_lab(True, state=state)


def test_run_guard_precedes_manifest_model_and_pdf_reads(tmp_path, monkeypatch):
    def guard(*args, **kwargs):
        raise ValueError("Offline LAB required")
    monkeypatch.setattr(study, "require_offline_lab", guard)
    monkeypatch.setattr(study, "load_job", lambda *args: pytest.fail("Read job before LAB guard"))
    class Refused:
        def __init__(self, *args, **kwargs): self.state = {}
        def __enter__(self): return self
        def __exit__(self, *args): return False
    monkeypatch.setattr(study, "ResearchRun", Refused)
    with pytest.raises(ValueError, match="Offline LAB required"):
        study.run_cic_profile(tmp_path, "not_even_a_valid_run", lab_attested=True)


def manifests():
    manifest, sources = [], []
    for partition in ("train", "validation", "test"):
        for label in ("0", "1"):
            for index in range(8):
                identifier = f"{partition}_{label}_{index}"
                digest = hashlib.sha256(identifier.encode()).hexdigest()
                manifest.append({"sample_id": identifier, "duplicate_group_id": identifier,
                    "Label": label, "split": partition, "cohort": "cic"})
                sources.append({"sample_id": identifier, "Label": label, "pdf_sha256": digest,
                    "related_group_id": identifier, "pdf_relative_path": f"data/raw/cic_pdf/{identifier}.pdf"})
    return manifest, sources


def test_fixed_selection_is_order_independent_and_never_selects_test():
    manifest, sources = manifests()
    first = study.select_subset(manifest, sources, 8)
    assert first == study.select_subset(list(reversed(manifest)), list(reversed(sources)), 8)
    assert len(first) == 16 and {row["split"] for row in first} == {"train", "validation"}
    assert all(sum(row["split"] == part and row["Label"] == label for row in first) == 4
               for part in ("train", "validation") for label in ("0", "1"))


@pytest.mark.parametrize("kind", ["file", "related", "vector", "label"])
def test_saved_split_or_label_changes_are_refused(kind):
    manifest, sources = manifests()
    if kind == "label":
        sources[0]["Label"] = "1"
    elif kind == "vector":
        manifest[16]["duplicate_group_id"] = manifest[0]["duplicate_group_id"]
    else:
        key = "pdf_sha256" if kind == "file" else "related_group_id"
        sources[16][key] = sources[0][key]
    with pytest.raises(ValueError):
        study.select_subset(manifest, sources, 8)


def test_normalized_publisher_labels_are_joined_and_conflicts_refused():
    manifest, sources = manifests()
    rows = study.select_subset(manifest, sources, 8)
    normalized = [{**row, "target_pdf_byte_verified": "True", "target_label_source": "fixture publisher label"} for row in rows]
    study.verify_label_provenance(rows, normalized)
    assert all(row["label_source"] == "fixture publisher label" for row in rows)
    normalized.append(dict(normalized[0]))  # Same-file aliases are not extra identities.
    study.verify_label_provenance(rows, normalized)
    normalized[0]["Label"] = "1" if normalized[0]["Label"] == "0" else "0"
    with pytest.raises(ValueError, match="publisher label"):
        study.verify_label_provenance(rows, normalized)


def test_actual_profile_cold_warm_invalid_hash_and_ast_failure(tmp_path):
    path = tmp_path / "benign.pdf"
    content = fixture_pdf(filters=("/ASCIIHexDecode", "/FlateDecode"))
    path.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    cold = profile_pdf(path, boundary=tmp_path, digest=digest)
    assert cold["status"] == "complete" and cold["code"]["ast_complete"]
    assert cold["peak_rss_bytes"] > 0 and cold["peak_family_rss_sampled_bytes"] > 0
    assert all(cold["timings"][key] is not None for key in STAGES if key not in {"inference", "inference_gate"})
    value = {key: cold[key] for key in ("profile_version", "status", "errors", "reasons", "static", "code")}
    checksum = hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
    cache = tmp_path / "cache.json"
    cache.write_text(json.dumps({"key": "fixture", "profile_sha256": checksum, "profile": value}))
    warm = profile_pdf(path, boundary=tmp_path, digest=digest, cache_path=cache, cache_key="fixture")
    assert warm["cache_hit"] and warm["timings"]["parse_pdf"] is None
    assert warm["static"]["features"] == cold["static"]["features"]
    changed = profile_pdf(path, boundary=tmp_path, digest=digest, cache_path=cache, cache_key="new_version")
    assert not changed["cache_hit"] and changed["status"] == "complete"
    mismatch = profile_pdf(path, boundary=tmp_path, digest="0" * 64)
    assert mismatch["status"] == "input_error" and mismatch["static"] is None
    path.write_bytes(fixture_pdf(b"var =;"))
    bad = profile_pdf(path, boundary=tmp_path, digest=hashlib.sha256(path.read_bytes()).hexdigest())
    assert bad["status"] == "partial" and bad["code"]["ast"] is None
    assert "javascript_parse_error" in bad["errors"]


def test_analyzer_supplied_snapshot_hash_cannot_bypass_integrity(tmp_path):
    path = tmp_path / "benign.pdf"; content = fixture_pdf(None); path.write_bytes(content)
    result = StaticPDFAnalyzer().inspect(path, snapshot=content, snapshot_sha256="0" * 64)
    assert not result.parser["success"] and result.errors[0].fatal


def _stalled_profile_child(connection, *args):
    os.setsid()
    observed = {name: None for name in STAGES}; observed["read_hash"] = 0.001
    connection.send_bytes(json.dumps({"event": "finished", "stage": "read_hash", "timings": observed}).encode())
    connection.send_bytes(json.dumps({"event": "started", "stage": "parse_pdf", "timings": observed}).encode())
    time.sleep(30)


def test_profile_timeout_preserves_finished_stage_and_reaps_worker(tmp_path, monkeypatch):
    import malpdf.static.profile_worker as worker
    context = multiprocessing.get_context("fork")
    monkeypatch.setattr(worker.multiprocessing, "get_context", lambda *args: context)
    monkeypatch.setattr(worker, "_profile_child", _stalled_profile_child)
    monkeypatch.setattr(worker, "_worker_count", lambda *args: 1)
    before = {p.pid for p in multiprocessing.active_children()}
    result = profile_pdf(tmp_path / "unused.pdf", boundary=tmp_path, digest="0" * 64,
        limits=CodeInspectionLimits(cpu_seconds=1, wall_seconds=1))
    assert result["status"] == "timeout" and result["last_stage"] == "parse_pdf"
    assert result["timings"]["read_hash"] == 0.001 and result["timings"]["parse_pdf"] is None
    assert {p.pid for p in multiprocessing.active_children()} == before


@pytest.mark.parametrize("model_missing", [False, True])
def test_benign_whole_job_keeps_failed_rows_cache_misses_and_both_passes(tmp_path, monkeypatch, model_missing):
    from malpdf.inference import deployment
    import numpy as np
    raw = tmp_path / "data/raw/cic_pdf"; raw.mkdir(parents=True)
    rows = []
    for name, content in (("good", fixture_pdf()), ("bad_ast", fixture_pdf(b"var =;")), ("not_pdf", b"inert non-PDF fixture")):
        path = raw / (name + ".pdf"); path.write_bytes(content)
        rows.append({"sample_id": name, "pdf_relative_path": str(path.relative_to(tmp_path)),
            "pdf_sha256": hashlib.sha256(content).hexdigest(), "split": "train", "Label": "0"})
    class Model:
        def set_params(self, **params):
            assert params == {"n_jobs": 1}
            return self
        def predict_proba(self, frame):
            return np.tile([0.8, 0.2], (len(frame), 1))
    manifest = {"model_id": "fixture", "artifact_sha256": "0" * 64,
        "training_dataset": {"sha256": "1" * 64}, "feature_schema": "fixture", "threshold": 0.5}
    def load(root):
        if model_missing:
            raise deployment.DeploymentError("fixture missing artifact", code="deployment_artifact_missing")
        return Model(), manifest
    monkeypatch.setattr(deployment, "load_verified_deployment_model", load)
    monkeypatch.setattr(study, "require_offline_lab", lambda *args: {"fixture_lab": True})
    monkeypatch.setattr(study, "clean_code", lambda *args: None)
    cfg = {"warm_repeats": 1, "compare_models": False}
    monkeypatch.setattr(study, "load_job", lambda *args: (rows, {"configuration": cfg, "subset_sha256": "fixture", "fingerprint": {"backends": {"fixture": "1"}}}, CodeInspectionLimits(wall_seconds=20, cpu_seconds=12)))
    class Run:
        def __init__(self, root, *args, **kwargs):
            self.report, self.artifacts = root / "report", root / "artifacts"
            self.report.mkdir(); self.artifacts.mkdir(); self.state = {"metrics": {}}
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def progress(self, *args, **kwargs): pass
    monkeypatch.setattr(study, "ResearchRun", Run)
    state = study.run_cic_profile(tmp_path, "fixture", lab_attested=True)
    assert state["status"] == "completed"
    evidence = json.loads((tmp_path / "report/pipeline_summary.json").read_text())
    assert evidence["cold"]["planned"] == evidence["warm"]["planned"] == 3
    assert evidence["cold"]["status_counts"] == {"complete": 1, "partial": 1, "input_error": 1}
    assert evidence["warm"]["cache_hits"] == 1
    assert evidence["cold"]["ast_error_files"] == evidence["warm"]["ast_error_files"] == 1
    assert evidence["cold"]["inference_executed"] == (0 if model_missing else 2)
    if model_missing:
        assert evidence["model_setup"]["error_code"] == "deployment_artifact_missing"
        assert evidence["cold"]["stages_seconds"]["inference"]["measured"] == 0
        assert evidence["cold"]["stages_seconds"]["inference"]["sum"] is None
        assert evidence["cold"]["stages_seconds"]["inference_gate"]["measured"] == 2
    lines = (tmp_path / "artifacts/per_file.jsonl").read_text().splitlines()
    assert len(lines) == 6
    assert all(json.loads(line)["prediction"]["predicted_label"] is None for line in lines if json.loads(line)["sample_id"] == "not_pdf")


def test_cic_comparison_uses_same_rows_train_only_imputation_and_keeps_refusals(tmp_path, monkeypatch):
    from sklearn.impute import SimpleImputer
    from malpdf.static.schema import RIT_FEATURES
    captured = []
    original = SimpleImputer.fit
    def fit(self, values, *args, **kwargs):
        captured.append(values.copy())
        return original(self, values, *args, **kwargs)
    monkeypatch.setattr(SimpleImputer, "fit", fit)
    records = []
    for partition in ("train", "validation"):
        for label in (0, 1):
            for index in range(3):
                features = {name: float(label + 1) for name in RIT_FEATURES}
                if partition == "validation":
                    features["pdfsize"] = 1000000.0
                records.append({"cache_mode": "cold", "split": partition, "Label": str(label), "sample_id": f"{partition}{label}{index}",
                    "code": None, "static": {"input": {"size_bytes": 0, "sha256": None}, "features": features,
                        "parser": {"success": True, "structural_complete": index != 2}, "errors": []}})
    run = SimpleNamespace(report=tmp_path / "report", artifacts=tmp_path / "artifacts", state={"metrics": {}})
    run.report.mkdir(); run.artifacts.mkdir()
    study.compare_cic_features(run, records, {"rf": {"n_estimators": 4, "max_depth": 2}, "threshold": 0.5})
    evidence = json.loads((run.report / "feature_comparison.json").read_text())
    assert len(captured) == 2 and all(len(values) == 4 for values in captured)
    assert all(1000000 not in values for values in captured)
    for model in evidence["models"].values():
        assert model["dev_planned"] == 6 and model["dev_available"] == 4 and model["refusals"] == 2
        assert model["malicious_planned"] == model["benign_planned"] == 3
        assert model["malicious_coverage"] == model["benign_coverage"] == 2 / 3
        assert model["threshold"] == 0.5
    assert all(row["code"] is None for row in records)  # Unknown raw AST never rewritten to zeros.


def test_new_feature_equivalence_blocks_comparison_before_fit(tmp_path, monkeypatch):
    from sklearn.impute import SimpleImputer
    from malpdf.static.schema import RIT_FEATURES
    monkeypatch.setattr(SimpleImputer, "fit", lambda *args, **kwargs: pytest.fail("Fit before checking feature leakage"))
    records = [{"cache_mode": "cold", "split": partition, "Label": str(label), "code": None,
        "static": {"input": {}, "features": {name: label + 1 for name in RIT_FEATURES},
            "parser": {"success": True, "structural_complete": True}, "errors": []}}
        for partition in ("train", "validation") for label in (0, 1)]
    run = SimpleNamespace(report=tmp_path / "report", artifacts=tmp_path / "artifacts", state={"metrics": {}})
    run.report.mkdir(); run.artifacts.mkdir()
    study.compare_cic_features(run, records, {"rf": {"n_estimators": 4}, "threshold": 0.5})
    evidence = json.loads((run.report / "feature_comparison.json").read_text())
    assert evidence["status"] == "feature_equivalence_crosses_saved_partitions"
    assert evidence["overlapping_vectors"] == 2 and evidence["metrics"] is None
    assert len(records) == 4 and not run.state["metrics"]


def test_broken_xref_fixture_keeps_strict_failure_and_reports_recovery(tmp_path):
    data = fixture_pdf(None)
    match = re.search(rb"startxref\n(\d+)", data)
    altered = data[:match.start(1)] + str(int(match[1]) + 5).encode() + data[match.end(1):]
    path = tmp_path / "inert_xref.pdf"; path.write_bytes(altered)
    profile = profile_pdf(path, boundary=tmp_path, digest=hashlib.sha256(altered).hexdigest())
    assert profile["static"]["parser"]["success"]
    diagnostic = profile["static"]["parser"]["diagnostics"]
    assert diagnostic["strict"] is False and "xref_offset_recovery" in diagnostic["recovery_notice_codes"]
    assert profile["static"]["reference_parser_repaired"] is True
    strict = profile["code"]["parser_diagnostics"]
    assert strict["strict"] is True and not strict["open_success"]
    assert strict["failures"] == [{"stage": "open", "exception_type": "PdfReadError", "reason": "xref_invalid"}]
    assert profile["status"] == "partial" and "pdf_parser_failure" in profile["reasons"]


def test_unresolved_reference_partial_has_reason_even_when_errors_empty(tmp_path):
    writer = PdfWriter(); writer.add_blank_page(72, 72)
    writer._root_object[NameObject("/Fixture")] = IndirectObject(999, 0, writer)
    output = io.BytesIO(); writer.write(output)
    path = tmp_path / "inert_reference.pdf"; data = output.getvalue(); path.write_bytes(data)
    profile = profile_pdf(path, boundary=tmp_path, digest=hashlib.sha256(data).hexdigest())
    assert profile["status"] == "partial"
    assert "structural_reference_unavailable" in profile["reasons"]
    assert profile["static"]["parser"]["structural_complete"] is False


def test_parser_categories_never_export_exception_content(monkeypatch):
    import logging
    from malpdf.static.parser_diagnostics import ParserDiagnostics
    secret = "fixture-private-content"
    diagnostic = ParserDiagnostics(strict=True)
    before = list(logging.getLogger("pypdf").handlers)
    with diagnostic.capture_open_notices():
        logging.getLogger("pypdf._reader").warning("incorrect startxref pointer: %s", secret)
    diagnostic.failure(ValueError(secret), "open")
    assert secret not in json.dumps(diagnostic.data)
    assert diagnostic.data["failures"][0]["exception_type"] == "ValueError"
    assert diagnostic.data["recovery_notice_codes"] == ["xref_offset_recovery"]
    assert logging.getLogger("pypdf").handlers == before


def test_failed_predict_call_is_measured_but_not_a_prediction(tmp_path):
    from malpdf.static.schema import RIT_FEATURES
    from malpdf.inference.predictor import StaticScanSession
    static = study.static_result({"static": {"input": {}, "features": {name: 1 for name in RIT_FEATURES},
        "parser": {"success": True, "structural_complete": True}, "errors": []}})
    class Model:
        def predict_proba(self, features):
            raise ValueError("fixture inference failure")
    timings = StageTimings()
    session = StaticScanSession(repository_root=tmp_path, inspector=lambda *args, **kwargs: static,
        model_loader=lambda *args: (Model(), {}), timings=timings)
    prediction = session.scan_many(["synthetic"], explain=False)[0].prediction
    assert not prediction["available"] and prediction["predicted_label"] is None
    assert timings.seconds["inference"] is not None and timings.seconds["inference_gate"] is not None


@pytest.mark.parametrize("changed", [False, True])
def test_saved_baseline_pairing_refuses_changed_label_or_partition(tmp_path, monkeypatch, changed):
    identifier = "run_synthetic_baseline"
    old = [{"sample_id": str(label), "pdf_sha256": str(label) * 64, "Label": str(label), "split": "validation",
        "cache_mode": "cold", "status": "partial", "errors": []} for label in (0, 1)]
    new = [{**row, "status": "complete", "reasons": []} for row in old]
    folder = tmp_path / "artifacts/cic_static_profile" / identifier; folder.mkdir(parents=True)
    (folder / "per_file.jsonl").write_text("\n".join(json.dumps(row) for row in old))
    lock = {"baseline_run": identifier, "subset_sha256": "fixture", "configuration": {}, "rows": 2}
    monkeypatch.setattr(study, "baseline_method", lambda *args: lock)
    run = SimpleNamespace(root=tmp_path, report=tmp_path / "report", artifacts=tmp_path / "new_artifacts")
    run.report.mkdir(); run.artifacts.mkdir()
    if changed:
        new[0]["Label"] = "1"
        with pytest.raises(ValueError, match="same PDFs, labels and partitions"):
            study.compare_saved_baseline(run, new, lock)
        assert not (run.report / "baseline_comparison.json").exists()
    else:
        study.compare_saved_baseline(run, new, lock)
        saved = json.loads((run.report / "baseline_comparison.json").read_text())
        assert saved["paired_cold_samples"] == 2 and saved["status_transitions"] == {"partial -> complete": 2}
        assert saved["inference_time_comparable"] is False

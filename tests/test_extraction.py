"""Synthetic byte fixtures and immutable checkpoints; no external PDF access."""

from copy import deepcopy
from dataclasses import replace
import hashlib
import io
import json
from pathlib import Path

import pytest
from pypdf import PdfWriter
from pypdf.generic import DictionaryObject, NameObject, TextStringObject

from malpdf.extraction.contracts import GROUPS, ObservationStatus, validate_bundle
from malpdf.extraction.normalize import normalize_profile
from malpdf.extraction.orchestrator import extract_pdf, write_bundle
from malpdf.extraction.raw import inspect_raw_layout, MAX_MARKERS, MAX_NAMES, MAX_WINDOWS, WINDOW_BYTES
from malpdf.extraction.schemas import schemas
from malpdf.extraction.triggers import plan_triggers
from malpdf.static.code_inspector import CodeInspectionLimits


def benign_pdf():
    writer = PdfWriter()
    writer.add_blank_page(72, 72)
    writer._root_object[NameObject("/OpenAction")] = DictionaryObject({
        NameObject("/S"): NameObject("/JavaScript"), NameObject("/JS"): TextStringObject("var inert = 1;")})
    output = io.BytesIO()
    writer.write(output)
    return output.getvalue()


def raw_profile(data=b"%PDF-1.7\n/JS 1\n%%EOF\n"):
    layout = inspect_raw_layout(data)
    return {"status": "complete", "errors": [], "raw_layout": layout,
            "raw_evidence": {"sha256": layout["sha256"], "size_bytes": len(data), "features": layout["token_counts"]}}


def bundle():
    profile = raw_profile()
    return normalize_profile(profile, profile["raw_layout"]["sha256"], "fast-static")


def test_raw_layout_conserves_bytes_and_redacts_names_with_exact_offsets():
    data = b"prefix%PDF-1.7\n/J#61vaScript /PrivateSecret\n%%EOF\nTAIL"
    result = inspect_raw_layout(data)
    assert result["size_bytes"] == sum(result["byte_histogram"]) == len(data)
    assert result["prefix_bytes"] == 6 and result["suffix_bytes"] == 5
    assert result["escaped_name_candidates"] == 1
    hint = result["escaped_name_hints"][0]
    assert data[hint["start"]:hint["end"]] == b"/J#61vaScript"
    assert hint["normalized_sha256"] == hashlib.sha256(b"/JavaScript").hexdigest()
    assert "PrivateSecret" not in json.dumps(result) and "J#61" not in json.dumps(result)


def test_raw_layout_limits_never_claim_complete_scans():
    result = inspect_raw_layout(b"%PDF-" + b"%%EOF " * (MAX_MARKERS + 1)
        + b"/J#53 " * (MAX_NAMES + 1) + b"x" * (WINDOW_BYTES * MAX_WINDOWS + 1))
    assert len(result["markers"]["eof"]["offsets"]) == MAX_MARKERS
    assert not result["markers"]["eof"]["complete"]
    assert not result["name_scan_complete"] and result["name_candidates_seen"] == MAX_NAMES
    assert len(result["entropy_windows"]) == MAX_WINDOWS
    assert not result["entropy_windows_complete"]
    assert result["last_eof_offset"] is not None


def test_raw_empty_input_does_not_invent_header_or_eof():
    result = inspect_raw_layout(b"")
    assert result["entropy"] == 0 and result["prefix_bytes"] is None and result["suffix_bytes"] is None
    assert result["header_offset"] is None and result["last_eof_offset"] is None


def test_fast_store_reports_lexical_absence_in_its_scope_and_other_modules_not_run():
    result = bundle()
    records = {item["feature_name"]: item for item in result["feature_store"]["records"]}
    assert records["lexical_JS"]["value"] == 1
    assert records["lexical_Launch"]["value"] == 0
    assert records["lexical_Launch"]["observation_status"] == "absent_within_scope"
    coverage = result["coverage_report"]
    assert set(coverage["groups"]) == set(GROUPS)
    assert coverage["groups"]["dynamic_telemetry"]["observation_status"] == "not_run"
    assert coverage["backends"]["pypdf"]["observation_status"] == "not_run"
    assert coverage["whole_document_complete"] is False
    assert not result["safety"]["active_content_executed"]


@pytest.mark.parametrize("failure,status", [("wall_timeout", "timeout"), ("worker_memory_limit", "resource_limit"),
    ("encrypted_pdf", "encrypted"), ("unsupported_filter", "unsupported"), ("flate_decode_failure", "decode_error")])
def test_interrupted_secondary_preserves_primary_values_and_separate_failure(failure, status):
    profile = raw_profile()
    digest = profile["raw_layout"]["sha256"]
    primary = {"input": {"sha256": digest}, "features": {"JS": 7, "images": -1, "pages": None},
               "parser": {"success": True}}
    profile.update(status="worker_error", errors=[failure], static=primary)
    before = deepcopy(profile)
    result = normalize_profile(profile, digest, "deep-static")
    assert profile == before
    assert result["status"] == status
    preserved = next(item for item in result["evidence_store"]["records"] if item["kind"] == "primary_checkpoint")
    assert preserved["details"]["features"] == primary["features"]
    values = {item["feature_name"]: item for item in result["feature_store"]["records"]}
    assert values["canonical_JS"]["value"] == 7
    assert values["canonical_images"]["value"] is None
    assert values["canonical_pages"]["value"] is None
    assert values["canonical_images"]["observation_status"] == "partial"
    assert result["coverage_report"]["backends"]["qpdf"]["observation_status"] == "not_run"


@pytest.mark.parametrize("mutation,reason", [
    (lambda b: b.update(sample_sha256="bad"), "document_identity"),
    (lambda b: b["feature_store"].update(sample_sha256="0" * 64), "store_identity"),
    (lambda b: b["safety"].update(active_content_executed=True), "safety"),
    (lambda b: b["feature_store"]["records"][0].update(evidence_refs=["missing"]), "feature_reference"),
    (lambda b: b["feature_store"]["records"][0].update(value=float("nan")), "feature_value"),
    (lambda b: b["feature_store"]["records"][0].update(observation_status="not_run"), "unavailable_feature"),
    (lambda b: b["feature_store"]["records"][0].update(observation_status="absent_within_scope", value=0, scope_complete=False), "complete_scope"),
    (lambda b: b["evidence_store"]["records"][0].update(revision="unknown"), "locator"),
    (lambda b: b["coverage_report"]["groups"].pop("dynamic_telemetry"), "coverage_groups"),
    (lambda b: b["coverage_report"]["groups"]["raw_layout"].update(feature_count=0), "coverage_count"),
])
def test_contract_refuses_unverified_identity_absence_and_references(mutation, reason):
    result = bundle()
    mutation(result)
    with pytest.raises(ValueError, match=reason):
        validate_bundle(result)


def test_repaired_backend_identity_and_unknown_locator_remain_separate():
    profile = raw_profile()
    digest = profile["raw_layout"]["sha256"]
    profile["analysis_v9"] = {"document_sha256": digest, "observations": [
        {"id": f"{backend}:12:7", "kind": "pdf_object", "backend": backend, "object_number": 12,
         "generation": 7, "offset": "unknown", "status": "observed", "revision": "unknown"}
        for backend in ("pypdf", "MuPDF")], "edges": [], "conflicts": [{"reason_code": "revision_unverified"}]}
    result = normalize_profile(profile, digest, "deep-static")
    nodes = [item for item in result["evidence_store"]["records"] if item["kind"] == "pdf_object"]
    assert len(nodes) == 2 and all(item["generation"] == 7 and item["revision"] is None for item in nodes)
    assert all(item["byte_offset_start"] is None for item in nodes)
    assert {item["backend"]: item["is_synthetic_repaired"] for item in nodes} == {"pypdf": False, "MuPDF": True}
    assert result["evidence_store"]["conflicts"] == profile["analysis_v9"]["conflicts"]


def test_checkpoint_document_mismatch_refuses_cross_sample_evidence():
    profile = raw_profile()
    with pytest.raises(ValueError, match="checkpoint_identity"):
        normalize_profile(profile, "0" * 64, "fast-static")


def test_distributable_schemas_cover_actual_stores_and_all_observation_states():
    result = bundle()
    exported = schemas()
    for filename, key in (("evidence_store.schema.json", "evidence_store"),
                          ("feature_record.schema.json", "feature_store"), ("coverage_report.schema.json", "coverage_report")):
        schema = exported[filename]
        assert schema["$schema"].endswith("2020-12/schema")
        assert set(schema["required"]) == set(result[key])
    states = exported["feature_record.schema.json"]["properties"]["records"]["items"]["properties"]["observation_status"]["enum"]
    assert set(states) == {str(value) for value in ObservationStatus}


def test_export_uses_fresh_ignored_processed_storage(repository):
    result = bundle()
    with (repository / ".gitignore").open("a") as handle:
        handle.write("data/processed/**\n")
    output = write_bundle(result, repository / "data/processed/pdf_extraction", repository_root=repository)
    saved = json.loads((output / "bundle.json").read_text())
    assert saved["evidence_store"] == result["evidence_store"]
    assert saved["feature_store"] == result["feature_store"]
    assert saved["coverage_report"]["provenance"]["generating_commit"]
    assert result["coverage_report"]["provenance"] == {}
    assert len(list(output.glob("*.json"))) == 7
    with pytest.raises(ValueError, match="data/processed"):
        write_bundle(result, repository / "reports/leak", repository_root=repository)


@pytest.fixture
def repository(tmp_path):
    import subprocess

    (tmp_path / ".gitignore").write_text("data/processed/**\n")
    for arguments in (["init", "-q"], ["add", "."],
                      ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "Fixture"]):
        subprocess.run(["git", "-C", str(tmp_path), *arguments], check=True, capture_output=True)
    return tmp_path


@pytest.mark.parametrize("profile", ["fast-static", "deep-static"])
def test_isolated_extraction_of_benign_fixture_preserves_original_bytes(tmp_path, profile):
    data = benign_pdf()
    path = tmp_path / "fixture.pdf"
    path.write_bytes(data)
    result = extract_pdf(path, boundary=tmp_path, profile=profile)
    assert result["sample_sha256"] == hashlib.sha256(data).hexdigest()
    assert path.read_bytes() == data
    assert result["coverage_report"]["worker"]["worker_cleanup_complete"] is True
    assert result["coverage_report"]["provenance"]["execution_mode"] == "vm"
    assert result["coverage_report"]["worker"]["resource_limits"]["wall_seconds"] is None
    nodes = result["evidence_store"]["records"]
    if profile == "deep-static":
        scripts = [node for node in nodes if node["kind"] == "script"]
        assert scripts and scripts[0]["details"]["ast_status"] == "complete"
        assert any(record["feature_name"].endswith(":ast:node_count") for record in result["feature_store"]["records"])
        assert result["trigger_plan"]["events"][0]["event"] == "open_document"
        assert result["trigger_plan"]["events"][0]["execution_status"] == "not_run"
    else:
        assert not any(node["kind"] == "script" for node in nodes)
    assert "var inert" not in json.dumps(result)


def _checkpoint_input_failure(connection, path, boundary, digest, limits, *args):
    import os
    os.setsid()
    raw = raw_profile()
    raw["raw_layout"]["sha256"] = digest
    raw["raw_evidence"]["sha256"] = digest
    connection.send_bytes(json.dumps({"event": "checkpoint", "profile": {**raw, "status": "partial",
        "static": {"input": {"sha256": digest}, "features": {"JS": 1}}, "code": None}}).encode())
    connection.send_bytes(json.dumps({"event": "result", "profile": {"status": "input_error",
        "errors": ["ValueError"], "reasons": ["ValueError"], "static": None, "code": None, "timings": {}}}).encode())
    connection.close()


def test_local_secondary_value_error_preserves_primary_and_raw_checkpoint_and_reaps_worker(tmp_path, monkeypatch):
    import multiprocessing
    from malpdf.static import profile_worker
    context = multiprocessing.get_context("fork")
    monkeypatch.setattr(profile_worker.multiprocessing, "get_context", lambda *args: context)
    monkeypatch.setattr(profile_worker, "_profile_child", _checkpoint_input_failure)
    monkeypatch.setattr(profile_worker, "_worker_count", lambda *args: 1)
    before = {child.pid for child in multiprocessing.active_children()}
    result = profile_worker.profile_pdf(tmp_path / "unused.pdf", boundary=tmp_path, digest="a" * 64,
        analysis_version="v9", extraction_profile="deep-static")
    assert result["static"]["features"]["JS"] == 1
    assert result["raw_layout"]["sha256"] == "a" * 64
    assert result["worker_cleanup_complete"]
    assert {child.pid for child in multiprocessing.active_children()} == before


def test_static_trigger_plan_follows_legal_owner_paths_and_keeps_next_cycles():
    from malpdf.static.evidence_v9 import inspect_evidence_v9
    from malpdf.static.code_inspector import _inspect_code_bytes

    writer = PdfWriter()
    writer.add_blank_page(72, 72)
    first = DictionaryObject({NameObject("/S"): NameObject("/URI")})
    second = DictionaryObject({NameObject("/S"): NameObject("/JavaScript"), NameObject("/JS"): TextStringObject("var inert = 1;")})
    first_ref, second_ref = writer._add_object(first), writer._add_object(second)
    first[NameObject("/Next")] = second_ref
    second[NameObject("/Next")] = first_ref
    writer._root_object[NameObject("/OpenAction")] = first_ref

    writer._root_object[NameObject("/Private")] = DictionaryObject({NameObject("/Type"): NameObject("/Annot"), NameObject("/A"): second_ref})
    output = io.BytesIO()
    writer.write(output)
    data, limits = output.getvalue(), CodeInspectionLimits()
    profile = raw_profile(data)
    digest = profile["raw_layout"]["sha256"]
    static = {"input": {"sha256": digest}, "features": {}, "parser": {}}
    code = _inspect_code_bytes(data, limits)
    profile["analysis_v9"] = inspect_evidence_v9(data, static, code, limits, primary_complete=True)
    result = normalize_profile(profile, digest, "deep-static")
    plan = plan_triggers(result)
    assert len(plan["events"]) == 1
    assert plan["events"][0]["cycle_observed"] and len(plan["events"][0]["action_chain"]) == 2
    assert plan_triggers(result, max_chain=1)["events"][0]["chain_limited"]
    assert plan["dynamic_execution_status"] == "not_run" and not plan["forced_execution"]


def test_extract_cli_returns_output_location_without_dumping_sample_metadata(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv('MALPDF_LAB_ISOLATED', '1')
    from malpdf.cli import main
    from malpdf.extraction import orchestrator
    monkeypatch.setattr(orchestrator, "extract_pdf", lambda *args, **kwargs: bundle())
    monkeypatch.setattr(orchestrator, "write_bundle", lambda *args, **kwargs: tmp_path / "run_fixture")
    assert main(["extract", "synthetic.pdf", "--profile", "fast-static"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output == {"status": "observed", "output_directory": str(tmp_path / "run_fixture")}


def test_input_and_admission_failures_return_no_fabricated_zero_features(tmp_path, monkeypatch):
    from malpdf.extraction import orchestrator

    path = tmp_path / "fixture.pdf"
    path.write_bytes(benign_pdf())
    result = extract_pdf(path, expected_sha256="0" * 64)
    assert result["status"] == "partial" and not result["feature_store"]["records"]
    assert "input_checksum_mismatch" in result["coverage_report"]["limitations"]
    monkeypatch.setattr(orchestrator, "profile_pdf", lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("RAM")))
    result = extract_pdf(path)
    assert not result["feature_store"]["records"]
    assert "worker_admission_failed" in result["coverage_report"]["limitations"]
    result = extract_pdf(tmp_path / "missing.pdf")
    assert result["sample_sha256"] is None and not result["feature_store"]["records"]


def test_byte_cap_symlink_and_hybrid_execution_are_refused(tmp_path):
    path = tmp_path / "fixture.pdf"
    path.write_bytes(benign_pdf())
    link = tmp_path / "link.pdf"
    link.symlink_to(path)
    assert not extract_pdf(link)["feature_store"]["records"]
    assert not extract_pdf(path, limits=replace(CodeInspectionLimits(), max_file_bytes=1))["feature_store"]["records"]
    with pytest.raises(ValueError, match="approved environment"):
        extract_pdf(path, profile="full-hybrid")

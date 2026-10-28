import hashlib
import pytest
from malpdf.extraction.contracts import (
    EVASION_FLAGS,
    ExtractionStatus,
    ObservationStatus,
    validate_bundle,
)
from malpdf.extraction.filters import DecodeBudget, FilterLimits, decode_filters
from malpdf.extraction.normalize import normalize_profile
from malpdf.static.js_ast import inspect_js_syntax


from malpdf.extraction.raw import inspect_raw_layout


def _base_profile():
    layout = inspect_raw_layout(b"%PDF-1.7\n/JS\n%%EOF\n")
    digest = layout["sha256"]
    return digest, {
        "status": "complete",
        "sample_sha256": digest,
        "static": {
            "input": {"sha256": digest, "size_bytes": layout["size_bytes"]},
            "features": {"pdfsize": layout["size_bytes"], "obj": 2, "endobj": 2},
            "parser": {"status": "complete"},
            "errors": [],
            "warnings": [],
        },
        "raw_evidence": {"sha256": digest, "size_bytes": layout["size_bytes"]},
        "raw_layout": layout,
        "analysis_v9": {"document_sha256": digest, "observations": [], "capability_checks": []},
        "worker_result_received": True,
        "worker_seconds": 1.2,
        "worker_exit_code": 0,
        "worker_cleanup_complete": True,
        "peak_rss_bytes": 1024 * 1024,
        "rss_quality": "verified",
        "resource_limits": {},
        "last_stage": "complete",
        "timings": {},
    }


def test_clean_profile_normalized_as_complete():
    digest, profile = _base_profile()
    bundle = normalize_profile(profile, digest, "deep-static")

    assert bundle["extraction_status"] == ExtractionStatus.COMPLETE.value
    assert bundle["status"] == ObservationStatus.OBSERVED.value
    assert set(bundle["evasion_or_quota_flags"].keys()) == EVASION_FLAGS
    assert not any(bundle["evasion_or_quota_flags"].values())
    assert bundle["coverage_report"]["extraction_status"] == ExtractionStatus.COMPLETE.value
    validate_bundle(bundle)


def test_bounded_complete_on_stream_expansion_limit():
    digest, profile = _base_profile()
    profile["errors"] = ["decoded_byte_or_expansion_limit"]
    profile["stream_analysis"] = {
        "document_sha256": digest,
        "status": "resource_limit",
        "complete": False,
        "reason_codes": ["decoded_byte_or_expansion_limit"],
        "flag_decompression_ratio_exceeded": True,
        "is_truncated_stream": True,
    }

    bundle = normalize_profile(profile, digest, "deep-static")

    assert bundle["extraction_status"] == ExtractionStatus.BOUNDED_COMPLETE.value
    assert bundle["status"] == ObservationStatus.BOUNDED_COMPLETE.value
    assert bundle["evasion_or_quota_flags"]["flag_decompression_ratio_exceeded"] is True
    assert bundle["evasion_or_quota_flags"]["is_truncated_stream"] is True
    features = {f["feature_name"]: f["value"] for f in bundle["feature_store"]["records"]}
    assert features["flag_decompression_ratio_exceeded"] == 1
    assert features["is_truncated_stream"] == 1
    validate_bundle(bundle)


def test_bounded_complete_on_arlington_metadata_flood():
    digest, profile = _base_profile()
    profile["arlington_analysis"] = {
        "document_sha256": digest,
        "status": "partial",
        "complete": False,
        "reason_codes": ["arlington_metadata_limit"],
        "flag_spec_violation_flood": True,
        "total_violations": 1500,
    }

    bundle = normalize_profile(profile, digest, "deep-static")

    assert bundle["extraction_status"] == ExtractionStatus.BOUNDED_COMPLETE.value
    assert bundle["status"] == ObservationStatus.BOUNDED_COMPLETE.value
    assert bundle["evasion_or_quota_flags"]["flag_spec_violation_flood"] is True
    features = {f["feature_name"]: f["value"] for f in bundle["feature_store"]["records"]}
    assert features["flag_spec_violation_flood"] == 1
    assert features["arlington_total_violations"] == 1500
    validate_bundle(bundle)


def test_bounded_complete_on_ast_complexity_pruning():
    digest, profile = _base_profile()
    profile["code"] = {"flag_ast_complexity_truncated": True}

    bundle = normalize_profile(profile, digest, "deep-static")

    assert bundle["extraction_status"] == ExtractionStatus.BOUNDED_COMPLETE.value
    assert bundle["status"] == ObservationStatus.BOUNDED_COMPLETE.value
    assert bundle["evasion_or_quota_flags"]["flag_ast_complexity_truncated"] is True
    features = {f["feature_name"]: f["value"] for f in bundle["feature_store"]["records"]}
    assert features["flag_ast_complexity_truncated"] == 1
    validate_bundle(bundle)


def test_bounded_complete_on_excessive_object_graph():
    digest, profile = _base_profile()
    profile["errors"] = ["pdf_structure_limit"]

    bundle = normalize_profile(profile, digest, "deep-static")

    assert bundle["extraction_status"] == ExtractionStatus.BOUNDED_COMPLETE.value
    assert bundle["status"] == ObservationStatus.BOUNDED_COMPLETE.value
    assert bundle["evasion_or_quota_flags"]["flag_excessive_object_graph"] is True
    features = {f["feature_name"]: f["value"] for f in bundle["feature_store"]["records"]}
    assert features["flag_excessive_object_graph"] == 1
    validate_bundle(bundle)


def test_timeout_partial_status_when_primary_available():
    digest, profile = _base_profile()
    profile["status"] = "timeout"
    profile["errors"] = ["worker_timeout"]

    bundle = normalize_profile(profile, digest, "deep-static")

    assert bundle["extraction_status"] == ExtractionStatus.TIMEOUT_PARTIAL.value
    assert bundle["status"] == ObservationStatus.TIMEOUT.value
    validate_bundle(bundle)


def test_failed_status_when_primary_missing():
    digest = hashlib.sha256(b"dummy").hexdigest()
    profile = {
        "status": "partial",
        "errors": ["not_pdf_or_byte_limit"],
        "worker_result_received": False,
        "worker_exit_code": 1,
    }

    bundle = normalize_profile(profile, digest, "deep-static")

    assert bundle["extraction_status"] == ExtractionStatus.FAILED.value
    validate_bundle(bundle)


def test_js_ast_bounded_pruning_and_statistics():
    deep_code = "if (true) { " * 70 + "var target = 'obfuscated_string_payload';" + " }" * 70
    summary = inspect_js_syntax(deep_code, max_nodes=5000, max_depth=64, bounded=True)

    assert summary["flag_ast_complexity_truncated"] is True
    assert summary["literal_strings_count"] >= 0
    assert "mean_string_length" in summary
    assert "string_literal_ratio" in summary


def test_stream_filter_expansion_ratio_bounding():
    import zlib
    payload = b"A" * (200 * 1024)
    compressed = zlib.compress(payload)

    limits = FilterLimits(max_expansion_ratio=5)
    result = decode_filters(compressed, ["/FlateDecode"], limits=limits)

    assert result.metadata["flag_decompression_ratio_exceeded"] is True
    assert result.metadata["is_truncated_stream"] is True
    assert "compressed_entropy" in result.metadata
    assert result.metadata["compressed_entropy"] >= 0.0


def test_stream_head_tail_sampling_and_keyword_scan():
    import zlib
    head = b"var benign_head = 1;\n" + (b" " * (20 * 1024))
    middle = b" " * (35 * 1024)
    tail = b"\nvar payload = unescape('%41'); eval(payload); exportDataObject();\n"
    trailing = b" " * (20 * 1024)
    payload = head + middle + tail + trailing
    compressed = zlib.compress(payload)

    limits = FilterLimits(max_stage_bytes=68 * 1024, max_expansion_ratio=1000)
    result = decode_filters(compressed, ["/FlateDecode"], limits=limits)

    assert result.metadata["is_truncated_stream"] is True
    assert result.metadata["flag_decompression_ratio_exceeded"] is True
    assert b"/* ...MALPDF_STREAM_TRUNCATED... */" in result.partial_data
    assert len(result.partial_data) <= 64 * 1024 + 128
    assert "eval" in result.metadata["suspicious_keywords_found"]
    assert "unescape" in result.metadata["suspicious_keywords_found"]
    assert "exportDataObject" in result.metadata["suspicious_keywords_found"]


def test_continuous_ratio_features_exported():
    digest, profile = _base_profile()
    profile["arlington_analysis"] = {
        "document_sha256": digest,
        "status": "observed",
        "complete": True,
        "reason_codes": [],
        "total_violations": 50,
        "objects_checked": 100,
    }
    profile["stream_analysis"] = {
        "document_sha256": digest,
        "status": "observed",
        "complete": True,
        "reason_codes": [],
        "discovered_streams": 10,
        "truncated_streams": 3,
    }
    profile["analysis_v9"] = {
        "document_sha256": digest,
        "observations": [],
        "capability_checks": [],
        "budget_usage": {"objects_visited": 4000},
    }

    bundle = normalize_profile(profile, digest, "deep-static")
    features = {f["feature_name"]: f["value"] for f in bundle["feature_store"]["records"]}

    assert features["arlington_violation_rate"] == 0.5
    assert features["stream_truncation_ratio"] == 0.3
    assert features["object_graph_visited_ratio"] == 0.4
    validate_bundle(bundle)


def test_priority_first_object_traversal_order():
    import io
    from pypdf import PdfWriter
    from pypdf.generic import DictionaryObject, NameObject, TextStringObject, ArrayObject
    from malpdf.static.code_inspector import CodeInspectionLimits, _inspect_code_bytes
    from malpdf.static.evidence_v9 import inspect_evidence_v9

    writer = PdfWriter()
    writer.add_blank_page(72, 72)
    js_dict = DictionaryObject({
        NameObject("/S"): NameObject("/JavaScript"),
        NameObject("/JS"): TextStringObject("app.alert('priority_js');")
    })
    names_array = ArrayObject([TextStringObject("EmbeddedJS"), js_dict])
    js_tree = DictionaryObject({NameObject("/Names"): names_array})
    names_dict = DictionaryObject({NameObject("/JavaScript"): js_tree})
    writer._root_object[NameObject("/Names")] = names_dict

    output = io.BytesIO()
    writer.write(output)
    data = output.getvalue()

    limits = CodeInspectionLimits()
    code = _inspect_code_bytes(data, limits)
    static = {
        "input": {"sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)},
        "features": {},
        "parser": {"success": True, "structural_complete": True},
        "errors": []
    }
    result = inspect_evidence_v9(data, static, code, limits, primary_complete=True)

    assert result["flag_excessive_object_graph"] is False
    actions = [e for e in result["edges"] if e["kind"] == "catalog_action"]
    assert len(actions) >= 1
    assert any("/Names/JavaScript" in (e.get("route") or "") for e in actions)


def test_telemetry_bounded_complete_summary_validation(tmp_path):
    import sys
    from pathlib import Path
    lab_dir = str(Path(__file__).resolve().parent.parent / "scripts" / "lab")
    if lab_dir not in sys.path:
        sys.path.insert(0, lab_dir)
    import lab_jobs as jobs
    import lab_side as side
    summary_valid = jobs.summary_valid
    merge_summary = jobs.merge_summary

    summary = {
        "completed": 6,
        "observed": 5,
        "bounded_complete": 2,
        "partial": 1,
        "failed": 0,
        "primary_available": 6,
        "timeout": 0,
        "elapsed_ms": 120,
        "peak_rss_bytes": 1024 * 1024,
        "status_counts": {
            "observed": 3,
            "bounded_complete": 2,
            "partial": 1
        }
    }
    assert summary_valid(summary) is True

    invalid_summary = dict(summary, bounded_complete=6)
    assert summary_valid(invalid_summary) is False

    job = {"limits": {"samples": 4}}
    shard0 = {
        "shard": 0,
        "shards": 2,
        "planned": 4,
        "completed": 2,
        "observed": 2,
        "bounded_complete": 1,
        "partial": 0,
        "failed": 0,
        "primary_available": 2,
        "timeout": 0,
        "elapsed_ms": 100,
        "peak_rss_bytes": 1024 * 1024,
        "status_counts": {"bounded_complete": 1, "observed": 1}
    }
    shard1 = {
        "shard": 1,
        "shards": 2,
        "planned": 4,
        "completed": 2,
        "observed": 1,
        "bounded_complete": 1,
        "partial": 1,
        "failed": 0,
        "primary_available": 2,
        "timeout": 0,
        "elapsed_ms": 150,
        "peak_rss_bytes": 2048 * 1024,
        "status_counts": {"bounded_complete": 1, "partial": 1}
    }
    import json
    (tmp_path / "pdf_summary.0.json").write_text(json.dumps(shard0))
    (tmp_path / "pdf_summary.1.json").write_text(json.dumps(shard1))

    merged = merge_summary(job, tmp_path, 2)
    assert merged["completed"] == 4
    assert merged["observed"] == 3
    assert merged["bounded_complete"] == 2
    assert merged["partial"] == 1
    assert merged["failed"] == 0


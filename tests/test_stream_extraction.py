"""Static stream integration with inert generated PDFs and bounded workers."""

from copy import deepcopy
from dataclasses import replace
import base64
import hashlib
import io
import json
import os

import pytest
from pypdf import PdfWriter
from pypdf.generic import (ArrayObject, DecodedStreamObject, DictionaryObject,
                          EncodedStreamObject, IndirectObject, NameObject, NumberObject, TextStringObject)
import zlib

from malpdf.extraction.contracts import validate_bundle
from malpdf.extraction.normalize import normalize_profile
from malpdf.extraction.orchestrator import extract_pdf
from malpdf.extraction.streams import StreamCollector
from malpdf.static.code_inspector import CodeInspectionLimits
from malpdf.static.profile_worker import profile_pdf


def stream(raw, filters=(), parameters=None):
    value = EncodedStreamObject() if filters else DecodedStreamObject()
    value._data = raw
    if filters:
        names = [NameObject(name) for name in filters]
        value[NameObject("/Filter")] = names[0] if len(names) == 1 else ArrayObject(names)
    if parameters is not None:
        value[NameObject("/DecodeParms")] = parameters
    return value


def fixture_pdf(values):
    pdf = PdfWriter()
    pdf.add_blank_page(72, 72)
    for index, value in enumerate(values):
        pdf._root_object[NameObject(f"/FixtureStream{index}")] = pdf._add_object(value)
    pdf._root_object[NameObject("/OpenAction")] = DictionaryObject({NameObject("/S"): NameObject("/JavaScript"),
        NameObject("/JS"): TextStringObject("var harmlessFixture = 1;")})
    output = io.BytesIO()
    pdf.write(output)
    return output.getvalue()


def test_isolated_filter_chain_persists_verified_intermediates_and_preserves_primary(tmp_path):
    payload = b"SYNTHETIC benign content for a private stream"
    compressed = zlib.compress(payload)
    raw = base64.a85encode(compressed, adobe=True)
    data = fixture_pdf([stream(raw, ["/ASCII85Decode", "/FlateDecode"])])
    path = tmp_path / "fixture.pdf"
    path.write_bytes(data)
    limits = CodeInspectionLimits(wall_seconds=20, cpu_seconds=12)
    baseline = profile_pdf(path, boundary=tmp_path, digest=hashlib.sha256(data).hexdigest(),
                           analysis_version="v9", limits=limits)
    output_dir = tmp_path / "stream_blobs"
    result = extract_pdf(path, boundary=tmp_path, limits=limits, raw_artifact_dir=output_dir)
    validate_bundle(result)
    primary = next(record for record in result["evidence_store"]["records"] if record["kind"] == "primary_checkpoint")
    assert primary["details"]["features"] == baseline["static"]["features"]
    assert primary["details"]["source_profile"]["code"] == baseline["code"]
    assert primary["details"]["source_profile"]["analysis_v8"] == baseline["analysis_v8"]
    decode = next(record for record in result["evidence_store"]["records"] if record["kind"] == "stream_decode")
    assert decode["filter_chain"] == ["/ASCII85Decode", "/FlateDecode"]
    assert decode["details"]["decode"]["decoded_bytes"] == len(payload)
    assert all(step["retention"]["parent_verification_status"] == "verified" for step in decode["details"]["decode"]["steps"])
    for value in (raw, compressed, payload):
        blob = output_dir / (hashlib.sha256(value).hexdigest() + ".bin")
        assert blob.read_bytes() == value and not blob.stat().st_mode & 0o111
    assert path.read_bytes() == data
    assert payload.decode() not in json.dumps(result) and "harmlessFixture" not in json.dumps(result)
    assert result["coverage_report"]["worker"]["worker_cleanup_complete"] is True
    assert result["coverage_report"]["worker"]["timings"]["stream_decode"] > 0


def test_empty_unsupported_encrypted_and_malformed_streams_remain_distinct(tmp_path):
    raw = zlib.compress(b"inert recovered prefix")[:-2]
    values = [stream(b""), stream(b"inert non-image", ["/JBIG2Decode"]),
              stream(b"inert non-encrypted fixture", ["/Crypt"]), stream(raw, ["/FlateDecode"])]
    data = fixture_pdf(values)
    path = tmp_path / "fixture.pdf"
    path.write_bytes(data)
    result = extract_pdf(path, boundary=tmp_path)
    decodes = [record for record in result["evidence_store"]["records"] if record["kind"] == "stream_decode"]
    assert {record["observation_status"] for record in decodes} == {"observed", "unsupported", "encrypted", "decode_error"}
    empty = next(record for record in decodes if record["filter_chain"] == [])
    assert empty["details"]["decode"]["decoded_bytes"] == 0
    assert all(record["details"]["decode"]["decoded_bytes"] is None for record in decodes if record is not empty)
    damaged = next(record for record in decodes if record["observation_status"] == "decode_error")
    step = damaged["details"]["decode"]["steps"][0]
    assert step["output_bytes"] == len(b"inert recovered prefix")
    assert step["retention"]["parent_verification_status"] == "verified_not_persisted"


    primary = next(record for record in result["evidence_store"]["records"] if record["kind"] == "primary_checkpoint")
    assert primary["details"]["features"]["JS"] == 1
    assert result["status"] != "observed"


def test_escaped_filter_name_is_resolved_without_modifying_source_bytes(tmp_path):
    raw = zlib.compress(b"inert name-obfuscation fixture")
    bodies = [b"<< /Type /Catalog /Pages 2 0 R /Private 3 0 R >>",
        b"<< /Type /Pages /Kids [4 0 R] /Count 1 >>",
        b"<< /Length " + str(len(raw)).encode() + b" /Filter /Fl#61teDecode >>\nstream\n" + raw + b"\nendstream",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 72 72] /Resources <<>> >>"]
    data, offsets = b"%PDF-1.7\n", [0]
    for index, body in enumerate(bodies, 1):
        offsets.append(len(data))
        data += str(index).encode() + b" 0 obj\n" + body + b"\nendobj\n"
    xref = len(data)
    data += b"xref\n0 5\n0000000000 65535 f \n" + b"".join(f"{offset:010d} 00000 n \n".encode() for offset in offsets[1:])
    data += b"trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n" + str(xref).encode() + b"\n%%EOF\n"
    path = tmp_path / "escaped_filter.pdf"
    path.write_bytes(data)
    result = extract_pdf(path, boundary=tmp_path)
    stream_record = next(record for record in result["evidence_store"]["records"] if record["kind"] == "stream_decode")
    assert stream_record["filter_chain"] == ["/FlateDecode"]
    assert stream_record["observation_status"] == "observed"
    assert stream_record["object_number"] == 3 and stream_record["generation"] == 0
    assert stream_record["byte_offset_start"] == offsets[3]
    layout = next(record for record in result["evidence_store"]["records"] if record["kind"] == "raw_layout")
    assert layout["details"]["escaped_name_candidates"] == 1
    assert path.read_bytes() == data


def observe(collector, value, number):
    collector.observe(value, backend="pypdf", source_id=f"source:{number}", object_number=number, generation=7, offset="unknown")


def test_shared_remaining_budget_is_used_after_v9_and_not_reset_per_stream():
    collector = StreamCollector("a" * 64, CodeInspectionLimits())
    observe(collector, stream(zlib.compress(b"ABCDEF"), ["/FlateDecode"]), 1)
    observe(collector, stream(zlib.compress(b"GHIJKL"), ["/FlateDecode"]), 2)
    checkpoints = []
    collector.checkpoint = lambda state: checkpoints.append(deepcopy(state))
    result = collector.finish(8)
    assert result["decoded_bytes_available"] == result["decoded_bytes_used"] == 8
    assert result["decoded_bytes_remaining"] == 0
    assert result["records"][0]["decode"]["decoded_bytes"] == 6
    assert result["records"][1]["status"] == "resource_limit"
    assert result["records"][1]["decode"]["steps"][0]["output_bytes"] == 2
    assert any(len(checkpoint["records"]) == 1 for checkpoint in checkpoints)


def test_parameter_reference_budget_is_shared_across_streams():
    class Reader:
        calls = 0
        def get_object(self, reference):
            self.calls += 1
            return NameObject("/ASCIIHexDecode") if reference.idnum == 1 else DictionaryObject()
    reader = Reader()
    collector = StreamCollector("a" * 64, CodeInspectionLimits(max_objects=2))
    for index in (1, 2):
        value = stream(b"41>")
        value[NameObject("/Filter")] = IndirectObject(1, 0, reader)
        value[NameObject("/DecodeParms")] = IndirectObject(2, 0, reader)
        observe(collector, value, index)
    result = collector.finish(100)
    assert reader.calls == result["parameter_reference_reads"] == 2
    assert result["records"][0]["status"] == "observed"
    assert result["records"][1]["reason_codes"] == ["stream_parameter_reference_limit"]


def test_in_flight_filter_checkpoints_export_completed_layers_after_interruption():
    from malpdf.static.code_inspector import _inspect_code_bytes
    from malpdf.static.evidence_v9 import inspect_evidence_v9
    raw = zlib.compress(b"inert checkpoint fixture").hex().encode() + b">"
    data, limits = fixture_pdf([stream(raw, ["/ASCIIHexDecode", "/FlateDecode"])]), CodeInspectionLimits()
    digest = hashlib.sha256(data).hexdigest()
    checkpoints = []
    collector = StreamCollector(digest, limits, checkpoint=lambda value: checkpoints.append(deepcopy(value)))
    static = {"input": {"sha256": digest}, "features": {}, "parser": {}}
    code = _inspect_code_bytes(data, limits)
    analysis = inspect_evidence_v9(data, static, code, limits, primary_complete=True, stream_sink=collector.observe)
    collector.finish(analysis["budget_usage"]["decoded_bytes_remaining"])
    partial = next(value for value in checkpoints if len(((value.get("active_stream") or {}).get("decode") or {}).get("steps", [])) == 1)
    partial["worker_failure_codes"] = ["wall_timeout"]
    profile = {"status": "timeout", "errors": ["wall_timeout"], "static": static,
               "code": code, "analysis_v9": analysis, "stream_analysis": partial}
    result = normalize_profile(profile, digest, "deep-static")
    assert result["status"] == "timeout"
    layers = [item for item in result["evidence_store"]["records"] if item["kind"] == "stream_filter_stage"]
    assert len(layers) == 1 and layers[0]["observation_status"] == "observed"
    decoded = next(item for item in result["evidence_store"]["records"] if item["kind"] == "stream_decode")
    assert decoded["observation_status"] == "partial" and decoded["details"]["decode"]["decoded_bytes"] is None


def test_stream_cap_preserves_observations_and_records_incomplete_enumeration(monkeypatch):
    from malpdf.extraction import streams
    monkeypatch.setattr(streams, "MAX_STREAMS", 1)
    collector = StreamCollector("a" * 64, CodeInspectionLimits())
    observe(collector, stream(b"first"), 1)
    observe(collector, stream(b"second"), 2)
    result = collector.finish(100)
    assert result["discovered_streams"] == 2 and result["retained_sources"] == 1
    assert len(result["records"]) == 1 and result["source_limit_reached"]
    assert not result["complete"] and "stream_source_limit" in result["reason_codes"]


def test_metadata_cap_retains_prior_stream_entries_with_explicit_unavailable_remainder(monkeypatch):
    from malpdf.extraction import streams
    monkeypatch.setattr(streams, "MAX_METADATA_BYTES", 6500)
    collector = StreamCollector("a" * 64, CodeInspectionLimits())
    observe(collector, stream(b"first"), 1)
    observe(collector, stream(b"second", ["/" + "X" * 250] * 8), 2)
    result = collector.finish(100)
    assert len(result["records"]) == 1 and result["records"][0]["status"] == "observed"
    assert "stream_metadata_limit" in result["reason_codes"] and not result["complete"]
    assert len(json.dumps(result, separators=(",", ":")).encode()) <= 6500


def test_invalid_parameter_sibling_does_not_erase_valid_stream_evidence():
    collector = StreamCollector("a" * 64, CodeInspectionLimits())
    invalid = stream(b"00>", ["/ASCIIHexDecode"])
    invalid[NameObject("/DecodeParms")] = NumberObject(3)
    observe(collector, invalid, 1)
    observe(collector, stream(b"4142>", ["/ASCIIHexDecode"]), 2)
    result = collector.finish(100)
    assert result["records"][0]["status"] == "decode_error"
    assert result["records"][1]["status"] == "observed"
    assert result["records"][1]["decode"]["decoded_sha256"] == hashlib.sha256(b"AB").hexdigest()


def test_parameter_reference_cycle_stops_without_an_unbounded_parser_retry():
    class Reader:
        def get_object(self, reference):
            return IndirectObject(10, 0, self)
    value = stream(b"inert")
    value[NameObject("/Filter")] = IndirectObject(10, 0, Reader())
    collector = StreamCollector("a" * 64, CodeInspectionLimits())
    observe(collector, value, 1)
    result = collector.finish(100)
    assert result["records"][0]["status"] == "resource_limit"
    assert result["records"][0]["reason_codes"] == ["stream_parameter_reference_limit"]


@pytest.mark.parametrize("failure", ["backend_closed", "missing_reference"])
def test_unavailable_filter_reference_is_partial_with_no_decode_error_claim(failure):
    class Reader:
        def get_object(self, reference):
            if failure == "backend_closed":
                raise ValueError("private synthetic backend detail")
            return None
    value = stream(b"inert undecoded bytes")
    value[NameObject("/Filter")] = IndirectObject(10, 0, Reader())
    collector = StreamCollector("a" * 64, CodeInspectionLimits())
    observe(collector, stream(b"4142>", ["/ASCIIHexDecode"]), 1)
    observe(collector, value, 2)
    result = collector.finish(100)
    assert result["records"][0]["status"] == "observed"
    assert result["records"][1]["status"] == "partial"
    assert result["records"][1]["decode"] is None
    assert result["records"][1]["reason_codes"] == ["stream_parameter_reference_unavailable"]
    assert result["decoded_bytes_used"] == 2
    assert "private synthetic" not in json.dumps(result)


@pytest.mark.parametrize("failure,status", [("recovery_object_limit", "resource_limit"), ("recovery_generation_unsupported", "unsupported")])
def test_backend_reference_limits_and_unsupported_generations_keep_distinct_statuses(failure, status):
    from malpdf.static.js_ast import CodeInspectionError
    class Reader:
        def get_object(self, reference):
            raise CodeInspectionError(failure)
    value = stream(b"inert")
    value[NameObject("/Filter")] = IndirectObject(10, 0, Reader())
    collector = StreamCollector("a" * 64, CodeInspectionLimits())
    observe(collector, value, 1)
    result = collector.finish(100)
    assert result["records"][0]["status"] == status
    assert result["decoded_bytes_used"] == 0


@pytest.mark.parametrize("field,value", [("backend", "MuPDF"), ("generation", 99), ("raw_sha256", "0" * 64)])
def test_stream_projection_refuses_cross_backend_generation_or_byte_identity(field, value):
    from malpdf.static.code_inspector import _inspect_code_bytes
    from malpdf.static.evidence_v9 import inspect_evidence_v9
    data, limits = fixture_pdf([stream(b"4142>", ["/ASCIIHexDecode"])]), CodeInspectionLimits()
    digest = hashlib.sha256(data).hexdigest()
    collector = StreamCollector(digest, limits)
    static = {"input": {"sha256": digest}, "features": {}, "parser": {}}
    code = _inspect_code_bytes(data, limits)
    analysis = inspect_evidence_v9(data, static, code, limits, primary_complete=True, stream_sink=collector.observe)
    streams = collector.finish(analysis["budget_usage"]["decoded_bytes_remaining"])
    profile = {"status": "complete", "static": static, "code": code, "analysis_v9": analysis, "stream_analysis": streams}
    normalize_profile(profile, digest, "deep-static")
    entry = streams["records"][0]
    if field == "raw_sha256":
        entry["decode"][field] = value
    else:
        entry[field] = value
    with pytest.raises(ValueError, match="stream_source_identity_mismatch"):
        normalize_profile(profile, digest, "deep-static")


def _checkpoint_then_stall(connection, path, boundary, digest, limits, *args):
    import time
    os.setsid()
    connection.send_bytes(json.dumps({"event": "checkpoint", "profile": {"status": "complete", "errors": [],
        "static": {"input": {"sha256": digest}, "features": {"JS": 1}}, "code": None,
        "resource_limits": {"address_space_bytes": [limits.memory_bytes] * 2},
        "stream_analysis": {"schema_version": "pdf-stream-analysis-v1", "document_sha256": digest,
            "status": "partial", "complete": False, "records": [{"id": "completed_stream_evidence"}], "reason_codes": []}}}).encode())
    time.sleep(30)


def _completed_filter_then_stall(connection, path, boundary, digest, limits, *args):
    import time
    from malpdf.extraction import filters
    os.setsid()
    base = {"status": "complete", "errors": [], "static": {"input": {"sha256": digest}, "features": {"JS": 1}}, "code": None}
    connection.send_bytes(json.dumps({"event": "checkpoint", "profile": base}).encode())
    def checkpoint(value):
        connection.send_bytes(json.dumps({"event": "checkpoint", "profile": {"stream_analysis": value}}).encode())
    collector = StreamCollector(digest, limits, checkpoint=checkpoint)
    raw = zlib.compress(b"inert").hex().encode() + b">"
    observe(collector, stream(raw, ["/ASCIIHexDecode", "/FlateDecode"]), 1)
    filters._flate = lambda data, cap: time.sleep(30)
    collector.finish(1000)


def test_timeout_preserves_finished_stream_checkpoints_and_reaps_child(tmp_path, monkeypatch):
    import multiprocessing
    from malpdf.static import profile_worker
    context = multiprocessing.get_context("fork")
    monkeypatch.setattr(profile_worker.multiprocessing, "get_context", lambda *args: context)
    monkeypatch.setattr(profile_worker, "_profile_child", _checkpoint_then_stall)
    monkeypatch.setattr(profile_worker, "_worker_count", lambda *args: 1)
    result = profile_worker.profile_pdf(tmp_path / "unused.pdf", boundary=tmp_path, digest="a" * 64,
        analysis_version="v9", extraction_profile="deep-static", limits=CodeInspectionLimits(wall_seconds=1, cpu_seconds=1))
    assert result["status"] == "timeout" and result["worker_cleanup_complete"]
    assert result["static"]["features"] == {"JS": 1}
    assert result["stream_analysis"]["records"] == [{"id": "completed_stream_evidence"}]
    assert result["stream_analysis"]["complete"] is False
    assert result["resource_limits"]["address_space_bytes"][0] == 1024**3
    assert result["rss_quality"] == "sampled_lower_bound"


def test_worker_deadline_keeps_completed_filter_inside_an_unfinished_stream(tmp_path, monkeypatch):
    import multiprocessing
    from malpdf.static import profile_worker
    context = multiprocessing.get_context("fork")
    monkeypatch.setattr(profile_worker.multiprocessing, "get_context", lambda *args: context)
    monkeypatch.setattr(profile_worker, "_profile_child", _completed_filter_then_stall)
    monkeypatch.setattr(profile_worker, "_worker_count", lambda *args: 1)
    result = profile_worker.profile_pdf(tmp_path / "unused.pdf", boundary=tmp_path, digest="a" * 64,
        analysis_version="v9", extraction_profile="deep-static", limits=CodeInspectionLimits(wall_seconds=1, cpu_seconds=1))
    assert result["status"] == "timeout" and result["worker_cleanup_complete"]
    assert result["static"]["features"]["JS"] == 1
    active = result["stream_analysis"]["active_stream"]
    assert active["status"] == "partial" and not active["decode"]["complete"]
    assert len(active["decode"]["steps"]) == 1
    assert active["decode"]["steps"][0]["complete"]
    assert active["decode"]["steps"][0]["output_sha256"] == hashlib.sha256(zlib.compress(b"inert")).hexdigest()

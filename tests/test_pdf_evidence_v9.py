"""Inert generated PDF graphs and synthetic failures; no external PDF corpus."""

from copy import deepcopy
from dataclasses import replace
import hashlib
import io
import json
import zlib

import pytest
from pypdf import PdfReader, PdfWriter
from pypdf.generic import (ArrayObject, DecodedStreamObject, DictionaryObject,
                          EncodedStreamObject, IndirectObject, NameObject, TextStringObject)

from malpdf.static.code_inspector import CodeInspectionLimits, _inspect_code_bytes
from malpdf.static.evidence_v9 import (EVIDENCE_SCHEMA, inspect_evidence_v9,
                                     merge_evidence_delta, _payload_magic)


def dictionary(**values):
    return DictionaryObject({NameObject("/" + key): value for key, value in values.items()})


def js_action(script="var inert = 1;"):
    return dictionary(S=NameObject("/JavaScript"), JS=TextStringObject(script))


def serialize(writer):
    output = io.BytesIO()
    writer.write(output)
    return output.getvalue()


def writer():
    result = PdfWriter()
    result.add_blank_page(72, 72)
    return result


def inspect(data, *, limits=None, complete=True, **kwargs):
    limits = limits or CodeInspectionLimits()
    code = _inspect_code_bytes(data, limits)
    static = {"input": {"sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)},
              "features": {}, "parser": {"success": complete, "structural_complete": complete}, "errors": []}
    return inspect_evidence_v9(data, static, code, limits, primary_complete=complete, **kwargs)


def test_direct_actions_have_distinct_locators_and_link_exact_scripts():
    pdf = writer()
    pdf._root_object[NameObject("/OpenAction")] = js_action("var first = 1;")
    pdf.pages[0][NameObject("/AA")] = dictionary(O=js_action("var second = 2;"))
    data = serialize(pdf)
    result = inspect(data)
    scripts = [item for item in result["observations"] if item["kind"] == "script"]
    assert len(scripts) == 2 and len({item["id"] for item in scripts}) == 2
    assert all(item["ast_status"] == "complete" and item["decoded_validated"] for item in scripts)
    assert len(result["witnesses"]) == 2
    assert "var first" not in json.dumps(result) and "var second" not in json.dumps(result)
    assert result["complete"] and result["original_bytes_changed"] is False


def test_shared_indirect_script_keeps_all_incoming_edges_and_one_ast(monkeypatch):
    from malpdf.static import evidence_v9
    pdf = writer()
    script = pdf._add_object(TextStringObject("var shared = 1;"))
    first, second = js_action(), js_action()
    first[NameObject("/JS")] = second[NameObject("/JS")] = script
    pdf._root_object[NameObject("/OpenAction")] = first
    pdf.pages[0][NameObject("/AA")] = dictionary(O=second)
    calls, original = [], evidence_v9.inspect_js_syntax
    def counted(*args, **kwargs):
        calls.append(True)
        return original(*args, **kwargs)
    monkeypatch.setattr(evidence_v9, "inspect_js_syntax", counted)
    result = inspect(serialize(pdf))
    assert len(calls) == 1
    edges = [item for item in result["edges"] if item["kind"] == "action_JS"]
    assert len(edges) == 2 and edges[0]["target"] == edges[1]["target"]
    assert len([item for item in result["observations"] if item["kind"] == "script"]) == 1


def test_next_array_and_cycles_preserve_index_and_stop():
    pdf = writer()
    first = dictionary(S=NameObject("/URI"), URI=TextStringObject("https://inert.invalid"))
    second, third = js_action("var nextOne = 1;"), js_action("var nextTwo = 2;")
    first_ref, second_ref, third_ref = map(pdf._add_object, [first, second, third])
    first[NameObject("/Next")] = ArrayObject([second_ref, third_ref])
    second[NameObject("/Next")] = first_ref
    pdf._root_object[NameObject("/OpenAction")] = first_ref
    result = inspect(serialize(pdf))
    edges = [item for item in result["edges"] if item["kind"] == "action_Next"]
    assert {item["route"] for item in edges} == {"/Next[0]", "/Next[1]", "/Next"}
    assert len(result["witnesses"]) == 2 and len(result["observations"]) < 50
    assert "inert.invalid" not in json.dumps(result)


def test_arbitrary_script_and_fake_annotation_are_not_legal_context():
    pdf = writer()
    pdf._root_object[NameObject("/Private")] = dictionary(JS=TextStringObject("var unlinked = 1;"))
    pdf._root_object[NameObject("/FakeAnnotation")] = dictionary(Type=NameObject("/Annot"), A=js_action())
    result = inspect(serialize(pdf))
    assert not result["witnesses"]


def test_real_annotation_action_uses_verified_page_owner_path():
    pdf = writer()
    annotation = pdf._add_object(dictionary(Type=NameObject("/Annot"), Subtype=NameObject("/Link"), A=js_action()))
    pdf.pages[0][NameObject("/Annots")] = ArrayObject([annotation])
    result = inspect(serialize(pdf))
    assert len(result["witnesses"]) == 1
    assert any(edge["kind"] == "page_annotation" for edge in result["edges"])


def test_dangling_reference_records_requested_identity_and_local_scope():
    pdf = writer()
    pdf._root_object[NameObject("/OpenAction")] = js_action()
    pdf._root_object[NameObject("/Private")] = IndirectObject(9999, 7, pdf)
    result = inspect(serialize(pdf), complete=False)
    missing = [item for item in result["observations"] if item["kind"] == "unresolved_reference"]
    assert missing and all(item["object_number"] == 9999 and item["generation"] == 7 for item in missing)
    assert any("recovery_generation_unsupported" in item["reason_codes"] for item in missing)
    assert result["status"] == "partial"
    assert result["witnesses"]
    failed_check = next(item for item in result["capability_checks"] if item["backend"] == "pypdf" and item["capability"] == "catalog")
    assert failed_check["scope_ids"] and not failed_check["required_ids"]
    assert not any(item["kind"] == "document" and item["id"] in failed_check["scope_ids"] for item in result["observations"])


@pytest.mark.parametrize("backend", ["pypdf", "MuPDF"])
def test_backend_open_failure_does_not_erase_independent_completed_nodes(monkeypatch, backend):
    from malpdf.static import evidence_v9
    pdf = writer()
    pdf._root_object[NameObject("/OpenAction")] = js_action()
    def fail(*args, **kwargs):
        raise AttributeError("private parser fixture detail")
    monkeypatch.setattr(evidence_v9, "PdfReader" if backend == "pypdf" else "MuPDFObjectReader", fail)
    result = inspect(serialize(pdf), complete=False)
    failed = next(item for item in result["backend_results"] if item["backend"] == backend)
    assert failed["status"] == "error" and failed["stage"] == "open"
    assert any(item["kind"] == "script" and item["ast_status"] == "complete" for item in result["observations"])
    assert "private parser" not in json.dumps(result)


def test_ast_attribute_error_preserves_graph_and_completed_extraction_checkpoint(monkeypatch):
    from malpdf.static import evidence_v9
    pdf = writer()
    pdf._root_object[NameObject("/OpenAction")] = js_action()
    checkpoints = []
    def fail(*args, **kwargs):
        raise AttributeError("inert private AST fixture")
    monkeypatch.setattr(evidence_v9, "inspect_js_syntax", fail)
    result = inspect(serialize(pdf), checkpoint=checkpoints.append)
    extraction = [item for delta in checkpoints for item in delta.get("observations", []) if item["kind"] == "script_extraction"]
    assert extraction and extraction[0]["extraction_status"] == "complete"
    assert extraction[0]["decoded_sha256"]
    assert any(edge["kind"] == "catalog_action" for edge in result["edges"])
    script = next(item for item in result["observations"] if item["kind"] == "script")
    assert script["ast_status"] == "unavailable" and "script_ast_attribute_error" in script["reason_codes"]
    assert not result["witnesses"] and "private AST" not in json.dumps(result)


def test_checkpoint_merge_is_additive_and_collision_refuses_overwrite():
    pdf = writer()
    pdf._root_object[NameObject("/OpenAction")] = js_action()
    collected = {"schema_version": EVIDENCE_SCHEMA}
    result = inspect(serialize(pdf), checkpoint=lambda delta: merge_evidence_delta(collected, delta))
    assert collected["observations"] == result["observations"]
    assert collected["edges"] == result["edges"]
    before = deepcopy(collected)
    bad = dict(result["observations"][0], status="unavailable")
    with pytest.raises(ValueError, match="overwrite"):
        merge_evidence_delta(collected, {"observations": [bad]})
    assert collected == before


def executable_fixture():
    # Format-identification bytes only: no instructions or executable body.
    content = bytearray(88)
    content[:2], content[60:64], content[64:68] = b"MZ", (64).to_bytes(4, "little"), b"PE\0\0"
    return bytes(content)


@pytest.mark.parametrize("action_kind,external,eligible", [("/Launch", False, True), ("/Launch", True, False), ("/GoToE", False, False)])
def test_launch_requires_exact_filespec_ef_and_full_decoded_payload(action_kind, external, eligible):
    pdf = writer()
    stream = DecodedStreamObject()
    stream._data = executable_fixture()
    stream[NameObject("/Type")] = NameObject("/EmbeddedFile")
    embedded = pdf._add_object(stream)
    filespec = dictionary(Type=NameObject("/Filespec"), F=TextStringObject("same-private-name"), EF=dictionary(F=embedded))
    action = dictionary(S=NameObject(action_kind), F=TextStringObject("same-private-name") if external else pdf._add_object(filespec))
    pdf._root_object[NameObject("/OpenAction")] = action
    pdf._root_object[NameObject("/PrivatePayload")] = embedded
    result = inspect(serialize(pdf))
    witnesses = [item for item in result["witnesses"] if item["family"] == "embedded_launch"]
    assert bool(witnesses) == eligible
    assert "same-private-name" not in json.dumps(result)


def test_short_magic_prefix_is_not_a_verified_executable_header():
    assert _payload_magic(b"MZsome inert text") == "other"
    assert _payload_magic(b"\x7fELFtext") == "other"
    assert _payload_magic(executable_fixture()) == "pe"


@pytest.mark.parametrize("event,expected", [(True, True), (False, False)])
def test_xfa_requires_declared_event_ancestor(event, expected):
    pdf = writer()
    text = b'<script contentType="application/x-javascript">var xfaInert = 1;</script>'
    xml = b"<template>" + (b'<event activity="initialize">' + text + b"</event>" if event else text) + b"</template>"
    stream = DecodedStreamObject()
    stream._data = xml
    form = pdf._add_object(dictionary(XFA=pdf._add_object(stream)))
    pdf._root_object[NameObject("/AcroForm")] = form
    result = inspect(serialize(pdf))
    witnesses = [item for item in result["witnesses"] if item["family"] == "xfa_javascript"]
    assert bool(witnesses) == expected
    assert "xfaInert" not in json.dumps(result)


@pytest.mark.parametrize("variant,eligible", [("valid", True), ("truncated", False), ("checksum", False), ("trailing", False), ("bomb", False)])
def test_strict_flate_eligibility_retains_raw_before_decode(variant, eligible):
    pdf = writer()
    body = b"var harmless = 1;" if variant != "bomb" else b" " * 10000
    compressed = zlib.compress(body)
    if variant == "truncated":
        compressed = compressed[:-2]
    elif variant == "checksum":
        compressed = compressed[:-1] + bytes([compressed[-1] ^ 1])
    elif variant == "trailing":
        compressed += b"unverified trailing bytes"
    stream = EncodedStreamObject()
    stream._data = compressed
    stream[NameObject("/Filter")] = NameObject("/FlateDecode")
    action = dictionary(S=NameObject("/JavaScript"), JS=pdf._add_object(stream))
    pdf._root_object[NameObject("/OpenAction")] = action
    received = []
    def sink(content):
        received.append(content)
        return {"sha256": hashlib.sha256(content).hexdigest(), "status": "retained", "reason_code": None}
    result = inspect(serialize(pdf), limits=replace(CodeInspectionLimits(), max_decoded_bytes=1024), raw_sink=sink)
    assert compressed in received
    assert any(item["raw_sha256"] == hashlib.sha256(compressed).hexdigest() for item in result["observations"])
    assert bool(result["witnesses"]) == eligible
    script = next(item for item in result["observations"] if item["kind"] == "script")
    assert script["decoded_validated"] == eligible
    assert result["budget_usage"]["decoded_bytes_remaining"] >= 0


def test_legacy_remaining_budget_is_not_reset_for_recovery():
    pdf = writer()
    pdf._root_object[NameObject("/OpenAction")] = js_action()
    result = inspect(serialize(pdf), complete=False, legacy_analysis={"decoded_bytes_remaining": 0, "backends": []})
    assert result["budget_usage"]["decoded_bytes_remaining"] == 0
    assert not result["witnesses"]
    assert all(item.get("decoded_validated") is not True for item in result["observations"] if item["kind"] == "script")


def test_prior_ast_limit_is_latched_even_when_completed_node_count_is_small(monkeypatch):
    from malpdf.static import evidence_v9
    pdf = writer()
    pdf._root_object[NameObject("/OpenAction")] = js_action()
    data = serialize(pdf)
    limits = CodeInspectionLimits()
    code = _inspect_code_bytes(data, limits)
    code["errors"].append("ast_node_limit")
    code["budget_usage"]["ast_nodes"] = 1
    def forbidden(*args, **kwargs):
        pytest.fail("An exhausted AST allowance must never restart")
    monkeypatch.setattr(evidence_v9, "inspect_js_syntax", forbidden)
    result = inspect_evidence_v9(data, {"input": {"sha256": hashlib.sha256(data).hexdigest()},
        "features": {}, "parser": {}, "errors": []}, code, limits)
    assert not result["witnesses"]
    assert any("ast_node_limit" in item["reason_codes"] for item in result["observations"] if item["kind"] == "script")


def test_completed_legacy_ast_cache_can_be_preserved_after_later_ast_limit(monkeypatch):
    from malpdf.static import evidence_v9
    pdf = writer()
    pdf._root_object[NameObject("/OpenAction")] = js_action()
    data = serialize(pdf)
    limits = CodeInspectionLimits()
    code = _inspect_code_bytes(data, limits, evidence_metadata=True)
    code["errors"].append("ast_node_limit")
    def forbidden(*args, **kwargs):
        pytest.fail("Completed exact-identity AST evidence must be reused")
    monkeypatch.setattr(evidence_v9, "inspect_js_syntax", forbidden)
    result = inspect_evidence_v9(data, {"input": {"sha256": hashlib.sha256(data).hexdigest()},
        "features": {}, "parser": {}, "errors": []}, code, limits)
    assert result["witnesses"] and result["budget_usage"]["ast_nodes_v9"] == 0


def test_script_limit_cannot_restart_on_secondary_backend(monkeypatch):
    from malpdf.static import evidence_v9
    pdf = writer()
    pdf._root_object[NameObject("/OpenAction")] = js_action()
    data = serialize(pdf)
    limits = CodeInspectionLimits()
    code = _inspect_code_bytes(data, limits)
    code["errors"].append("script_count_limit")
    calls = []
    monkeypatch.setattr(evidence_v9, "inspect_js_syntax", lambda *args, **kwargs: calls.append(True))
    result = inspect_evidence_v9(data, {"input": {"sha256": hashlib.sha256(data).hexdigest()},
        "features": {}, "parser": {}, "errors": []}, code, limits)
    assert not calls and not result["witnesses"]
    assert any("script_count_limit" in item["reason_codes"] for item in result["observations"] if item["kind"] == "script")


def test_metadata_cap_preserves_early_graph_and_records_incomplete(monkeypatch):
    from malpdf.static import evidence_v9
    pdf = writer()
    pdf._root_object[NameObject("/OpenAction")] = js_action()
    pdf._root_object[NameObject("/Large")]=ArrayObject([TextStringObject(str(i)) for i in range(100)])
    monkeypatch.setattr(evidence_v9, "MAX_METADATA_BYTES", 45000)
    from malpdf.static.evidence_ipc import EvidenceAccumulator
    data = serialize(pdf)
    retained = EvidenceAccumulator(hashlib.sha256(data).hexdigest())
    result = inspect(data, checkpoint=retained.merge)
    assert not result["complete"] and result["observations"]
    assert any("evidence_metadata_limit" in item["reason_codes"] for item in result["capability_checks"])
    assert result["witnesses"]
    assert any(item["kind"] == "stage_failure" and "evidence_metadata_limit" in item["reason_codes"]
               and item["affected_ids"] for item in retained.value["observations"])
    for section in ("observations", "edges", "capability_checks", "backend_results", "conflicts"):
        assert retained.value[section] == result[section]


def recovery_metadata_fixture(monkeypatch):
    """Leave enough ordinary metadata for primary, then exhaust it in recovery."""
    from malpdf.static import evidence_v9
    pdf = writer()
    pdf._root_object[NameObject("/OpenAction")] = js_action()
    pdf._root_object[NameObject("/Large")] = ArrayObject([TextStringObject(str(i)) for i in range(100)])
    data = serialize(pdf)
    primary = inspect(data)
    maximum = (primary["budget_usage"]["graph_metadata_bytes"] + 4096) * 3 // 2
    monkeypatch.setattr(evidence_v9, "MAX_METADATA_BYTES", maximum)
    return data, primary, maximum


def test_recovery_metadata_limit_retains_primary_and_localized_checkpoint_for_integration(monkeypatch):
    from malpdf.experiments.cic_v9 import assess_integration
    from malpdf.static.evidence_ipc import EvidenceAccumulator, encoded
    data, primary, maximum = recovery_metadata_fixture(monkeypatch)
    digest = hashlib.sha256(data).hexdigest()
    retained = EvidenceAccumulator(digest)
    result = inspect(data, complete=False, checkpoint=retained.merge)
    nodes = {item["id"]: item for item in result["observations"]}
    failures = [item for item in nodes.values() if item["kind"] == "stage_failure"
                and item["backend"] == "MuPDF" and "evidence_metadata_limit" in item["reason_codes"]]
    assert failures and all(item["affected_ids"] for item in failures)
    assert all(nodes[identifier]["locator"] and nodes[identifier]["document_sha256"] == digest
               for item in failures for identifier in item["affected_ids"])
    assert [item for item in result["observations"] if item["backend"] == "pypdf"] == [
        item for item in primary["observations"] if item["backend"] == "pypdf"]
    recovery = [item for item in retained.value["capability_checks"] if item["backend"] == "MuPDF"]
    assert recovery and all(item["status"] == "partial" and item["scope_ids"] for item in recovery)
    for section in ("observations", "edges", "capability_checks", "backend_results", "conflicts"):
        assert retained.value[section] == result[section]
    assert len(encoded(result)) <= maximum
    profile = {"status": "partial", "errors": [], "worker_cleanup_complete": True,
               "static": {"input": {"sha256": digest}, "features": {}}, "analysis_v9": result}
    monkeypatch.setattr("malpdf.experiments.cic_static_accuracy.profile_input_available", lambda *args: True)
    previous = {"pdf_sha256": digest, "static": profile["static"]}
    assert assess_integration(profile, previous)["passed"]
    result["observations"] = [item for item in result["observations"] if item not in failures]
    assert "backend_failure_stage_unlocalized" in assess_integration(profile, previous)["reason_codes"]


@pytest.mark.parametrize("section", ["backend_results", "capability_checks"])
def test_interrupt_after_recovery_cap_keeps_terminal_checkpoint(monkeypatch, section):
    from malpdf.static.evidence_ipc import EvidenceAccumulator
    data, primary, _ = recovery_metadata_fixture(monkeypatch)
    retained = EvidenceAccumulator(hashlib.sha256(data).hexdigest())
    def interrupt(delta):
        retained.merge(delta)
        if any(item.get("backend") == "MuPDF" for item in delta.get(section, [])):
            raise KeyboardInterrupt("synthetic interruption after recovery cap")
    with pytest.raises(KeyboardInterrupt):
        inspect(data, complete=False, checkpoint=interrupt)
    assert [item for item in retained.value["observations"] if item["backend"] == "pypdf"] == [
        item for item in primary["observations"] if item["backend"] == "pypdf"]
    assert any(item["kind"] == "stage_failure" and "evidence_metadata_limit" in item["reason_codes"]
               and item["affected_ids"] for item in retained.value["observations"])
    assert any(item.get("backend") == "MuPDF" for item in retained.value[section])


def test_terminal_reserve_is_bounded_and_cannot_restart_ordinary_metadata(monkeypatch):
    from malpdf.static import evidence_v9
    from malpdf.static.js_ast import CodeInspectionError
    monkeypatch.setattr(evidence_v9, "MAX_METADATA_BYTES", 50000)
    store = evidence_v9._Store("a" * 64, None, None)
    retained = store.observation("pypdf", "object:1:0", "catalog")
    for index in range(100):
        try:
            store.observation("MuPDF", f"object:{index + 2}:0", "pdf_object", projection={"padding": "x" * 2000})
        except CodeInspectionError:
            break
    else:
        pytest.fail("ordinary metadata allowance was not enforced")
    ordinary = deepcopy(store.result["observations"])
    store.observation("MuPDF", "catalog|metadata_cap", "stage_failure", status="unavailable",
                      affected_ids=[retained], capability="catalog", reason_codes=["evidence_metadata_limit"])
    assert store.result["observations"][:-1] == ordinary
    with pytest.raises(CodeInspectionError, match="evidence_metadata_limit"):
        store.observation("MuPDF", "ordinary_after_cap", "pdf_object", projection={"padding": "x" * 2000})
    before = deepcopy(store.result)
    with pytest.raises(CodeInspectionError, match="evidence_metadata_limit"):
        store.observation("MuPDF", "oversized_failure", "stage_failure", affected_ids=[retained], padding="x" * 50000)
    assert store.result == before and store.metadata_bytes < 50000


def test_oversized_complete_capability_becomes_localized_checkpointed_partial(monkeypatch):
    from malpdf.static import evidence_v9
    from malpdf.static.evidence_ipc import EvidenceAccumulator
    from malpdf.static.js_ast import CodeInspectionError
    original = evidence_v9._Store.append
    refused = []
    def fail_large_check(self, key, item):
        if key == "capability_checks" and item["capability"] == "catalog" and item["status"] == "complete":
            refused.append(True)
            raise CodeInspectionError("evidence_metadata_limit")
        return original(self, key, item)
    monkeypatch.setattr(evidence_v9._Store, "append", fail_large_check)
    data = serialize(writer())
    retained = EvidenceAccumulator(hashlib.sha256(data).hexdigest())
    result = inspect(data, checkpoint=retained.merge)
    check = next(item for item in result["capability_checks"] if item["capability"] == "catalog")
    assert refused and not result["complete"] and check["status"] == "partial" and check["scope_ids"]
    assert check in retained.value["capability_checks"]
    assert result["backend_results"][0]["status"] == "partial"
    assert "evidence_metadata_limit" in result["backend_results"][0]["reason_codes"]
    assert any(item["kind"] == "stage_failure" and item["affected_ids"] == check["scope_ids"]
               for item in retained.value["observations"])


def test_incremental_update_keeps_generations_distinct_and_latest_catalog_context():
    pdf = writer()
    old = pdf._add_object(js_action("var oldRevision = 1;"))
    pdf._root_object[NameObject("/OpenAction")] = old
    original = serialize(pdf)
    reader = PdfReader(io.BytesIO(original))
    root = reader.trailer.raw_get("/Root")
    pages = reader.trailer["/Root"].raw_get("/Pages")
    previous = int(original.split(b"startxref\n")[-1].splitlines()[0])
    update = bytearray(original + b"\n")
    root_offset = len(update)
    update.extend((f"{root.idnum} 0 obj\n<< /Type /Catalog /Pages {pages.idnum} 0 R "
                   f"/OpenAction {old.idnum} 1 R /PrivateOld {old.idnum} 0 R >>\nendobj\n").encode())
    action_offset = len(update)
    update.extend((f"{old.idnum} 1 obj\n<< /S /JavaScript /JS (var newRevision = 2;) >>\nendobj\n").encode())
    xref_offset = len(update)
    entries = sorted([(root.idnum, root_offset, 0), (old.idnum, action_offset, 1)])
    update.extend(b"xref\n")
    for number, offset, generation in entries:
        update.extend(f"{number} 1\n{offset:010d} {generation:05d} n \n".encode())
    update.extend((f"trailer\n<< /Root {root.idnum} 0 R /Size {len(pdf._objects) + 1} /Prev {previous} >>\n"
                   f"startxref\n{xref_offset}\n%%EOF\n").encode())
    result = inspect(bytes(update))
    actions = [item for item in result["observations"] if item["kind"] == "action" and item["object_number"] == old.idnum]
    assert {item["generation"] for item in actions} == {0, 1}
    assert len({item["id"] for item in actions}) == 2
    assert all(item["revision"] == "unknown" and type(item["offset"]) is int for item in actions)
    assert len(result["witnesses"]) == 1
    updated = next(item for item in actions if item["generation"] == 1)
    assert updated["id"] in result["witnesses"][0]["supporting_ids"]
    assert "oldRevision" not in json.dumps(result) and "newRevision" not in json.dumps(result)

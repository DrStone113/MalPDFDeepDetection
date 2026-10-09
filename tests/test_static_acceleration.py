"""Synthetic contracts for capped reads, batch inference and inert AST evidence."""

from dataclasses import replace
import io
import json
import multiprocessing
import time
import zlib

import numpy as np
import pytest
from pypdf import PdfWriter
from pypdf.generic import DictionaryObject, NameObject, TextStringObject, EncodedStreamObject

from malpdf.inference.predictor import StaticScanSession
from malpdf.inference.schema import DEPLOYMENT_FEATURE_ORDER
from malpdf.static.analyzer import StaticPDFAnalyzer
from malpdf.static.code_inspector import CodeInspectionLimits, _inspect_code_bytes, inspect_pdf_code, inspect_pdf_codes
from malpdf.static.js_ast import CodeInspectionError, inspect_js_syntax
from malpdf.static.result import StaticInspectionResult
from malpdf.static.safety import StaticInspectionLimits, read_bounded_bytes
from malpdf.static.schema import RIT_FEATURES, implementation_statuses


def _pdf(script=None, *, compressed=False, filter_name="/FlateDecode"):
    writer = PdfWriter()
    writer.add_blank_page(72, 72)
    if script is not None:
        value = TextStringObject(script)
        if compressed:
            value = EncodedStreamObject()
            value._data = zlib.compress(script.encode())
            value[NameObject("/Filter")] = NameObject(filter_name)
            value = writer._add_object(value)
        writer._root_object[NameObject("/OpenAction")] = writer._add_object(DictionaryObject({
            NameObject("/S"): NameObject("/JavaScript"), NameObject("/JS"): value}))
    output = io.BytesIO()
    writer.write(output)
    return output.getvalue()


def _inspection(value=0, failed=False):
    features = {feature: value for feature in RIT_FEATURES}
    if failed:
        features[DEPLOYMENT_FEATURE_ORDER[0]] = None
    return StaticInspectionResult(input={"size_bytes": 100}, parser={"success": True},
        features=features, compatibility=dict(implementation_statuses()), diagnostics={})


def _manifest():
    return {"model_id": "synthetic", "artifact_sha256": "0" * 64,
            "training_dataset": {"sha256": "1" * 64}, "feature_schema": "synthetic", "threshold": 0.5}


class _Model:
    def __init__(self):
        self.rows = []

    def predict_proba(self, frame):
        assert tuple(frame.columns) == DEPLOYMENT_FEATURE_ORDER
        self.rows.append(frame.iloc[:, 0].tolist())
        p = np.asarray(frame.iloc[:, 0], dtype=float) / 10
        return np.column_stack([1 - p, p])


def test_analyzer_checks_size_before_opening_or_hashing(tmp_path, monkeypatch):
    path = tmp_path / "large.pdf"
    path.write_bytes(_pdf())
    def forbidden(*args, **kwargs):
        raise AssertionError("Oversized input must not be read or hashed")
    monkeypatch.setattr("malpdf.static.analyzer.read_bounded_bytes", forbidden)
    monkeypatch.setattr("malpdf.static.analyzer.hashlib.sha256", forbidden)
    result = StaticPDFAnalyzer(StaticInspectionLimits(max_file_size_bytes=10)).inspect(path)
    assert result.input["sha256"] is None
    assert [issue.code for issue in result.errors] == ["file_size_limit"]


def test_analyzer_uses_one_stable_snapshot(tmp_path, monkeypatch):
    path = tmp_path / "one.pdf"
    data = _pdf()
    path.write_bytes(data)
    from malpdf.static.safety import read_bounded_bytes
    calls = []
    def bounded(*args, **kwargs):
        calls.append(args[0])
        return read_bounded_bytes(*args, **kwargs)
    monkeypatch.setattr("malpdf.static.analyzer.read_bounded_bytes", bounded)
    result = StaticPDFAnalyzer().inspect(path)
    assert result.parser["success"] and calls == [path]
    import hashlib
    assert result.input["sha256"] == hashlib.sha256(data).hexdigest()


def test_analyzer_rejects_symlink_without_following_it(tmp_path):
    target, link = tmp_path / "target.pdf", tmp_path / "link.pdf"
    target.write_bytes(_pdf())
    link.symlink_to(target)
    result = StaticPDFAnalyzer().inspect(link)
    assert result.input["sha256"] is None and not result.parser["success"]
    assert result.errors[0].code == "file_read_error"


def test_analyzer_preserves_refusal_if_snapshot_changes(tmp_path, monkeypatch):
    path = tmp_path / "changing.pdf"
    path.write_bytes(_pdf())
    def changed(*args, **kwargs):
        raise ValueError("Input changed during reading")
    monkeypatch.setattr("malpdf.static.analyzer.read_bounded_bytes", changed)
    result = StaticPDFAnalyzer().inspect(path)
    assert result.input["sha256"] is None
    assert not result.protocol_g_drop3constant_gate().passed


def test_bounded_snapshot_does_not_allocate_maximum_cap_for_small_files(tmp_path, monkeypatch):
    import builtins
    path = tmp_path / "small.txt"
    path.write_bytes(b"bounded inert bytes")
    original, requested = builtins.open, []
    class ObservedFile:
        def __init__(self, handle): self.handle = handle
        def __enter__(self): return self
        def __exit__(self, *args): return self.handle.__exit__(*args)
        def fileno(self): return self.handle.fileno()
        def read(self, size):
            requested.append(size)
            return self.handle.read(size)
    monkeypatch.setattr(builtins, "open", lambda *args, **kwargs: ObservedFile(original(*args, **kwargs)))
    assert read_bounded_bytes(path, boundary=tmp_path, max_bytes=50 * 1024**2) == b"bounded inert bytes"
    assert requested == [len(b"bounded inert bytes") + 1]


def test_size_based_bounded_read_still_rejects_file_growth(tmp_path, monkeypatch):
    import builtins
    path = tmp_path / "growing.txt"
    path.write_bytes(b"initial")
    original = builtins.open
    class GrowingFile:
        def __init__(self, handle): self.handle = handle
        def __enter__(self): return self
        def __exit__(self, *args): return self.handle.__exit__(*args)
        def fileno(self): return self.handle.fileno()
        def read(self, size):
            with original(path, "ab") as writer: writer.write(b"extra bytes past requested length")
            return self.handle.read(size)
    monkeypatch.setattr(builtins, "open", lambda *args, **kwargs: GrowingFile(original(*args, **kwargs)))
    with pytest.raises(ValueError, match="changed during reading"):
        read_bounded_bytes(path, boundary=tmp_path, max_bytes=1024)


def test_resident_session_batches_only_compatible_rows_and_preserves_order():
    model, loads = _Model(), []
    manifest = _manifest()
    def loader(root):
        loads.append(root)
        return model, manifest
    session = StaticScanSession(repository_root="synthetic", batch_size=3,
        inspector=lambda path, limits=None: _inspection(int(path) if path != "bad" else 0, path == "bad"), model_loader=loader)
    results = session.scan_many(["1", "bad", "3", "5", "9"])
    assert loads == ["synthetic"] and model.rows == [[1, 3], [5, 9]]
    assert [r.prediction["malicious_probability"] for r in results] == [0.1, None, 0.3, 0.5, 0.9]
    assert not results[1].prediction["available"]
    assert results[0].explanation["reason"] == "not_requested"
    manifest["threshold"] = 0.95
    assert session.scan_many(["9"])[0].prediction["predicted_label"] == 1
    assert len(loads) == 1  # Immutable manifest snapshot stays frozen.


def test_session_all_gate_failures_never_load_model():
    def forbidden(root):
        raise AssertionError("Never load on incompatible features")
    results = StaticScanSession(repository_root="synthetic", model_loader=forbidden,
        inspector=lambda path, limits=None: _inspection(failed=True)).scan_many(range(4))
    assert all(not result.prediction["available"] for result in results)


@pytest.mark.parametrize("raw", [np.array([[0.5, np.nan]]), np.array([[0.7, 0.6]]), np.ones((1, 3))])
def test_session_rejects_invalid_model_probabilities(raw):
    model = _Model()
    model.predict_proba = lambda frame: raw
    result = StaticScanSession(repository_root="synthetic", model_loader=lambda root: (model, _manifest()),
        inspector=lambda path, limits=None: _inspection()).scan_many(["x"])[0]
    assert not result.prediction["available"]
    assert result.prediction["malicious_probability"] is None


def test_session_load_failure_is_not_retried_for_each_file():
    calls = []
    def unavailable(root):
        calls.append(root)
        raise ValueError("unverified artifact")
    results = StaticScanSession(repository_root="synthetic", batch_size=1, model_loader=unavailable,
        inspector=lambda path, limits=None: _inspection()).scan_many(range(3))
    assert len(calls) == 1 and all(not r.prediction["available"] for r in results)


def test_ast_ignores_tokens_in_comments_and_literals():
    result = inspect_js_syntax('var note="eval unescape util.printf"; /* eval("text") */ var count=1;')
    assert sum(result["named_calls"].values()) == 0
    assert result["node_count"] > 0


def test_ast_recognizes_computed_literal_calls_and_redacts_source():
    result = inspect_js_syntax('util["pri"+"ntf"]("private text"); unescape("%41");')
    assert result["named_calls"]["util.printf"] == 1
    assert result["named_calls"]["unescape"] == 1
    assert "private text" not in json.dumps(result)


def test_ast_structure_is_invariant_to_local_variable_renaming():
    first = inspect_js_syntax('var apple=1; for(var banana=0;banana<2;banana++){apple+=banana;}')
    second = inspect_js_syntax('var x=1; for(var y=0;y<2;y++){x+=y;}')
    assert first == second and first["loops"] == 1


@pytest.mark.parametrize("source,kwargs,code", [
    ("var =;", {}, "javascript_parse_error"),
    ("var a=1;", {"max_bytes": 2}, "script_byte_limit"),
    ("var a=1;", {"max_nodes": 1}, "ast_node_limit"),
    ("var a=1;", {"max_depth": 1}, "ast_depth_limit"),
])
def test_ast_limits_and_invalid_syntax_remain_explicit(source, kwargs, code):
    with pytest.raises(CodeInspectionError, match=code):
        inspect_js_syntax(source, **kwargs)


@pytest.mark.parametrize("compressed", [False, True])
def test_pdf_literal_and_flate_scripts_yield_same_syntax_evidence(compressed):
    result = _inspect_code_bytes(_pdf('var count=1; util.printf("test");', compressed=compressed), CodeInspectionLimits())
    assert result["complete"] and result["scripts_parsed"] == 1
    assert result["ast"]["named_calls"]["util.printf"] == 1
    assert result["referral_recommended"] and not result["active_content_executed"]


def test_pdf_decoded_names_are_followed_without_counting_literal_mentions():
    data = _pdf('var text="/JS eval";')
    escaped = data.replace(b"/JS ", b"/J#53 ")  # after xref offsets: rebuild with writer
    from pypdf import PdfReader
    writer = PdfWriter(clone_from=PdfReader(io.BytesIO(escaped), strict=False))
    output = io.BytesIO()
    writer.write(output)
    result = _inspect_code_bytes(output.getvalue(), CodeInspectionLimits())
    assert result["scripts_parsed"] == 1 and sum(result["ast"]["named_calls"].values()) == 0


def test_unsupported_filter_and_decode_bomb_are_partial_not_clean():
    unsupported = _inspect_code_bytes(_pdf("var a=1;", compressed=True, filter_name="/LZWDecode"), CodeInspectionLimits())
    oversized = _inspect_code_bytes(_pdf(" " * 5000, compressed=True), replace(CodeInspectionLimits(), max_script_bytes=1024))
    assert unsupported["errors"] == ["unsupported_script_filter"]
    assert oversized["errors"] == ["script_byte_limit"]
    assert all(r["referral_recommended"] and not r["complete"] for r in (unsupported, oversized))


def test_bad_syntax_and_object_budget_force_referral():
    bad = _inspect_code_bytes(_pdf("var =;"), CodeInspectionLimits())
    limited = _inspect_code_bytes(_pdf("var a=1;"), replace(CodeInspectionLimits(), max_objects=1))
    assert bad["errors"] == ["javascript_parse_error"] and bad["scripts_parsed"] == 0
    assert "pdf_structure_limit" in limited["errors"] and not limited["complete"]


def test_actual_spawn_inspection_handles_benign_flate_and_non_pdf(tmp_path):
    pdf, other = tmp_path / "benign.pdf", tmp_path / "not_pdf.txt"
    pdf.write_bytes(_pdf('var n=1;', compressed=True))
    other.write_bytes(b"inert text")
    results = dict(inspect_pdf_codes([pdf, other], boundary=tmp_path, workers=2))
    assert results[0]["complete"] and results[0]["scripts_parsed"] == 1
    assert results[1]["status"] == "unavailable" and results[1]["referral_recommended"]
    assert "inert text" not in json.dumps(results)


def _slow_child(connection, path, boundary, limits, expected_sha256):
    time.sleep(30)  # synthetic worker timeout; no sample code is executed


def test_parent_timeout_terminates_worker_and_preserves_unavailable_result(tmp_path, monkeypatch):
    monkeypatch.setattr("malpdf.static.code_inspector._code_child", _slow_child)
    before = {p.pid for p in multiprocessing.active_children()}
    result = inspect_pdf_code(tmp_path / "unused.pdf", limits=replace(CodeInspectionLimits(), wall_seconds=1, cpu_seconds=1))
    assert result["errors"] == ["parser_exit_or_timeout"]
    assert {p.pid for p in multiprocessing.active_children()} == before


def test_process_inspection_rejects_symlink_and_oversized_file(tmp_path):
    path, link = tmp_path / "source.pdf", tmp_path / "alias.pdf"
    path.write_bytes(_pdf())
    link.symlink_to(path)
    for supplied, limits in [(link, CodeInspectionLimits()), (path, replace(CodeInspectionLimits(), max_file_bytes=10))]:
        result = inspect_pdf_code(supplied, boundary=tmp_path, limits=limits)
        assert not result["complete"] and result["referral_recommended"]


def test_cli_code_inspection_does_not_load_model(monkeypatch, capsys):
    from malpdf.cli import main
    monkeypatch.setattr("malpdf.cli.inspect_pdf_code", lambda path: {"complete": True, "active_content_executed": False})
    monkeypatch.setattr("malpdf.cli.scan_pdf", lambda *args, **kwargs: pytest.fail("Unexpected inference"))
    assert main(["code-inspect", "benign.pdf"]) == 0
    assert json.loads(capsys.readouterr().out)["active_content_executed"] is False


def test_no_script_and_encrypted_pdf_are_distinguished():
    clean = _inspect_code_bytes(_pdf(), CodeInspectionLimits())
    assert clean["complete"] and clean["scripts_found"] == 0
    assert not clean["referral_recommended"]
    writer = PdfWriter()
    writer.add_blank_page(72, 72)
    writer.encrypt("synthetic fixture password")
    output = io.BytesIO()
    writer.write(output)
    encrypted = _inspect_code_bytes(output.getvalue(), CodeInspectionLimits())
    assert encrypted["errors"] == ["encrypted_pdf"]
    assert encrypted["scripts_found"] is None and encrypted["referral_recommended"]


def test_multiple_scripts_share_decoding_and_ast_budgets():
    writer = PdfWriter()
    writer.add_blank_page(72, 72)
    from pypdf.generic import ArrayObject
    actions = [DictionaryObject({NameObject("/JS"): TextStringObject("var count=1;")}) for _ in range(3)]
    writer._root_object[NameObject("/Actions")] = ArrayObject(actions)
    output = io.BytesIO()
    writer.write(output)
    for limits, error in [(replace(CodeInspectionLimits(), max_scripts=1), "script_count_limit"),
                          (replace(CodeInspectionLimits(), max_decoded_bytes=14), "decoded_byte_limit"),
                          (replace(CodeInspectionLimits(), max_ast_nodes=6), "ast_node_limit")]:
        result = _inspect_code_bytes(output.getvalue(), limits)
        assert error in result["errors"] and not result["complete"]
        assert result["referral_recommended"]


def test_code_decode_parameters_are_not_implicitly_processed():
    from pypdf.generic import NumberObject
    writer = PdfWriter()
    writer.add_blank_page(72, 72)
    stream = EncodedStreamObject()
    stream._data = zlib.compress(b"var count=1;")
    stream[NameObject("/Filter")] = NameObject("/FlateDecode")
    stream[NameObject("/DecodeParms")] = DictionaryObject({NameObject("/Predictor"): NumberObject(12)})
    writer._root_object[NameObject("/JS")] = writer._add_object(stream)
    output = io.BytesIO()
    writer.write(output)
    result = _inspect_code_bytes(output.getvalue(), CodeInspectionLimits())
    assert result["errors"] == ["unsupported_decode_parameters"]
    assert result["scripts_parsed"] == 0 and result["referral_recommended"]


def test_cli_incomplete_code_evidence_overrides_benign_model_decision(monkeypatch, capsys):
    from malpdf.cli import main
    from malpdf.inference.result import InferenceResult
    model = _Model()
    payload = StaticScanSession(repository_root="synthetic", model_loader=lambda root: (model, _manifest()),
        inspector=lambda path, limits=None: _inspection()).scan_many(["x"])[0].to_dict()
    monkeypatch.setattr("malpdf.cli.scan_pdf", lambda *args, **kwargs: InferenceResult(**payload))
    monkeypatch.setattr("malpdf.cli.inspect_pdf_code", lambda path, **kwargs: {"complete": False, "referral_recommended": True,
                       "errors": ["unsupported_script_filter"]})
    assert main(["scan", "benign.pdf", "--json", "--no-explanation", "--code-inspection"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["prediction"]["verdict"] == "BENIGN"
    assert result["static_decision"]["verdict"] == "REFERRAL_REQUIRED"
    assert not result["static_decision"]["dynamic_analysis_executed"]


def test_code_inspection_refuses_a_changed_snapshot_before_ast_parsing(tmp_path):
    import hashlib
    path = tmp_path / "benign.pdf"
    original = _pdf("var count=1;")
    path.write_bytes(original)
    digest = hashlib.sha256(original).hexdigest()
    matched = inspect_pdf_code(path, boundary=tmp_path, expected_sha256=digest)
    assert matched["complete"] and matched["scripts_parsed"] == 1
    path.write_bytes(_pdf("var count=2;"))
    changed = inspect_pdf_code(path, boundary=tmp_path, expected_sha256=digest)
    assert changed["errors"] == ["input_snapshot_mismatch"]
    assert changed["scripts_parsed"] is None and changed["ast"] is None
    assert changed["referral_recommended"]

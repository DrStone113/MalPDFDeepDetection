from __future__ import annotations

import io
import zlib

import numpy as np
import pikepdf
import pytest
import torch

from malpdf.cdr.engine import PDFDisarmer
from malpdf.cdr.fixtures import load_real_benign_bytes
from malpdf.scanner.forensic import (
    _reconcile_semantic_verdict,
    reconcile_taxonomy_observations,
    semantic_graph_selection,
)
from test_complete_hardening_wave4 import _assert_integrity, _fixture, _link
from test_complete_hardening_wave4 import engines as engines
from test_four_pillar_improvements import _with_scripts

PHISHING_URI = "https://portal-verify-2026.invalid/login"


def _scan_both(engines, raw, verdict):
    results = [engine.scan_bytes(raw, explain=True) for engine in engines]
    assert [result.verdict for result in results] == [verdict] * len(engines)
    assert abs(results[0].malware_probability - results[1].malware_probability) <= 1e-5
    return results


def _assert_clean_taxonomy(result):
    taxonomy = result.threat_taxonomy
    assert taxonomy["detected_count"] == 0
    assert not [head["id"] for head in taxonomy["ml_label_predictions"] if head["evidence_status"] == "model_signal"]


def _trim(pdf, pages):
    del pdf.pages[pages:]
    for page in pdf.pages:
        if "/Annots" in page.obj:
            del page.obj["/Annots"]


@pytest.mark.parametrize("variant", ["text", "image", "qr"])
def test_fastpath_and_image_qr_inspection(engines, variant):
    pixels = np.tile(np.arange(128, dtype=np.uint8) * 2, (128, 1))
    if variant == "qr":
        zxingcpp = pytest.importorskip("zxingcpp")
        pixels = np.asarray(zxingcpp.write_barcode(zxingcpp.BarcodeFormat.QRCode, PHISHING_URI, width=180, height=180))

    def edit(pdf):
        _trim(pdf, 1)
        page = pdf.pages[0].obj
        if variant == "text":
            font = pikepdf.Dictionary(
                Type=pikepdf.Name.Font, Subtype=pikepdf.Name.Type1, BaseFont=pikepdf.Name.Helvetica
            )
            page.Resources = pikepdf.Dictionary(Font=pikepdf.Dictionary(Text=font))
            page.Contents = pdf.make_stream(b"BT /Text 12 Tf 50 440 Td (Publication schedule) Tj ET")
            return
        image = pdf.make_stream(
            zlib.compress(pixels.tobytes()),
            Type=pikepdf.Name.XObject,
            Subtype=pikepdf.Name.Image,
            Width=pixels.shape[1],
            Height=pixels.shape[0],
            BitsPerComponent=8,
            ColorSpace=pikepdf.Name.DeviceGray,
            Filter=pikepdf.Name.FlateDecode,
        )
        page.Resources = pikepdf.Dictionary(XObject=pikepdf.Dictionary(Picture=image))
        page.Contents = pdf.make_stream(b"q 160 0 0 160 50 440 cm /Picture Do Q")
        assert "/Font" not in page.Resources and "/Annots" not in page

    raw = _fixture(edit)
    if variant == "text":
        results = _scan_both(engines, raw, "BENIGN")
        assert all(result.forensic_dossier["differential_analysis"]["pikepdf_pages"] == 0 for result in results)
        return
    assert b"/Font" not in raw and b"/Annots" not in raw
    for result in _scan_both(engines, raw, "MALICIOUS" if variant == "qr" else "BENIGN"):
        qr = result.forensic_dossier["qr_analysis"]
        assert qr["images_scanned"] >= 1
        if variant == "qr":
            assert qr["has_qr_threat"] and qr["decoded_uris"] == [PHISHING_URI]
        else:
            assert result.is_ood is False
            _assert_clean_taxonomy(result)


def _navigation_fixture(pages, action):
    base = load_real_benign_bytes()
    if action == "acroform":
        base = _with_scripts("form", 'AFNumber_Format(2, 0, 0, 0, "$", true);')
    with pikepdf.open(io.BytesIO(base)) as pdf:
        _trim(pdf, pages)
        destination = pikepdf.Array([pdf.pages[0].obj, pikepdf.Name.FitH, None])
        named = pikepdf.Dictionary(S=pikepdf.Name.Named, N=pikepdf.Name.FirstPage)
        if action == "empty_aa":
            pdf.Root.AA = pikepdf.Dictionary()
        elif action == "named_aa":
            pdf.Root.AA = pikepdf.Dictionary(WP=named)
        elif action == "named":
            pdf.Root.OpenAction = named
        elif action in {"goto", "indirect_goto"}:
            target = pdf.make_indirect(destination) if action == "indirect_goto" else destination
            pdf.Root.OpenAction = pikepdf.Dictionary(S=pikepdf.Name.GoTo, D=target)
        else:
            pdf.Root.OpenAction = destination
        output = io.BytesIO()
        mode = pikepdf.ObjectStreamMode.generate if action == "packed" else pikepdf.ObjectStreamMode.disable
        pdf.save(output, object_stream_mode=mode)
        return output.getvalue()


@pytest.mark.parametrize(
    ("action", "evidence_id", "role"),
    [
        ("array", "action:open_action", "destination"),
        ("goto", "action:open_action", "destination"),
        ("indirect_goto", "action:open_action", "destination"),
        ("named", "action:open_action", "benign_navigation"),
        ("empty_aa", "action:aa", "empty_aa"),
        ("named_aa", "action:aa", "benign_navigation"),
        ("packed", "action:open_action", "destination"),
    ],
)
@pytest.mark.parametrize("pages", [1, 2])
def test_navigation_calibrates_and_disarms(engines, pages, action, evidence_id, role):
    raw = _navigation_fixture(pages, action)
    for result in _scan_both(engines, raw, "BENIGN"):
        assert result.pages_count == pages
        assert result.is_ood is False and result.confidence == "HIGH"
        calibration = result.forensic_dossier["navigation_semantic_calibration"]
        assert calibration["applied"] and calibration["reconciled_nodes"] == [evidence_id]
        node = next(node for node in result.graph_nodes if node["id"] == evidence_id)
        assert node["action_role"] == role and not node["is_threat_trigger"]
        _assert_clean_taxonomy(result)
        if action == "packed":
            assert b"/ObjStm" in raw
            structural = next(
                h for h in result.threat_taxonomy["ml_label_predictions"] if h["id"] == "structural_parser_evasion"
            )
            assert structural["evidence_status"] == "not_observed"
    clean, audit = PDFDisarmer().sanitize_bytes(raw)
    assert audit.is_sanitized
    _assert_integrity(raw, clean, audit)
    _scan_both(engines, clean, "BENIGN")


@pytest.mark.parametrize("catalog_aa", [False, True])
def test_extra_page_trigger_blocks_navigation_calibration(engines, catalog_aa):
    def edit(pdf):
        _trim(pdf, 1)
        if catalog_aa:
            pdf.Root.AA = pikepdf.Dictionary()
            pdf.pages[0].obj.AA = pikepdf.Dictionary()
        else:
            destination = pikepdf.Array([pdf.pages[0].obj, pikepdf.Name.FitH, None])
            pdf.Root.OpenAction = destination
            pdf.pages[0].obj.OpenAction = destination

    raw = _fixture(edit)
    results = [engine.scan_bytes(raw, explain=True) for engine in engines]
    assert results[0].verdict == results[1].verdict
    assert abs(results[0].malware_probability - results[1].malware_probability) <= 1e-5
    for result in results:
        assert "navigation_semantic_calibration" not in result.forensic_dossier
    pt_engine = engines[0]
    data = pt_engine.ingestion.ingest(raw)
    _, reconciled_prob = _reconcile_semantic_verdict(
        data,
        3.5,
        0.97,
        pt_engine.decision_threshold,
        pt_engine.temperature,
        pt_engine.uses_regime_b,
        lambda *_args: -6.0,
    )
    assert reconciled_prob == pytest.approx(0.97)
    assert "navigation_semantic_calibration" not in data


def test_verified_form_script_and_catalog_navigation_calibrate_together(engines):
    raw = _navigation_fixture(1, "acroform")
    for result in _scan_both(engines, raw, "BENIGN"):
        assert result.is_ood is False and result.confidence == "HIGH"
        assert result.forensic_dossier["ast_semantic_calibration"]["applied"]
        node = next(node for node in result.graph_nodes if node["id"] == "action:open_action")
        assert node["action_role"] == "destination" and not node["is_threat_trigger"]
        _assert_clean_taxonomy(result)
    clean, audit = PDFDisarmer().sanitize_bytes(raw)
    assert audit.is_sanitized
    _assert_integrity(raw, clean, audit)
    _scan_both(engines, clean, "BENIGN")


@pytest.mark.parametrize(
    "control", ["javascript", "launch", "next", "print", "array", "names", "remote", "uri", "polyglot", "escaped"]
)
def test_active_or_ambiguous_catalog_navigation_fails_closed(engines, control):
    def edit(pdf):
        _trim(pdf, 1)
        target = pikepdf.Array([pdf.pages[0].obj, pikepdf.Name.FitH, None])
        script = pikepdf.Dictionary(S=pikepdf.Name.JavaScript, JS="eval('1')")
        pdf.Root.OpenAction = target
        if control == "javascript":
            pdf.Root.OpenAction = pikepdf.Dictionary(S=pikepdf.Name.JavaScript, JS="eval(unescape('%31'))")
        elif control == "launch":
            pdf.Root.OpenAction = pikepdf.Dictionary(S=pikepdf.Name.Launch, F="fixture-nonexistent.invalid")
        elif control == "next":
            pdf.Root.OpenAction = pikepdf.Dictionary(
                S=pikepdf.Name.GoTo, D=target, Next=pikepdf.Dictionary(S=pikepdf.Name.JavaScript, JS="app.alert(1)")
            )
        elif control == "print":
            pdf.Root.OpenAction = pikepdf.Dictionary(S=pikepdf.Name.Named, N=pikepdf.Name.Print)
        elif control == "array":
            pdf.Root.OpenAction = pikepdf.Array([script])
        elif control == "names":
            pdf.Root.Names = pikepdf.Dictionary(
                JavaScript=pikepdf.Dictionary(Names=pikepdf.Array(["check", pdf.make_indirect(script)]))
            )
        elif control == "remote":
            pdf.pages[0].obj.Annots = pikepdf.Array(
                [
                    pdf.make_indirect(
                        pikepdf.Dictionary(
                            Type=pikepdf.Name.Annot,
                            Subtype=pikepdf.Name.Link,
                            Rect=pikepdf.Array([20, 20, 70, 70]),
                            A=pikepdf.Dictionary(S=pikepdf.Name.GoToR, F="reference.pdf", D="reference"),
                        )
                    )
                ]
            )
        elif control == "uri":
            _link(pdf, PHISHING_URI)

    raw = _fixture(edit)
    if control == "polyglot":
        raw += b"PK\x03\x04"
    if control == "escaped":
        raw = raw.replace(b"/OpenAction", b"/Open#41ction", 1)
    if control == "print":
        results = [engine.scan_bytes(raw, explain=True) for engine in engines]
        assert results[0].verdict == results[1].verdict
        assert abs(results[0].malware_probability - results[1].malware_probability) <= 1e-5
        for result in results:
            assert "navigation_semantic_calibration" not in result.forensic_dossier
        pt_engine = engines[0]
        data = pt_engine.ingestion.ingest(raw)
        _, reconciled_prob = _reconcile_semantic_verdict(
            data,
            3.5,
            0.97,
            pt_engine.decision_threshold,
            pt_engine.temperature,
            pt_engine.uses_regime_b,
            lambda *_args: -6.0,
        )
        assert reconciled_prob == pytest.approx(0.97)
        assert "navigation_semantic_calibration" not in data
        return
    for result in _scan_both(engines, raw, "MALICIOUS"):
        assert "navigation_semantic_calibration" not in result.forensic_dossier
        if control == "array":
            node = next(node for node in result.graph_nodes if node["id"] == "action:open_action")
            assert node["action_role"] is None


@pytest.mark.parametrize(
    "trigger",
    [
        "action_inspection_limit",
        "codec_inspection_limit",
        "supplemental_inspection_incomplete",
    ],
)
def test_budget_markers_remain_auditable_without_triggering_anti_padding(engines, trigger):
    def edit(pdf):
        _trim(pdf, 1)
        with pikepdf.open(io.BytesIO(load_real_benign_bytes())) as source:
            pdf.pages.extend(source.pages[0] for _ in range(20))

    engine = engines[0]
    data = engine.ingestion.ingest(_fixture(edit))
    data["non_js_triggers"] = [trigger]
    calls = []

    def counterfactual(nodes, columns, baselines):
        calls.append(nodes)
        assert not columns and not baselines
        kept_nodes, kept_edges, indices = semantic_graph_selection(
            len(data["node_features"]), data["edge_index"].numpy(), nodes
        )
        with torch.no_grad():
            logits, _ = engine._forward(
                data["node_features"][kept_nodes],
                data["node_types"][kept_nodes],
                torch.as_tensor(indices),
                data["edge_rel"][kept_edges],
                data["batch"][kept_nodes],
                data["ast_tokens"],
                data["v4_tab_features" if engine.is_v4 else "v3_tab_features"],
                data["graph_present"],
            )
        return logits.item()

    _reconcile_semantic_verdict(data, -3, 0.05, 0.5, engine.temperature, engine.uses_regime_b, counterfactual)
    assert bool(calls) == (trigger == "supplemental_inspection_incomplete")
    assert data["non_js_triggers"] == [trigger]
    assert reconcile_taxonomy_observations({}, data, "BENIGN") == set()


def test_exact_taxonomy_domains_fail_closed(engines):
    data = engines[0].ingestion.ingest(_navigation_fixture(1, "array"))
    suppressed = reconcile_taxonomy_observations({}, data, "BENIGN")
    assert {"active_form_or_exploit", "suspicious_uri_redirect"} <= suppressed
    assert reconcile_taxonomy_observations({}, data, "MALICIOUS") == set()
    locked = {**data, "encryption_analysis": {"password_locked": True}}
    assert reconcile_taxonomy_observations({}, locked, "BENIGN") == set()

    disagreements = {"AcroForm": "active_form_or_exploit", "URI": "suspicious_uri_redirect", "AA": "auto_open_trigger"}
    for token, head in disagreements.items():
        count = len(data["extracted_uris"]) + 1 if token == "URI" else 1
        mismatched = {**data, "raw_tokens": {**data["raw_tokens"], token: count}}
        assert head not in reconcile_taxonomy_observations({}, mismatched, "BENIGN")
    observed = {"suspicious_uri_redirect": "Static observation"}
    assert "suspicious_uri_redirect" not in reconcile_taxonomy_observations(observed, data, "BENIGN")
    assert observed["suspicious_uri_redirect"] == "Static observation"
    repeated = {**data, "raw_tokens": {**data["raw_tokens"], "OpenAction": 2}}
    assert "auto_open_trigger" not in reconcile_taxonomy_observations({}, repeated, "BENIGN")


def test_packed_non_security_tokens_do_not_inflate_recovery(engines):
    with pikepdf.open(io.BytesIO(load_real_benign_bytes())) as pdf:
        stream = io.BytesIO()
        pdf.save(stream, object_stream_mode=pikepdf.ObjectStreamMode.generate)
    raw = stream.getvalue()
    for engine in engines:
        audit = engine.ingestion.ingest(raw)["evasion_unpack_audit"]
        assert audit["objstm_streams_unpacked"] > 0
        assert {"Resources", "Root", "page_command", "URI"}.isdisjoint(audit["recovered_hidden_triggers"])

    packed_navigation = _navigation_fixture(1, "packed")
    for engine in engines:
        data = engine.ingestion.ingest(packed_navigation)
        assert "OpenAction" in data["evasion_unpack_audit"]["recovered_hidden_triggers"]
        assert data["raw_tokens"]["OpenAction"] == 1
        observations = {}
        assert reconcile_taxonomy_observations(observations, data, "MALICIOUS") == set()
        assert observations["structural_parser_evasion"] is None

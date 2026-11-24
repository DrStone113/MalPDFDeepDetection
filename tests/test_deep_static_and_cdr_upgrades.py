from email import policy
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.parser import BytesParser
import hashlib
import importlib
import io
import json
import struct

from fastapi.testclient import TestClient
import pikepdf
from production.onnx_engine import ONNXMalPDFScannerEngine
import pymupdf
import pytest
from scripts.deploy.export_onnx_models import _binary_parity, _fixture_binary_inputs

from malpdf.cdr.engine import PDFDisarmer
from malpdf.cdr.fixtures import load_real_benign_bytes
from malpdf.gateway.mail_filter import MailGatewayFilter
from malpdf.scanner.engine import MalPDFScannerEngine


@pytest.fixture(scope="module")
def engines():
    return MalPDFScannerEngine(device="cpu"), ONNXMalPDFScannerEngine()


def _fixture(edit):
    with pikepdf.open(io.BytesIO(load_real_benign_bytes())) as pdf:
        edit(pdf)
        output = io.BytesIO()
        pdf.save(output)
        return output.getvalue()


def _scan(engines, raw, verdict):
    pt, onnx = engines
    results = [engine.scan_bytes(raw, explain=True) for engine in engines]
    assert [result.verdict for result in results] == [verdict, verdict]
    assert abs(results[0].malware_probability - results[1].malware_probability) <= 1e-5
    inputs = _fixture_binary_inputs(pt.ingestion.ingest(raw))
    assert _binary_parity(pt.model, onnx.bin_session, inputs) <= 1e-5
    return results


def _assert_integrity(raw, cleaned, audit, *, text_expected=True):
    assert len(cleaned) > 0.8 * len(raw)
    assert audit.content_streams_preserved and audit.resources_preserved
    with pymupdf.open(stream=raw) as before, pymupdf.open(stream=cleaned) as after:
        assert len(before) == len(after) == audit.original_pages == audit.sanitized_pages
        original_text = "".join(page.get_text() for page in before).strip()
        assert bool(original_text) is text_expected
        assert "".join(page.get_text() for page in after).strip() == original_text


def _xfa(pdf, *packets):
    streams = [pdf.make_stream(packet) for packet in packets]
    xfa = streams[0]
    if len(streams) > 1:
        xfa = pikepdf.Array()
        for index, stream in enumerate(streams):
            xfa.extend([pikepdf.String(f"packet{index}"), stream])
    pdf.Root.AcroForm = pikepdf.Dictionary(Fields=pikepdf.Array(), XFA=xfa)


@pytest.mark.parametrize("packet_array", [False, True])
def test_xfa_scripts_flow_through_both_scanners_and_cdr(engines, packet_array):
    code = "eval(String.fromCharCode(" + ",".join(str(ord(char)) for char in "1 + 2;") + "));"
    script = f'<template><script contentType="application/x-javascript">{code}</script></template>'.encode()
    packets = (b"<config/>", script, b"<datasets/>") if packet_array else (script,)
    raw = _fixture(lambda pdf: _xfa(pdf, *packets))
    for engine in engines:
        ingested = engine.ingestion.ingest(raw)
        assert ingested["xfa_analysis"]["javascript_count"] == 1
        assert ingested["xfa_analysis"]["anomalies"] == []
        assert ingested["ast_node_counts"]["CallExpression"] >= 2
        assert ingested["extracted_scripts"] == [
            {"script_id": "script:xfa_0", "parent_id": "script:acroform_xfa", "code": code}
        ]
    for result in _scan(engines, raw, "MALICIOUS"):
        script_finding = result.forensic_dossier["threat_scripts"][0]
        assert script_finding["full_code"] == code
        assert script_finding["deobfuscation_applied"]
    cleaned, audit = PDFDisarmer().sanitize_bytes(raw)
    assert audit.is_sanitized and "acroform_XFA" in audit.removed_triggers
    _assert_integrity(raw, cleaned, audit)
    _scan(engines, cleaned, "BENIGN")


@pytest.mark.parametrize(
    ("xml", "reason"),
    [
        (b'<!DOCTYPE template [<!ENTITY sample "inert">]><template/>', "xfa_xml_dtd_unsupported"),
        (b'<template usehref="#sample"/>', "xfa_reference_unsupported"),
    ],
)
def test_xfa_anomalies_reach_taxonomy(engines, xml, reason):
    raw = _fixture(lambda pdf: _xfa(pdf, xml))
    for engine in engines:
        result = engine.scan_bytes(raw, explain=True)
        assert reason in result.forensic_dossier["xfa_analysis"]["anomalies"]
        assert reason in json.dumps(result.threat_taxonomy)
    if reason == "xfa_xml_dtd_unsupported":
        _scan(engines, raw, "MALICIOUS")


def test_xfa_later_packet_dtd_and_invalid_script_are_observed(engines):
    dtd = _fixture(lambda pdf: _xfa(pdf, b"<config/>", b"<!DOCTYPE template><template/>"))
    for result in _scan(engines, dtd, "MALICIOUS"):
        assert "xfa_xml_dtd_unsupported" in result.forensic_dossier["xfa_analysis"]["anomalies"]
    invalid = _fixture(lambda pdf: _xfa(pdf, b'<script contentType="application/x-javascript">var = ;</script>'))
    for engine in engines:
        result = engine.scan_bytes(invalid, explain=True)
        assert "xfa_javascript_parse_error" in result.forensic_dossier["xfa_analysis"]["anomalies"]
        assert result.forensic_dossier["threat_scripts"][0]["full_code"] == "var = ;"


def _image(pdf, body, codec=None):
    image = pdf.make_stream(
        body,
        Type=pikepdf.Name.XObject,
        Subtype=pikepdf.Name.Image,
        Width=1,
        Height=1,
        ColorSpace=pikepdf.Name.DeviceGray,
        BitsPerComponent=8,
    )
    if codec:
        image.Filter = pikepdf.Name(codec)
    resources = pdf.pages[0].obj.Resources
    if "/XObject" not in resources:
        resources.XObject = pikepdf.Dictionary()
    resources.XObject["/StaticProbe"] = image
    return image


def _font(pdf, key, body, *, direct_descriptor=False):
    stream = pdf.make_stream(body)
    if key == "/FontFile3":
        stream.Subtype = pikepdf.Name.Type1C
    descriptor = pikepdf.Dictionary(Type=pikepdf.Name.FontDescriptor)
    descriptor[key] = stream
    font = next(iter(pdf.pages[0].obj.Resources.Font.values()))
    font.FontDescriptor = descriptor if direct_descriptor else pdf.make_indirect(descriptor)


def _jpx_header():
    return b"\xff\x4f\xff\x51" + struct.pack(">HH8IH3B", 41, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 7, 1, 1) + b"\xff\xd9"


def _sfnt(offset):
    return struct.pack(">4s4H4s3I4s", b"\0\1\0\0", 1, 16, 0, 0, b"name", 0, offset, 4, b"test")


@pytest.mark.parametrize(
    ("edit", "codec", "reason"),
    [
        (lambda pdf: _image(pdf, b"invalid", "/JPXDecode"), "JPX", "jpx_signature_invalid"),
        (lambda pdf: _image(pdf, _jpx_header(), "/JPXDecode"), "JPX", None),
        (lambda pdf: _font(pdf, "/FontFile2", _sfnt(100)), "FONT", "font_table_bounds_invalid"),
        (lambda pdf: _font(pdf, "/FontFile2", _sfnt(100), direct_descriptor=True), "FONT", "font_table_bounds_invalid"),
        (lambda pdf: _font(pdf, "/FontFile2", _sfnt(28)), "FONT", None),
        (lambda pdf: _font(pdf, "/FontFile3", b"\1\0\4\0"), "FONT", "cff_header_invalid"),
        (lambda pdf: _font(pdf, "/FontFile3", b"\1\0\4\4"), "FONT", None),
    ],
)
def test_codec_structure_and_benign_controls(engines, edit, codec, reason):
    raw = _fixture(edit)
    for result in _scan(engines, raw, "MALICIOUS" if reason else "BENIGN"):
        anomalies = result.forensic_dossier["codec_anomalies"]
        if reason:
            assert len(anomalies) == 1
            assert anomalies[0]["codec"] == codec and reason in anomalies[0]["reason_codes"]
            assert "stream" not in anomalies[0]
            assert reason in json.dumps(result.threat_taxonomy)
        else:
            assert anomalies == []


def test_residual_codec_anomaly_quarantines_attachment(engines, tmp_path):
    raw = _fixture(lambda pdf: _image(pdf, b"invalid", "/JPXDecode"))
    rewritten, audit = PDFDisarmer().sanitize_bytes(raw)
    assert not audit.is_sanitized and audit.quarantine_recommended
    assert audit.residual_codec_anomalies[0]["reason_codes"] == ["jpx_signature_invalid"]
    assert audit.trailer_state["residual_codec_anomalies_count"] == 1
    json.dumps(audit.to_dict())
    _assert_integrity(raw, rewritten, audit)

    message = MIMEMultipart()
    attachment = MIMEApplication(raw, _subtype="pdf")
    attachment.add_header("Content-Disposition", "attachment", filename="codec.pdf")
    message.attach(attachment)
    gateway = MailGatewayFilter(scanner_engine=engines[0], quarantine_dir=tmp_path)
    output, report = gateway.process_email_bytes(message.as_bytes())
    assert report.action_taken == "QUARANTINED_ATTACHMENT"
    assert not report.attachments[0].disarmed
    sha256 = hashlib.sha256(raw).hexdigest()
    assert (tmp_path / f"{sha256}.pdf").read_bytes() == raw
    result = BytesParser(policy=policy.default).parsebytes(output)
    assert result["X-MalPDF-Inspection"] == "THREATS_QUARANTINED"
    (notice,) = list(result.iter_attachments())
    assert notice.get_content_type() == "text/plain"
    assert notice.get_filename() == "quarantined_codec.pdf.txt"
    assert notice["X-MalPDF-Quarantined"] == "TRUE"
    assert notice["X-MalPDF-Original-SHA256"].strip() == sha256
    assert sha256 in notice.get_content()
    assert all(part.get_content_type() != "application/pdf" for part in result.walk())
    output_path = tmp_path / "clean.pdf"
    with pytest.raises(ValueError, match="cdr_output_requires_quarantine"):
        PDFDisarmer().sanitize_file(tmp_path / f"{sha256}.pdf", output_path)
    assert not output_path.exists()


def test_unlabelled_jbig2_anomaly_survives_cdr_rewrite(monkeypatch):
    marker = b"\x97JB2\r\n\x1a\n"
    with pikepdf.open(io.BytesIO(load_real_benign_bytes())) as pdf:
        _image(pdf, marker)
        output = io.BytesIO()
        pdf.save(output, compress_streams=False)

    def unexpected_renderer(*args, **kwargs):
        pytest.fail("CDR must skip native rendering for flagged codecs")

    monkeypatch.setattr(pymupdf, "open", unexpected_renderer)
    cleaned, audit = PDFDisarmer().sanitize_bytes(output.getvalue())
    assert marker in cleaned
    assert not audit.is_sanitized and audit.quarantine_recommended
    assert audit.residual_codec_anomalies[0]["codec"] == "JBIG2"
    assert len(cleaned) > 0.8 * audit.size_before
    assert audit.original_pages == audit.sanitized_pages
    assert audit.content_streams_preserved and audit.resources_preserved


@pytest.mark.parametrize("module_name", ["malpdf.web.app", "production.web_service"])
def test_web_does_not_offer_quarantined_cdr_output(module_name, monkeypatch, tmp_path):
    raw = _fixture(lambda pdf: _image(pdf, b"invalid", "/JPXDecode"))
    module = importlib.import_module(module_name)
    monkeypatch.setattr(module.session_registry, "quarantine_root", tmp_path / "quarantine")
    with TestClient(module.app) as client:
        scan = client.post("/api/scan", files={"file": ("codec.pdf", raw, "application/pdf")})
        assert scan.status_code == 200
        scan_id = scan.json()["scan_id"]
        cdr = client.post(f"/api/disarm/{scan_id}")
        assert cdr.status_code == 200
        assert not cdr.json()["is_sanitized"] and cdr.json()["quarantine_recommended"]
        assert client.get(f"/api/download/sanitized/{scan_id}").status_code == 409


def _visual_link(pdf, *, hide_text, uri, rect=(50, 100, 550, 700), subtype=pikepdf.Name.Link):
    _image(pdf, b"\xff")
    page = pdf.pages[0].obj
    if hide_text:
        del pdf.pages[1:]
        page.Contents = pdf.make_stream(b"q 100 0 0 100 50 100 cm /StaticProbe Do Q")
    page.Annots = pikepdf.Array(
        [
            pikepdf.Dictionary(
                Type=pikepdf.Name.Annot,
                Subtype=subtype,
                Rect=pikepdf.Array(rect),
                A=pikepdf.Dictionary(S=pikepdf.Name.URI, URI=pikepdf.String(uri)),
            )
        ]
    )


def test_visual_overlay_removed_when_cdr_skips_original_rendering():
    def edit(pdf):
        _visual_link(pdf, hide_text=True, uri="https://portal-doc-review-2026.net/view/98123")
        _xfa(pdf, b"invalid")
        pdf.Root.AcroForm.XFA.Filter = pikepdf.Name.JPXDecode

    raw = _fixture(edit)
    cleaned, audit = PDFDisarmer().sanitize_bytes(raw)
    assert "page_0_annot_0_image_lure_URI" in audit.actions_stripped
    assert audit.is_sanitized and not audit.page_previews[0]["pixel_identity_pct"]
    _assert_integrity(raw, cleaned, audit, text_expected=False)


@pytest.mark.parametrize(
    ("hide_text", "uri", "rect", "subtype", "lure"),
    [
        (True, "https://portal-doc-review-2026.net/view/98123", (50, 100, 550, 700), pikepdf.Name.Link, True),
        (False, "https://portal-doc-review-2026.net/view/98123", (50, 100, 550, 700), pikepdf.Name.Link, True),
        (False, "https://portal-doc-review-2026.net/view/98123", (0, 0, 90, 20), pikepdf.Name.Link, False),
        (True, "https://portal-doc-review-2026.net/view/98123", (0, 0, 50, 49), pikepdf.Name.Link, False),
        (True, "https://portal-doc-review-2026.net/view/98123", (0, 0, 50, 50), pikepdf.Name.Square, False),
        (True, "https://files.adobe.com/view", (50, 100, 550, 700), pikepdf.Name.Link, False),
    ],
)
def test_visual_lure_detection_and_overlay_neutralization(engines, hide_text, uri, rect, subtype, lure):
    raw = _fixture(lambda pdf: _visual_link(pdf, hide_text=hide_text, uri=uri, rect=rect, subtype=subtype))
    for result in _scan(engines, raw, "MALICIOUS" if lure else "BENIGN"):
        phishing = result.forensic_dossier["phishing_analysis"]
        assert phishing["image_only_lure"] is lure
        if lure:
            (link,) = phishing["suspicious_uris"]
            reason = "image_only_visual_lure" if hide_text else "large_overlay_visual_lure"
            assert reason in link["reasons"]
            assert link["page_index"] == 0 and link["rect_area"] == 300000

    cleaned, audit = PDFDisarmer().sanitize_bytes(raw)
    assert audit.is_sanitized
    with pikepdf.open(io.BytesIO(cleaned)) as pdf:
        assert ("/A" not in pdf.pages[0].obj.Annots[0]) is lure
    if lure:
        surface = "image" if hide_text else "overlay"
        assert f"page_0_annot_0_{surface}_lure_URI" in audit.actions_stripped
        _assert_integrity(raw, cleaned, audit, text_expected=not hide_text)
        _scan(engines, cleaned, "BENIGN")

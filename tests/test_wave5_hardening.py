from email import message_from_bytes
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import io
import json
import zlib

import numpy as np
import pikepdf
import pymupdf
import pytest

from malpdf.cdr.engine import PDFDisarmer
from malpdf.cdr.fixtures import load_real_benign_bytes, load_real_threat_bytes
from malpdf.gateway.mail_filter import MailGatewayFilter
from malpdf.scanner import qr_scan
from malpdf.scanner.ai_explainer import AIThreatExplainer
from malpdf.scanner.threat_intel import StaticBlocklistProvider
from test_complete_hardening_wave4 import (
    _assert_integrity,
    _fixture,
    _link,
    _observed_taxonomy,
    _scan,
    _with_page_text,
)
from test_complete_hardening_wave4 import (
    codec_client as codec_client,
)
from test_complete_hardening_wave4 import (
    engines as engines,
)


def test_unaccented_vietnamese_lure_and_invoice_control(engines):
    url = "https://fixture.workers.dev/review"
    raw = _fixture(
        lambda pdf: _link(pdf, url),
        _with_page_text("xac minh tai khoan va dat lai mat khau de xem tai lieu"),
    )
    _scan(engines, raw, "MALICIOUS")
    clean, audit = PDFDisarmer().sanitize_bytes(raw)
    assert audit.is_sanitized
    _assert_integrity(raw, clean, audit)
    _scan(engines, clean, "BENIGN")
    for text in (
        "Cong hoa xa hoi chu nghia Viet Nam Hoa don gia tri gia tang Chu ky so",
        "Cộng hòa xã hội chủ nghĩa Việt Nam Hóa đơn giá trị gia tăng Chữ ký số",
    ):
        _scan(engines, _fixture(lambda pdf: _link(pdf, url), _with_page_text(text)), "BENIGN")


def test_page_coverage_overlay_defeats_padding_evasion(engines):
    def edit(pdf, *, rect, count):
        _replace_page_text(
            pdf,
            "This disclaimer asks readers to check the sender and the publication date before sharing this document with colleagues.",
        )
        _link(pdf, "https://external-review.invalid/reference", rect=rect)
        with pikepdf.open(io.BytesIO(load_real_benign_bytes())) as source:
            pdf.pages.extend(source.pages[0] for _ in range(count - len(pdf.pages)))
        if count > 3:
            pdf.pages[-1].obj.Contents = pdf.pages[0].obj.Contents
            pdf.pages[-1].obj.Resources = pdf.pages[0].obj.Resources
            pdf.pages[-1].obj.Annots = pdf.pages[0].obj.Annots
            del pdf.pages[0].obj["/Annots"]

    for count in (3, 5):
        raw = _fixture(lambda pdf: edit(pdf, rect=(0, 0, 520, 590), count=count))
        for result in _scan(engines, raw, "MALICIOUS"):
            assert "large_overlay_visual_lure" in _observed_taxonomy(result, "suspicious_uri_redirect")
            evidence = result.forensic_dossier["phishing_analysis"]["suspicious_uris"][0]
            assert evidence["page_index"] == (0 if count == 3 else 4)
            assert evidence["rect_area"] / evidence["page_area"] >= 0.45
        clean, audit = PDFDisarmer().sanitize_bytes(raw)
        assert audit.is_sanitized and any(item.endswith("_overlay_lure_URI") for item in audit.actions_stripped)
        _assert_integrity(raw, clean, audit)
        _scan(engines, clean, "BENIGN")
    small = _fixture(lambda pdf: edit(pdf, rect=(0, 0, 90, 20), count=3))
    _scan(engines, small, "BENIGN")


def test_differential_and_incremental_revision_shadowing(engines, tmp_path):
    def incremental(base, edit):
        path = tmp_path / "incremental.pdf"
        path.write_bytes(base)
        with pymupdf.open(path) as pdf:
            edit(pdf)
            pdf.saveIncr()
        result = path.read_bytes()
        assert result.count(b"%%EOF") == 2
        return result

    def update_signature(pdf):
        xref = pdf.get_new_xref()
        pdf.update_object(xref, "<< /Type /Sig /ByteRange [0 0 0 0] /Contents <00> >>")
        pdf.xref_set_key(pdf.pdf_catalog(), "Wave5Signature", f"{xref} 0 R")

    def update_catalog(pdf):
        pdf.xref_set_key(pdf.pdf_catalog(), "AA", "null")
        pdf.xref_set_key(pdf.pdf_catalog(), "Names", "<</EmbeddedFiles <</Names []>>>>")

    base = _fixture(lambda pdf: setattr(pdf.Root, "AA", pikepdf.Dictionary()))
    shadowed = incremental(base, update_catalog)
    for result in _scan(engines, shadowed, "MALICIOUS"):
        analysis = result.forensic_dossier["differential_analysis"]
        assert analysis["has_differential_evasion"] and analysis["shadowed_triggers"]
        assert "incremental_hidden_trigger_revision" in analysis["anomalies"]
        assert "incremental_shadow_trigger_update" in _observed_taxonomy(result, "structural_parser_evasion")
        assert "incremental_shadow_trigger_update" in AIThreatExplainer().answer_question(
            result.to_dict(), "Các bộ phân tích có thấy dữ liệu khác nhau không?"
        )
    for edit in (update_signature, lambda pdf: pdf.set_metadata({"modDate": "D:20261124090000"})):
        for result in _scan(engines, incremental(load_real_benign_bytes(), edit), "BENIGN"):
            assert not result.forensic_dossier["differential_analysis"]["has_differential_evasion"]


def _replace_page_text(pdf, text):
    page = pdf.pages[0].obj
    page.Resources.Font.Wave5Text = pikepdf.Dictionary(
        Type=pikepdf.Name.Font, Subtype=pikepdf.Name.Type1, BaseFont=pikepdf.Name.Helvetica
    )
    lines = [text[start : start + 70] for start in range(0, len(text), 70)]
    body = "\n".join(f"({line}) Tj T*" for line in lines)
    page.Contents = pdf.make_stream(f"BT /Wave5Text 10 Tf 12 TL 40 720 Td\n{body}\nET".encode("ascii"))


def _qr_pdf(url, text, *, nested=False):
    zxingcpp = pytest.importorskip("zxingcpp")
    pixels = np.asarray(zxingcpp.write_barcode(zxingcpp.BarcodeFormat.QRCode, url, width=180, height=180))

    def edit(pdf):
        _replace_page_text(pdf, text)
        page = pdf.pages[0].obj
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
        if nested:
            image = pdf.make_stream(
                b"/Image Do",
                Subtype=pikepdf.Name.Form,
                BBox=pikepdf.Array([0, 0, 1, 1]),
                Resources=pikepdf.Dictionary(XObject=pikepdf.Dictionary(Image=image)),
            )
        page.Resources.XObject = pikepdf.Dictionary(QR=image)
        page.Contents = pikepdf.Array([page.Contents, pdf.make_stream(b"q 160 0 0 160 50 440 cm /QR Do Q")])
        if "/Annots" in page:
            del page["/Annots"]
        del pdf.pages[1:]

    return _fixture(edit)


def _mail(raw, body=None, *, html=False, subject=None):
    message = MIMEMultipart()
    if subject is not None:
        message["Subject"] = subject
    if body is not None:
        message.attach(MIMEText(body, "html" if html else "plain", "utf-8"))
    attachment = MIMEApplication(raw, _subtype="pdf")
    attachment.add_header("Content-Disposition", "attachment", filename="fixture.pdf")
    message.attach(attachment)
    return message.as_bytes()


def test_qr_image_phishing_and_fail_closed_cdr(engines, codec_client, tmp_path, monkeypatch):
    url = "https://portal-verify-2026.invalid/login"
    raw = _qr_pdf(url, "Scan QR code to review this document.", nested=True)
    for result in _scan(engines, raw, "MALICIOUS"):
        analysis = result.forensic_dossier["qr_analysis"]
        assert analysis["decoded_uris"] == [url] and analysis["qr_codes_found"] == 1
        assert result.threat_taxonomy["qr_analysis"] == analysis
        assert "qr_code_phishing_uri" in _observed_taxonomy(result, "suspicious_uri_redirect")
        assert url in AIThreatExplainer().explain_threat(result.to_dict())["executive_summary"]
    blocklist = tmp_path / "blocklist.json"
    blocklist.write_text(json.dumps({"domain_blocklist": ["portal-verify-2026.invalid"]}), encoding="utf-8")
    for engine in engines:
        monkeypatch.setattr(engine, "threat_intel", StaticBlocklistProvider.from_json_file(blocklist))
        assert engine.scan_bytes(raw, explain=False).forensic_dossier["threat_intel"]["hit"]
    clean, audit = PDFDisarmer().sanitize_bytes(raw)
    assert audit.quarantine_recommended and not audit.is_sanitized and audit.residual_qr_anomalies
    _assert_integrity(raw, clean, audit)
    source = tmp_path / "qr.pdf"
    source.write_bytes(raw)
    with pytest.raises(ValueError, match="cdr_output_requires_quarantine"):
        PDFDisarmer().sanitize_file(source)
    scan = codec_client.post("/api/scan", files={"file": ("qr.pdf", raw)})
    assert scan.status_code == 200
    scan_id = scan.json()["scan_id"]
    assert codec_client.post(f"/api/disarm/{scan_id}").json()["quarantine_recommended"]
    assert codec_client.get(f"/api/download/sanitized/{scan_id}").status_code == 409
    for engine in engines:
        output, report = MailGatewayFilter(engine, quarantine_dir=tmp_path).process_email_bytes(_mail(raw))
        part = message_from_bytes(output).get_payload()[-1]
        assert part.get_content_type() == "text/plain" and part["X-MalPDF-Quarantined"] == "TRUE"
        assert report.attachments[0].cdr_audit["residual_qr_anomalies"]
    text = "This reference describes the project and its publication schedule. " * 5
    _scan(engines, _qr_pdf("https://www.adobe.com/acrobat", text), "BENIGN")
    neutral_url = "https://external-review.invalid/reference"
    _scan(engines, _qr_pdf(neutral_url, text), "BENIGN")
    _scan(engines, _qr_pdf(neutral_url, "Publication schedule"), "MALICIOUS")


def test_qr_skips_unsafe_input_before_pixmap(monkeypatch):
    raw = _qr_pdf("https://www.adobe.com/acrobat", "Publication schedule")

    def native_decoder_called(*args, **kwargs):
        pytest.fail("Unsafe image reached the native Pixmap decoder")

    monkeypatch.setattr(qr_scan.fitz, "Pixmap", native_decoder_called)
    with pikepdf.open(io.BytesIO(raw)) as pdf:
        skipped = qr_scan.scan_pdf_qr_codes(raw, pdf, pages_count=1, codec_anomalies=[{"codec": "Test"}])
        assert skipped["images_scanned"] == 0
        pdf.pages[0].obj.Resources.XObject.QR.write(b"invalid flate", filter=pikepdf.Name.FlateDecode)
        invalid = qr_scan.scan_pdf_qr_codes(raw, pdf, pages_count=1, codec_anomalies=[])
        assert invalid["images_scanned"] == 0
        assert invalid["anomalies"][0].startswith("qr_image_stream_invalid:")
        monkeypatch.setattr(qr_scan, "zxingcpp", None)
        assert not qr_scan.scan_pdf_qr_codes(raw, pdf, pages_count=1, codec_anomalies=[])["scanner_available"]


def _encrypt(raw, password):
    with pikepdf.open(io.BytesIO(raw)) as pdf:
        output = io.BytesIO()
        pdf.save(output, encryption=pikepdf.Encryption(owner="fixture-owner", user=password, R=4))
    return output.getvalue()


def test_mail_gateway_auto_unlocks_from_email_and_web_password_api(engines, codec_client, tmp_path):
    password = "secret-2026"
    threat = _encrypt(load_real_threat_bytes(), password)
    vn_threat = _encrypt(load_real_threat_bytes(), "pass-vn-26")
    benign = _encrypt(load_real_benign_bytes(), password)
    _scan(engines, threat, "MALICIOUS", password=password)
    for engine in engines:
        gateway = MailGatewayFilter(engine, quarantine_dir=tmp_path)
        for raw, body, html, expected in (
            (threat, "Password: incorrect\nPassword: secret-2026", False, "MALICIOUS"),
            (vn_threat, "<p>Mật khẩu mở tệp: <b>pass-vn-26</b></p>", True, "MALICIOUS"),
            (benign, "Password: secret-2026", False, "BENIGN"),
        ):
            output, report = gateway.process_email_bytes(_mail(raw, body, html=html))
            item = report.attachments[0]
            assert item.unlocked_from_email_body and item.verdict == expected
            part = message_from_bytes(output).get_payload()[-1]
            assert part["X-MalPDF-Unlocked-From-Email"] == "TRUE"
            if expected == "MALICIOUS":
                assert item.disarmed
                _, audit = PDFDisarmer().sanitize_bytes(raw, password="pass-vn-26" if html else password)
                _assert_integrity(
                    raw, part.get_payload(decode=True), audit, password="pass-vn-26" if html else password
                )
            else:
                assert not item.disarmed and part.get_payload(decode=True) == raw
        for body in (None, "Password: wrong"):
            _, report = gateway.process_email_bytes(_mail(threat, body))
            assert report.action_taken == "QUARANTINED_PASSWORD_LOCKED"
            assert not report.attachments[0].unlocked_from_email_body
        _, report = gateway.process_email_bytes(_mail(benign, subject=f"Password: {password}"))
        assert report.attachments[0].unlocked_from_email_body
        assert report.subject == "Password: [redacted]"
    files = {"file": ("locked.pdf", threat, "application/pdf")}
    locked = codec_client.post("/api/scan", files=files).json()
    assert locked["forensic_dossier"]["encryption_analysis"]["password_locked"]
    assert "mật khẩu" in locked["ai_threat_explanation"]["executive_summary"]
    assert "mật khẩu" in AIThreatExplainer().answer_question(locked, "Tệp bị khóa vì sao?")
    core_js = codec_client.get("/assets/dashboard-core.js").text
    assessment = core_js.split("export function scanAssessment(data) {", 1)[1].split(
        "export async function consumeCloudStream", 1
    )[0]
    assert "encryption_analysis?.password_locked" in assessment
    assert assessment.index("Tệp bị khóa mật khẩu") < assessment.index("Chưa thấy dấu hiệu nguy hiểm")
    unlocked = codec_client.post("/api/scan", files=files, data={"password": password}).json()
    assert unlocked["verdict"] == "MALICIOUS"
    assert not unlocked["forensic_dossier"]["encryption_analysis"]["password_locked"]
    for response in (
        codec_client.post(f"/api/disarm/{locked['scan_id']}", data={"password": password}),
        codec_client.post("/api/disarm", files=files, data={"password": password}),
    ):
        assert response.status_code == 200
        audit = response.json()
        assert audit["is_sanitized"]
        assert all(audit["post_scan_verification"]["integrity_assertions"].values())
        assert password not in response.text
    assert password not in codec_client.get("/api/audit/logs").text


def test_baseline_verdict_and_runtime_parity(engines):
    threat = load_real_threat_bytes()
    clean, audit = PDFDisarmer().sanitize_bytes(threat)
    _assert_integrity(threat, clean, audit)
    for body, verdict in ((load_real_benign_bytes(), "BENIGN"), (threat, "MALICIOUS"), (clean, "BENIGN")):
        for result in _scan(engines, body, verdict):
            assert not result.forensic_dossier["qr_analysis"]["decoded_uris"]
            assert not result.forensic_dossier["differential_analysis"]["has_differential_evasion"]

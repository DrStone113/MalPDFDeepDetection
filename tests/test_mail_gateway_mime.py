from __future__ import annotations

import email
import importlib
from email.message import Message
from email.mime.application import MIMEApplication
from email.mime.message import MIMEMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import pymupdf as fitz
import pytest
from fastapi.testclient import TestClient

from malpdf.cdr.fixtures import load_real_benign_bytes, load_real_threat_bytes
from malpdf.gateway.mail_filter import MailGatewayFilter
from malpdf.scanner.engine import MalPDFScannerEngine


@pytest.mark.parametrize("module_name", ["malpdf.web.app", "production.web_service"])
def test_email_api_holds_unreadable_attachment_without_clean_download(tmp_path: Path, monkeypatch, module_name: str) -> None:
    service = importlib.import_module(module_name)
    monkeypatch.setattr(service.session_registry, "quarantine_root", tmp_path / "quarantine")
    attachment = _pdf_attachment(load_real_benign_bytes(), "missing.pdf")
    attachment.set_payload("")
    message = _mail_with_pdf(attachment, "nested_mixed")
    client = TestClient(service.app)
    response = client.post("/api/gateway/inspect-eml", files={"file": ("review.eml", message.as_bytes(), "message/rfc822")})
    assert response.status_code == 200
    report = response.json()
    assert report["action"] == "HELD_FOR_REVIEW"
    assert report["has_sanitized_eml"] is False
    assert client.get(f"/api/gateway/download/eml/{report['eml_job_id']}").status_code == 409
    assert client.get("/api/audit/logs").json()["logs"][0]["details"]["verdict"] == "UNAVAILABLE"


@pytest.fixture(scope="module")
def reviewed_fixture_scanner() -> MalPDFScannerEngine:
    return MalPDFScannerEngine(device="cpu")


def _pdf_attachment(data: bytes, filename: str) -> MIMEApplication:
    part = MIMEApplication(data, _subtype="pdf")
    part.add_header("Content-Disposition", "attachment", filename=filename)
    return part


def _mail_with_pdf(attachment: Message, shape: str) -> Message:
    if shape == "singlepart":
        message = attachment
    else:
        message = MIMEMultipart("mixed")
        message.attach(MIMEText("Preserved outer email body.", "plain"))
        if shape == "flat":
            message.attach(attachment)
        else:
            inner = MIMEMultipart("alternative" if shape == "nested_alternative" else "mixed")
            inner.attach(MIMEText("Preserved nested plain body.", "plain"))
            inner.attach(MIMEText("<p>Preserved nested HTML body.</p>", "html"))
            inner.attach(attachment)
            if shape == "forwarded_message":
                inner["From"] = "original.sender@example.invalid"
                inner["Subject"] = "Preserved forwarded subject"
                message.attach(MIMEMessage(inner))
            else:
                message.attach(inner)
        note = MIMEApplication(b"Preserved non-PDF attachment.", _subtype="octet-stream")
        note.add_header("Content-Disposition", "attachment", filename="notes.txt")
        message.attach(note)
    message["From"] = "review.sender@example.invalid"
    message["To"] = "review.recipient@example.invalid"
    message["Subject"] = "Reviewed MIME fixture"
    message["Message-ID"] = "<reviewed-mime@example.invalid>"
    return message


def _assert_pdf_content_preserved(original: bytes, cleaned: bytes) -> None:
    assert len(cleaned) > 0.8 * len(original)
    with fitz.open(stream=original, filetype="pdf") as original_pdf:
        original_pages = len(original_pdf)
        original_text = "\n".join(page.get_text("text") for page in original_pdf).strip()
    with fitz.open(stream=cleaned, filetype="pdf") as cleaned_pdf:
        assert len(cleaned_pdf) == original_pages
        cleaned_text = "\n".join(page.get_text("text") for page in cleaned_pdf).strip()
    assert len(cleaned_text) > 0
    assert cleaned_text == original_text


@pytest.mark.parametrize(
    "shape", ["flat", "nested_mixed", "nested_alternative", "singlepart", "forwarded_message"]
)
def test_gateway_disarms_reviewed_pdf_at_every_mime_depth(
    tmp_path: Path, reviewed_fixture_scanner: MalPDFScannerEngine, shape: str
) -> None:
    original_pdf = load_real_threat_bytes()
    message = _mail_with_pdf(_pdf_attachment(original_pdf, "reviewed_threat.pdf"), shape)
    gateway = MailGatewayFilter(scanner_engine=reviewed_fixture_scanner, quarantine_dir=tmp_path / "quarantine")

    filtered, report = gateway.process_email_bytes(message.as_bytes())

    assert report.total_attachments == 1
    assert report.malicious_attachments == 1
    assert report.unavailable_attachments == 0
    assert report.action_taken == "DISARMED_AND_QUARANTINED"
    assert report.attachments[0].disarmed is True
    parsed = email.message_from_bytes(filtered)
    assert parsed["X-MalPDF-Inspection"] == "THREATS_DETECTED_AND_DISARMED"
    for header in ("From", "To", "Subject", "Message-ID"):
        assert parsed[header] == message[header]
    pdf_parts = [part for part in parsed.walk() if part.get_content_type() == "application/pdf"]
    assert len(pdf_parts) == 1
    for part in pdf_parts:
        cleaned_pdf = part.get_payload(decode=True)
        assert cleaned_pdf != original_pdf
        assert part["X-MalPDF-Sanitized"] == "TRUE"
        _assert_pdf_content_preserved(original_pdf, cleaned_pdf)
    assert not any(part.get_payload(decode=True) == original_pdf for part in parsed.walk())
    if shape != "singlepart":
        assert parsed.get_content_subtype() == "mixed"
        plain_bodies = [
            part.get_payload(decode=True) for part in parsed.walk() if part.get_content_type() == "text/plain"
        ]
        assert any(b"Preserved outer email body." in body for body in plain_bodies)
        assert any(
            part.get_filename() == "notes.txt" and part.get_payload(decode=True) == b"Preserved non-PDF attachment."
            for part in parsed.walk()
        )
    if shape in {"nested_mixed", "nested_alternative", "forwarded_message"}:
        assert any(
            part.get_content_type() == "text/html"
            and part.get_payload(decode=True) == b"<p>Preserved nested HTML body.</p>"
            for part in parsed.walk()
        )
    if shape == "forwarded_message":
        forwarded = next(part for part in parsed.walk() if part.get_content_type() == "message/rfc822")
        assert forwarded.get_payload()[0]["Subject"] == "Preserved forwarded subject"


def test_gateway_preserves_nested_reviewed_benign_pdf(
    tmp_path: Path, reviewed_fixture_scanner: MalPDFScannerEngine
) -> None:
    original_pdf = load_real_benign_bytes()
    message = _mail_with_pdf(_pdf_attachment(original_pdf, "reviewed_benign.pdf"), "nested_mixed")
    gateway = MailGatewayFilter(scanner_engine=reviewed_fixture_scanner, quarantine_dir=tmp_path / "quarantine")

    filtered, report = gateway.process_email_bytes(message.as_bytes())

    assert report.total_attachments == 1
    assert report.malicious_attachments == 0
    assert report.unavailable_attachments == 0
    assert report.action_taken == "PASSED"
    assert report.attachments[0].verdict == "BENIGN"
    assert report.attachments[0].disarmed is False
    parsed = email.message_from_bytes(filtered)
    part = next(part for part in parsed.walk() if part.get_filename() == "reviewed_benign.pdf")
    assert part.get_payload(decode=True) == original_pdf


@pytest.mark.parametrize("shape", ["flat", "nested_mixed", "singlepart"])
def test_gateway_holds_pdf_mime_part_with_missing_payload_for_review(
    tmp_path: Path, reviewed_fixture_scanner: MalPDFScannerEngine, shape: str
) -> None:
    attachment = _pdf_attachment(load_real_benign_bytes(), "missing_payload.pdf")
    attachment.set_payload("")
    message = _mail_with_pdf(attachment, shape)
    gateway = MailGatewayFilter(scanner_engine=reviewed_fixture_scanner, quarantine_dir=tmp_path / "quarantine")

    filtered, report = gateway.process_email_bytes(message.as_bytes())

    assert report.total_attachments == 1
    assert report.malicious_attachments == 0
    assert report.unavailable_attachments == 1
    assert report.action_taken == "HELD_FOR_REVIEW"
    assert report.attachments[0].verdict == "UNAVAILABLE"
    assert report.attachments[0].prediction_available is False
    assert report.attachments[0].prediction_blockers
    assert email.message_from_bytes(filtered)["X-MalPDF-Inspection"] == "REVIEW_REQUIRED"


def test_gateway_preserves_body_when_declared_text_charset_is_unknown(
    tmp_path: Path, reviewed_fixture_scanner: MalPDFScannerEngine
) -> None:
    original_pdf = load_real_threat_bytes()
    original_body = b"Preserved body from a legacy email client."
    message = MIMEMultipart("mixed")
    body = MIMEText(original_body.decode("ascii"), "plain")
    body.set_param("charset", "x-unknown-email-charset")
    message.attach(body)
    message.attach(_pdf_attachment(original_pdf, "reviewed_threat.pdf"))
    gateway = MailGatewayFilter(scanner_engine=reviewed_fixture_scanner, quarantine_dir=tmp_path / "quarantine")

    filtered, report = gateway.process_email_bytes(message.as_bytes())

    assert report.total_attachments == 1
    assert report.malicious_attachments == 1
    assert report.action_taken == "DISARMED_AND_QUARANTINED"
    assert report.attachments[0].disarmed is True
    parsed = email.message_from_bytes(filtered)
    plain_body = next(part for part in parsed.walk() if part.get_content_type() == "text/plain")
    assert original_body in plain_body.get_payload(decode=True)
    assert plain_body.get_content_charset() == "utf-8"
    assert parsed["X-MalPDF-Inspection"] == "THREATS_DETECTED_AND_DISARMED"
    pdf_parts = [part for part in parsed.walk() if part.get_content_type() == "application/pdf"]
    assert len(pdf_parts) == 1
    _assert_pdf_content_preserved(original_pdf, pdf_parts[0].get_payload(decode=True))

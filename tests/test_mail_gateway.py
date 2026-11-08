from __future__ import annotations

import email
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import io
from pathlib import Path

import pymupdf as fitz
import pikepdf

from malpdf.cdr.fixtures import load_real_threat_bytes
from malpdf.gateway.mail_filter import MailGatewayFilter


def create_sample_email(attachments: list[tuple[str, bytes]]) -> bytes:
    msg = MIMEMultipart()
    msg["From"] = "sender@corporate.com"
    msg["To"] = "employee@internal.net"
    msg["Subject"] = "Quarterly Business Review Report"
    msg["Message-ID"] = "<corp-test-12345@internal.net>"

    body = MIMEText("Please find the attached document for review.", "plain")
    msg.attach(body)

    for name, content in attachments:
        part = MIMEApplication(content, _subtype="pdf")
        part.add_header("Content-Disposition", "attachment", filename=name)
        msg.attach(part)

    return msg.as_bytes()


def test_mail_gateway_holds_unclassified_real_attachment(tmp_path: Path) -> None:
    threat_pdf = load_real_threat_bytes()
    with fitz.open(stream=threat_pdf, filetype="pdf") as orig_doc:
        orig_pages = len(orig_doc)
        orig_text = "\n".join(p.get_text() for p in orig_doc).strip()

    raw_email = create_sample_email([("invoice_exploit.pdf", threat_pdf)])

    quarantine_dir = tmp_path / "quarantine"
    gateway = MailGatewayFilter(quarantine_dir=quarantine_dir, device="cpu")

    filtered_bytes, report = gateway.process_email_bytes(raw_email)

    assert report.total_attachments == 1
    assert report.malicious_attachments == 1
    assert report.unavailable_attachments == 0
    assert report.action_taken == "DISARMED_AND_QUARANTINED"
    assert len(list(quarantine_dir.glob("*.pdf"))) == 1
    parsed = email.message_from_bytes(filtered_bytes)
    assert parsed["X-MalPDF-Inspection"] == "THREATS_DETECTED_AND_DISARMED"
    attachment = next(part for part in parsed.walk() if part.get_filename())
    retained = attachment.get_payload(decode=True)
    assert len(retained) > 0.8 * len(threat_pdf)
    with fitz.open(stream=retained, filetype="pdf") as clean_doc:
        assert len(clean_doc) == orig_pages
        assert "\n".join(p.get_text() for p in clean_doc).strip() == orig_text
    assert report.attachments[0].disarmed is True
    assert report.attachments[0].malware_probability is not None
    assert report.attachments[0].malware_probability >= 0.50

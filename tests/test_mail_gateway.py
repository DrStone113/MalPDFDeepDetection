from __future__ import annotations

import email
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import pymupdf as fitz

from malpdf.cdr.fixtures import load_real_benign_bytes, load_real_threat_bytes
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


def test_mail_gateway_quarantines_unreadable_and_unavailable_attachments_without_raw_pdf_leak(
    tmp_path: Path, monkeypatch
) -> None:
    corrupt_bytes = b"NOT-A-VALID-PDF-PAYLOAD-001122"
    raw_corrupt_email = create_sample_email([("corrupt.pdf", corrupt_bytes)])
    gateway = MailGatewayFilter(quarantine_dir=tmp_path / "q_err", device="cpu")
    filtered_err, rep_err = gateway.process_email_bytes(raw_corrupt_email)
    assert rep_err.unavailable_attachments == 1
    assert rep_err.action_taken == "HELD_FOR_REVIEW"
    assert corrupt_bytes not in filtered_err
    parsed_err = email.message_from_bytes(filtered_err)
    att_err = next(part for part in parsed_err.walk() if part.get_filename())
    assert att_err.get_filename() == "quarantined_corrupt.pdf.txt"
    assert att_err["X-MalPDF-Quarantined"] == "TRUE"

    benign_pdf = load_real_benign_bytes()
    orig_scan = gateway.scanner.scan_bytes

    def unavailable_scan(data: bytes, file_name: str = "sample.pdf", explain: bool = True, **kw):
        res = orig_scan(data, file_name=file_name, explain=explain, **kw)
        res.prediction_available = False
        res.verdict = "UNAVAILABLE"
        res.prediction_blockers = ["forced_test_blocker"]
        return res

    monkeypatch.setattr(gateway.scanner, "scan_bytes", unavailable_scan)
    filtered_unavail, rep_unavail = gateway.process_email_bytes(create_sample_email([("doc.pdf", benign_pdf)]))
    assert rep_unavail.unavailable_attachments == 1
    assert benign_pdf not in filtered_unavail
    parsed_unavail = email.message_from_bytes(filtered_unavail)
    att_unavail = next(part for part in parsed_unavail.walk() if part.get_filename())
    assert att_unavail.get_filename() == "quarantined_doc.pdf.txt"
    assert att_unavail["X-MalPDF-Reason"] == "PDF_PREDICTION_UNAVAILABLE"


def test_mail_gateway_post_cdr_rescan_failure_and_multi_attachment_worst_case(tmp_path: Path, monkeypatch) -> None:
    import importlib

    benign_pdf = load_real_benign_bytes()
    threat_pdf = load_real_threat_bytes()
    gateway = MailGatewayFilter(quarantine_dir=tmp_path / "q_multi", device="cpu")

    _, multi_rep = gateway.process_email_bytes(
        create_sample_email([("clean_first.pdf", benign_pdf), ("exploit_second.pdf", threat_pdf)])
    )
    assert multi_rep.total_attachments == 2
    assert multi_rep.malicious_attachments == 1
    for mod_name in ("malpdf.web.app", "production.web_service"):
        mod = importlib.import_module(mod_name)
        rec = mod._gateway_record(multi_rep, "eml-multi", "Multi Test", 0)
        assert rec["verdict"] == "MALICIOUS"
        assert rec["malware_probability"] is not None and rec["malware_probability"] >= 0.5
        assert "(+1 tệp)" in rec["attachment"]

    orig_scan = gateway.scanner.scan_bytes

    def fail_post_scan(data: bytes, file_name: str = "sample.pdf", explain: bool = True, **kw):
        res = orig_scan(data, file_name=file_name, explain=explain, **kw)
        if str(file_name).startswith("sanitized_"):
            res.verdict = "MALICIOUS"
            res.malware_probability = 0.93
        return res

    monkeypatch.setattr(gateway.scanner, "scan_bytes", fail_post_scan)
    filtered_res, rep_res = gateway.process_email_bytes(create_sample_email([("residual.pdf", threat_pdf)]))
    assert rep_res.action_taken == "QUARANTINED_ATTACHMENT"
    assert rep_res.attachments[0].disarmed is False
    parsed_res = email.message_from_bytes(filtered_res)
    att_res = next(part for part in parsed_res.walk() if part.get_filename())
    assert att_res.get_filename() == "quarantined_residual.pdf.txt"
    assert att_res["X-MalPDF-Quarantined"] == "TRUE"

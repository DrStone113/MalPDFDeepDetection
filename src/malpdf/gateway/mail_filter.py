from __future__ import annotations

from dataclasses import asdict, dataclass, field
import email
from email import encoders
from email.message import Message
from email.mime.application import MIMEApplication
import hashlib
from pathlib import Path
import time
from typing import TYPE_CHECKING, Any

from malpdf.cdr.engine import CDRAuditLog, PDFDisarmer

if TYPE_CHECKING:
    from malpdf.scanner.engine import MalPDFScannerEngine, ScanResult


@dataclass
class AttachmentInspection:
    filename: str
    sha256: str
    size_bytes: int
    verdict: str
    malware_probability: float | None
    is_ood: bool | None
    disarmed: bool
    quarantine_path: str | None = None
    cdr_audit: dict[str, Any] | None = None
    prediction_available: bool = True
    prediction_blockers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EmailInspectionReport:
    message_id: str
    subject: str
    sender: str
    recipient: str
    total_attachments: int
    malicious_attachments: int
    attachments: list[AttachmentInspection] = field(default_factory=list)
    action_taken: str = "PASSED"
    processing_latency_ms: float = 0.0
    unavailable_attachments: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class MailGatewayFilter:
    def __init__(
        self,
        scanner_engine: Any = None,
        disarmer: PDFDisarmer | None = None,
        quarantine_dir: Path | str = "data/quarantine",
        device: str = "cpu",
    ) -> None:
        if scanner_engine is None:
            from malpdf.scanner.engine import MalPDFScannerEngine

            scanner_engine = MalPDFScannerEngine(device=device)
        self.scanner = scanner_engine
        self.disarmer = disarmer or PDFDisarmer()
        self.quarantine_dir = Path(quarantine_dir)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

    def process_email_bytes(self, raw_email_bytes: bytes) -> tuple[bytes, EmailInspectionReport]:
        start_time = time.perf_counter()
        msg = email.message_from_bytes(raw_email_bytes)

        message_id = msg.get("Message-ID", "unknown-mid")
        subject = msg.get("Subject", "No Subject")
        sender = msg.get("From", "unknown-sender")
        recipient = msg.get("To", "unknown-recipient")

        inspections: list[AttachmentInspection] = []
        malicious_count = 0
        unavailable_count = 0
        visited_parts = 0

        def inspect_part(part: Message, depth: int = 0) -> Message:
            nonlocal malicious_count, unavailable_count, visited_parts
            visited_parts += 1
            if depth > 64 or visited_parts > 1000:
                raise ValueError("mime_traversal_limit")
            if part.is_multipart():
                part.set_payload([inspect_part(child, depth + 1) for child in part.get_payload()])
                return part
            filename = part.get_filename() or ""
            if not (filename.lower().endswith(".pdf") or part.get_content_type() == "application/pdf"):
                return part
            pdf_bytes = part.get_payload(decode=True) or b""
            sha256 = hashlib.sha256(pdf_bytes).hexdigest()
            try:
                if not pdf_bytes:
                    raise ValueError("pdf_attachment_payload_missing")
                scan_res = self.scanner.scan_bytes(pdf_bytes, file_name=filename, explain=True)
            except (ValueError, RuntimeError):
                unavailable_count += 1
                inspections.append(AttachmentInspection(
                    filename=filename, sha256=sha256, size_bytes=len(pdf_bytes),
                    verdict="UNAVAILABLE", malware_probability=None, is_ood=None,
                    disarmed=False, prediction_available=False,
                    prediction_blockers=["pdf_attachment_unreadable" if pdf_bytes else "pdf_attachment_payload_missing"],
                ))
                return part
            if not scan_res.prediction_available:
                unavailable_count += 1
                inspections.append(AttachmentInspection(
                    filename=filename, sha256=sha256, size_bytes=len(pdf_bytes),
                    verdict="UNAVAILABLE", malware_probability=None, is_ood=None,
                    disarmed=False, prediction_available=False,
                    prediction_blockers=scan_res.prediction_blockers,
                ))
                return part
            audit = None
            q_path = None
            if scan_res.verdict == "MALICIOUS":
                malicious_count += 1
                q_path = self.quarantine_dir / f"{sha256}.pdf"
                q_path.write_bytes(pdf_bytes)
                sanitized_bytes, audit = self.disarmer.sanitize_bytes(pdf_bytes, file_name=filename)
                replacement = MIMEApplication(sanitized_bytes, _subtype="pdf")
                for key, value in part.items():
                    if key.lower() not in {
                        "content-type", "content-transfer-encoding", "content-disposition", "mime-version",
                        "x-malpdf-sanitized", "x-malpdf-original-sha256",
                    }:
                        replacement[key] = value
                replacement.add_header("Content-Disposition", "attachment", filename=f"sanitized_{filename or 'attachment.pdf'}")
                replacement.add_header("X-MalPDF-Sanitized", "TRUE")
                replacement.add_header("X-MalPDF-Original-SHA256", sha256)
                part = replacement
            inspections.append(AttachmentInspection(
                filename=filename, sha256=sha256, size_bytes=len(pdf_bytes),
                verdict=scan_res.verdict, malware_probability=scan_res.malware_probability,
                is_ood=scan_res.is_ood, disarmed=audit is not None,
                quarantine_path=str(q_path.resolve()) if q_path is not None else None,
                cdr_audit=audit.to_dict() if audit is not None else None,
            ))
            return part

        msg = inspect_part(msg)
        for header in ("X-MalPDF-Inspection", "X-MalPDF-Unavailable-Count", "X-MalPDF-Malicious-Count", "X-MalPDF-Gateway-Latency-MS"):
            del msg[header]

        latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        action_taken = "HELD_FOR_REVIEW" if unavailable_count else "DISARMED_AND_QUARANTINED" if malicious_count > 0 else "PASSED"

        if unavailable_count:
            msg["X-MalPDF-Inspection"] = "REVIEW_REQUIRED"
            msg["X-MalPDF-Unavailable-Count"] = str(unavailable_count)
        elif malicious_count > 0:
            msg["X-MalPDF-Inspection"] = "THREATS_DETECTED_AND_DISARMED"
            msg["X-MalPDF-Malicious-Count"] = str(malicious_count)
            msg["X-MalPDF-Gateway-Latency-MS"] = f"{latency_ms:.2f}"
            warning_banner = (
                f"\n\n[SECURITY ALERT: MalPDF Enterprise Gateway detected {malicious_count} active "
                f"malicious PDF attachment(s). Original payload was quarantined and replaced with a sanitized PDF.]\n"
            )
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    orig_body = part.get_payload(decode=True) or b""
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        body_text = orig_body.decode(charset, errors="replace")
                    except LookupError:
                        body_text = orig_body.decode("utf-8", errors="replace")
                    part.set_payload((warning_banner + body_text).encode("utf-8"))
                    part.set_param("charset", "utf-8")
                    del part["Content-Transfer-Encoding"]
                    encoders.encode_base64(part)
                    break
        else:
            msg["X-MalPDF-Inspection"] = "CLEAN"
            msg["X-MalPDF-Gateway-Latency-MS"] = f"{latency_ms:.2f}"

        report = EmailInspectionReport(
            message_id=message_id,
            subject=subject,
            sender=sender,
            recipient=recipient,
            total_attachments=len(inspections),
            malicious_attachments=malicious_count,
            attachments=inspections,
            action_taken=action_taken,
            processing_latency_ms=latency_ms,
            unavailable_attachments=unavailable_count,
        )

        return msg.as_bytes(), report

    def inspect_eml_bytes(self, raw_email_bytes: bytes) -> tuple[bytes, EmailInspectionReport]:
        return self.process_email_bytes(raw_email_bytes)

    def inspect_eml_file(self, eml_path: Path | str) -> tuple[bytes, EmailInspectionReport]:
        return self.process_email_bytes(Path(eml_path).read_bytes())

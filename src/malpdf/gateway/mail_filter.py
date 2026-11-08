from __future__ import annotations

from dataclasses import asdict, dataclass, field
import email
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
        modified = False

        if msg.is_multipart():
            new_payload = []
            for part in msg.get_payload():
                content_disposition = str(part.get("Content-Disposition", ""))
                content_type = str(part.get_content_type())
                filename = part.get_filename() or ""

                is_pdf = filename.lower().endswith(".pdf") or content_type == "application/pdf"
                if not is_pdf:
                    new_payload.append(part)
                    continue

                pdf_bytes = part.get_payload(decode=True)
                if not pdf_bytes:
                    new_payload.append(part)
                    continue

                sha256 = hashlib.sha256(pdf_bytes).hexdigest()
                scan_res = self.scanner.scan_bytes(pdf_bytes, file_name=filename, explain=True)

                if not scan_res.prediction_available:
                    unavailable_count += 1
                    new_payload.append(part)
                    inspections.append(AttachmentInspection(
                        filename=filename, sha256=sha256, size_bytes=len(pdf_bytes),
                        verdict="UNAVAILABLE", malware_probability=None, is_ood=None,
                        disarmed=False, prediction_available=False,
                        prediction_blockers=scan_res.prediction_blockers,
                    ))
                    continue

                if scan_res.verdict == "MALICIOUS":
                    malicious_count += 1
                    modified = True

                    q_path = self.quarantine_dir / f"{sha256}_{filename}"
                    q_path.write_bytes(pdf_bytes)

                    sanitized_bytes, audit = self.disarmer.sanitize_bytes(pdf_bytes)

                    sanitized_part = MIMEApplication(sanitized_bytes, _subtype="pdf")
                    sanitized_name = f"sanitized_{filename}"
                    sanitized_part.add_header("Content-Disposition", "attachment", filename=sanitized_name)
                    sanitized_part.add_header("X-MalPDF-Sanitized", "TRUE")
                    sanitized_part.add_header("X-MalPDF-Original-SHA256", sha256)
                    new_payload.append(sanitized_part)

                    inspections.append(
                        AttachmentInspection(
                            filename=filename,
                            sha256=sha256,
                            size_bytes=len(pdf_bytes),
                            verdict=scan_res.verdict,
                            malware_probability=scan_res.malware_probability,
                            is_ood=scan_res.is_ood,
                            disarmed=True,
                            quarantine_path=str(q_path.resolve()),
                            cdr_audit=audit.to_dict(),
                        )
                    )
                else:
                    new_payload.append(part)
                    inspections.append(
                        AttachmentInspection(
                            filename=filename,
                            sha256=sha256,
                            size_bytes=len(pdf_bytes),
                            verdict=scan_res.verdict,
                            malware_probability=scan_res.malware_probability,
                            is_ood=scan_res.is_ood,
                            disarmed=False,
                            quarantine_path=None,
                            cdr_audit=None,
                        )
                    )
            msg.set_payload(new_payload)

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
                    part.set_payload((warning_banner + orig_body.decode(errors="replace")).encode("utf-8"))
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

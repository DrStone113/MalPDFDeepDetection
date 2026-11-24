from __future__ import annotations

from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
import email
from email import encoders
from email.header import decode_header, make_header
from email.message import Message
from email.mime.application import MIMEApplication
from email.mime.text import MIMEText
import hashlib
from html import unescape
from itertools import islice
from pathlib import Path
import re
import time
from typing import TYPE_CHECKING, Any
import unicodedata

from malpdf.cdr.engine import PDFDisarmer

if TYPE_CHECKING:
    pass


_PASSWORD_CUE = re.compile(
    r"""\b(?:password|passwd|passcode|pwd|pass|mat\s+khau(?:\s+mo\s+tep)?|ma\s+mo\s+tep|mk)"""
    r"""\s*(?::|=|-|\bis\b|\bla\b)\s*["'`]?([^\s"'`<>,;]{1,64})(?![^\s"'`<>,;])""",
    re.IGNORECASE,
)
_PASSWORD_BODY_LIMIT = 64 * 1024
_HTML_TAG = re.compile(r"<[^<>]*>")


def _decoded_subject(subject: str) -> str:
    subject = subject[:_PASSWORD_BODY_LIMIT]
    try:
        return str(make_header(decode_header(subject)))
    except (LookupError, ValueError):
        return subject


def _password_value_spans(text: str) -> Iterator[tuple[int, int]]:
    if text.isascii():
        for match in _PASSWORD_CUE.finditer(text):
            yield match.span(1)
        return
    offsets = []
    chars = []
    for index, char in enumerate(text):
        for unit in unicodedata.normalize("NFD", char.replace("đ", "d").replace("Đ", "D")):
            if unicodedata.category(unit) != "Mn":
                chars.append(unit)
                offsets.append(index)
    offsets.append(len(text))
    # Match normalized labels while retaining the original password bytes.
    for match in _PASSWORD_CUE.finditer("".join(chars)):
        start, end = match.span(1)
        yield offsets[start], offsets[end]


def extract_email_password_candidates(msg: Message) -> list[str]:
    texts = [_decoded_subject(str(msg.get("Subject", "")))]
    remaining = _PASSWORD_BODY_LIMIT
    for part in islice(msg.walk(), 1000):
        content_type = part.get_content_type()
        if content_type not in {"text/plain", "text/html"} or part.get_content_disposition() == "attachment":
            continue
        body = (part.get_payload(decode=True) or b"")[:remaining]
        remaining -= len(body)
        try:
            text = body.decode(part.get_content_charset() or "utf-8", errors="replace")
        except LookupError:
            text = body.decode("utf-8", errors="replace")
        texts.append(unescape(_HTML_TAG.sub(" ", text)) if content_type == "text/html" else text)
        if not remaining:
            break

    candidates: dict[str, None] = {}
    for text in texts:
        for start, end in _password_value_spans(text):
            candidate = text[start:end]
            if 0 < len(candidate) <= 64:
                candidates[candidate] = None
            if len(candidates) == 8:
                return list(candidates)
    return list(candidates)


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
    unlocked_from_email_body: bool = False

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
        quarantine_password_locked: bool = True,
    ) -> None:
        if scanner_engine is None:
            from malpdf.scanner.engine import MalPDFScannerEngine

            scanner_engine = MalPDFScannerEngine(device=device)
        self.scanner = scanner_engine
        self.disarmer = disarmer or PDFDisarmer()
        self.quarantine_dir = Path(quarantine_dir)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.quarantine_password_locked = quarantine_password_locked

    def process_email_bytes(self, raw_email_bytes: bytes) -> tuple[bytes, EmailInspectionReport]:
        start_time = time.perf_counter()
        msg = email.message_from_bytes(raw_email_bytes)

        message_id = msg.get("Message-ID", "unknown-mid")
        subject = msg.get("Subject", "No Subject")
        sender = msg.get("From", "unknown-sender")
        recipient = msg.get("To", "unknown-recipient")

        inspections: list[AttachmentInspection] = []
        malicious_count = 0
        quarantined_only_count = 0
        password_locked_count = 0
        unavailable_count = 0
        visited_parts = 0
        password_candidates: list[str] | None = None

        def inspect_part(part: Message, depth: int = 0) -> Message:
            nonlocal malicious_count, quarantined_only_count, password_locked_count, unavailable_count, visited_parts
            nonlocal password_candidates
            visited_parts += 1
            if depth > 64 or visited_parts > 1000:
                raise ValueError("mime_traversal_limit")
            if part.is_multipart():
                part.set_payload([inspect_part(child, depth + 1) for child in part.get_payload()])
                return part
            filename = part.get_filename() or ""
            if not (filename.lower().endswith(".pdf") or part.get_content_type() == "application/pdf"):
                return part
            del part["X-MalPDF-Unlocked-From-Email"]
            pdf_bytes = part.get_payload(decode=True) or b""
            sha256 = hashlib.sha256(pdf_bytes).hexdigest()
            try:
                if not pdf_bytes:
                    raise ValueError("pdf_attachment_payload_missing")
                scan_res = self.scanner.scan_bytes(pdf_bytes, file_name=filename, explain=True)
            except (ValueError, RuntimeError):
                unavailable_count += 1
                inspections.append(
                    AttachmentInspection(
                        filename=filename,
                        sha256=sha256,
                        size_bytes=len(pdf_bytes),
                        verdict="UNAVAILABLE",
                        malware_probability=None,
                        is_ood=None,
                        disarmed=False,
                        prediction_available=False,
                        prediction_blockers=[
                            "pdf_attachment_unreadable" if pdf_bytes else "pdf_attachment_payload_missing"
                        ],
                    )
                )
                return part
            locked = scan_res.forensic_dossier.get("encryption_analysis", {}).get("password_locked", False)
            password = None
            if locked:
                if password_candidates is None:
                    password_candidates = extract_email_password_candidates(msg)
                for candidate in password_candidates:
                    try:
                        retry = self.scanner.scan_bytes(pdf_bytes, file_name=filename, explain=True, password=candidate)
                    except (ValueError, RuntimeError):
                        continue
                    if retry.prediction_available and not retry.forensic_dossier.get("encryption_analysis", {}).get(
                        "password_locked", True
                    ):
                        scan_res, locked, password = retry, False, candidate
                        break
            malicious = scan_res.verdict == "MALICIOUS"
            quarantine_locked = locked and (self.quarantine_password_locked or malicious)
            if not scan_res.prediction_available and not quarantine_locked:
                unavailable_count += 1
                inspections.append(
                    AttachmentInspection(
                        filename=filename,
                        sha256=sha256,
                        size_bytes=len(pdf_bytes),
                        verdict="UNAVAILABLE",
                        malware_probability=None,
                        is_ood=None,
                        disarmed=False,
                        prediction_available=False,
                        prediction_blockers=scan_res.prediction_blockers,
                    )
                )
                return part
            audit = None
            q_path = None
            disarmed = False
            if malicious or quarantine_locked:
                malicious_count += int(malicious)
                q_path = self.quarantine_dir / f"{sha256}.pdf"
                q_path.write_bytes(pdf_bytes)
                if quarantine_locked:
                    password_locked_count += 1
                else:
                    try:
                        sanitized_bytes, audit = self.disarmer.sanitize_bytes(
                            pdf_bytes, file_name=filename, password=password
                        )
                        disarmed = audit.is_sanitized and not audit.quarantine_recommended
                    except (ValueError, RuntimeError):
                        pass
                if disarmed:
                    replacement = MIMEApplication(sanitized_bytes, _subtype="pdf")
                    replacement_name = f"sanitized_{filename or 'attachment.pdf'}"
                    status_header = "X-MalPDF-Sanitized"
                else:
                    quarantined_only_count += int(malicious)
                    if quarantine_locked:
                        reason = "PASSWORD_LOCKED_UNINSPECTABLE"
                    elif audit and audit.residual_qr_anomalies:
                        reason = "A suspicious QR code requires quarantine."
                    elif audit and audit.residual_codec_anomalies:
                        reason = "Residual resource or codec anomalies require quarantine."
                    else:
                        reason = "Content disarm could not verify a clean PDF."
                    replacement = MIMEText(f"The original PDF (SHA-256 {sha256}) was quarantined. {reason}", "plain")
                    replacement_name = f"quarantined_{filename or 'attachment.pdf'}.txt"
                    status_header = "X-MalPDF-Quarantined"
                for key, value in part.items():
                    if key.lower() not in {
                        "content-type",
                        "content-transfer-encoding",
                        "content-disposition",
                        "mime-version",
                        "x-malpdf-sanitized",
                        "x-malpdf-quarantined",
                        "x-malpdf-reason",
                        "x-malpdf-original-sha256",
                    }:
                        replacement[key] = value
                replacement.add_header("Content-Disposition", "attachment", filename=replacement_name)
                replacement.add_header(status_header, "TRUE")
                replacement.add_header("X-MalPDF-Original-SHA256", sha256)
                if quarantine_locked:
                    replacement.add_header("X-MalPDF-Reason", reason)
                part = replacement
            if password is not None:
                part["X-MalPDF-Unlocked-From-Email"] = "TRUE"
            inspections.append(
                AttachmentInspection(
                    filename=filename,
                    sha256=sha256,
                    size_bytes=len(pdf_bytes),
                    verdict=scan_res.verdict,
                    malware_probability=scan_res.malware_probability,
                    is_ood=scan_res.is_ood,
                    disarmed=disarmed,
                    quarantine_path=str(q_path.resolve()) if q_path is not None else None,
                    cdr_audit=audit.to_dict() if audit is not None else None,
                    prediction_available=scan_res.prediction_available,
                    prediction_blockers=scan_res.prediction_blockers,
                    unlocked_from_email_body=password is not None,
                )
            )
            return part

        msg = inspect_part(msg)
        if password_candidates is not None:
            decoded_subject = _decoded_subject(subject)
            spans = list(_password_value_spans(decoded_subject))
            for start, end in reversed(spans):
                decoded_subject = decoded_subject[:start] + "[redacted]" + decoded_subject[end:]
            if spans:
                subject = decoded_subject
        for header in (
            "X-MalPDF-Inspection",
            "X-MalPDF-Unavailable-Count",
            "X-MalPDF-Malicious-Count",
            "X-MalPDF-Gateway-Latency-MS",
        ):
            del msg[header]

        latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        if unavailable_count:
            action_taken = "HELD_FOR_REVIEW"
            msg["X-MalPDF-Inspection"] = "REVIEW_REQUIRED"
            msg["X-MalPDF-Unavailable-Count"] = str(unavailable_count)
        elif malicious_count or password_locked_count:
            if password_locked_count:
                action_taken = "QUARANTINED_PASSWORD_LOCKED"
                msg["X-MalPDF-Inspection"] = "THREATS_QUARANTINED"
                attachment_status = f"{password_locked_count} tệp PDF bị khóa bằng mật khẩu đã được cách ly."
            elif quarantined_only_count:
                action_taken = "QUARANTINED_ATTACHMENT"
                msg["X-MalPDF-Inspection"] = "THREATS_QUARANTINED"
                attachment_status = (
                    f"{quarantined_only_count} tệp phải cách ly, "
                    f"{malicious_count - quarantined_only_count} tệp có bản đã làm sạch."
                )
            else:
                action_taken = "DISARMED_AND_QUARANTINED"
                msg["X-MalPDF-Inspection"] = "THREATS_DETECTED_AND_DISARMED"
                attachment_status = "Bản gốc đã được cách ly và thay thế bằng bản đã làm sạch."
            msg["X-MalPDF-Malicious-Count"] = str(malicious_count)
            msg["X-MalPDF-Gateway-Latency-MS"] = f"{latency_ms:.2f}"
            warning_banner = (
                f"\n\n[CẢNH BÁO BẢO MẬT - MalPDF DeepDetection. {attachment_status}]\n"
                if password_locked_count
                else f"\n\n[CẢNH BÁO BẢO MẬT - MalPDF DeepDetection: Đã phát hiện {malicious_count} tệp PDF "
                f"vượt ngưỡng cảnh báo. {attachment_status}]\n"
            )
            for part in msg.walk():
                if part.get_content_type() == "text/plain" and part.get_content_disposition() != "attachment":
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
            action_taken = "PASSED"
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

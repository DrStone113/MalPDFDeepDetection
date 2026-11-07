from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import threading
from typing import TYPE_CHECKING, Any
import uuid

from malpdf.cdr.engine import CDRAuditLog

if TYPE_CHECKING:
    from malpdf.scanner.engine import ScanResult


@dataclass
class ScanJob:
    scan_id: str
    file_name: str
    raw_bytes: bytes
    file_size_bytes: int
    sha256: str
    created_at: str
    status: str = "PENDING"
    batch_id: str | None = None
    scan_result: ScanResult | None = None
    sanitized_bytes: bytes | None = None
    cdr_audit: CDRAuditLog | None = None
    error_message: str | None = None

    def to_summary(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "file_name": self.file_name,
            "file_size_bytes": self.file_size_bytes,
            "sha256": self.sha256,
            "created_at": self.created_at,
            "status": self.status,
            "batch_id": self.batch_id,
            "verdict": self.scan_result.verdict if self.scan_result else "PENDING",
            "malware_probability": self.scan_result.malware_probability if self.scan_result else None,
            "has_sanitized": self.sanitized_bytes is not None,
            "error_message": self.error_message,
        }

    def to_detail(self) -> dict[str, Any]:
        data = self.to_summary()
        data["scan_result"] = self.scan_result.to_dict() if self.scan_result else None
        data["cdr_audit"] = self.cdr_audit.to_dict() if self.cdr_audit else None
        return data


class ScanJobStore:
    def __init__(self, max_jobs: int = 200, quarantine_dir: Path | str = "data/quarantine") -> None:
        self._max_jobs = max_jobs
        self._jobs: dict[str, ScanJob] = {}
        self._lock = threading.RLock()
        self._quarantine_dir = Path(quarantine_dir)
        self._quarantine_dir.mkdir(parents=True, exist_ok=True)
        self._audit_logs: deque[dict[str, Any]] = deque(maxlen=500)

    def create_job(self, raw_bytes: bytes, file_name: str, batch_id: str | None = None) -> ScanJob:
        with self._lock:
            scan_id = f"job-{uuid.uuid4().hex[:12]}"
            sha256 = hashlib.sha256(raw_bytes).hexdigest()
            created_at = datetime.now(timezone.utc).isoformat()
            job = ScanJob(
                scan_id=scan_id,
                file_name=file_name,
                raw_bytes=raw_bytes,
                file_size_bytes=len(raw_bytes),
                sha256=sha256,
                created_at=created_at,
                status="PENDING",
                batch_id=batch_id,
            )
            if len(self._jobs) >= self._max_jobs:
                oldest_id = next(iter(self._jobs))
                del self._jobs[oldest_id]
            self._jobs[scan_id] = job
            self.record_audit("JOB_CREATED", {"scan_id": scan_id, "file_name": file_name, "sha256": sha256})
            return job

    def get_job(self, scan_id: str) -> ScanJob | None:
        with self._lock:
            return self._jobs.get(scan_id)

    def list_jobs(self, batch_id: str | None = None, limit: int = 50) -> list[ScanJob]:
        with self._lock:
            jobs = list(self._jobs.values())
            if batch_id is not None:
                jobs = [j for j in jobs if j.batch_id == batch_id]
            jobs.sort(key=lambda j: j.created_at, reverse=True)
            return jobs[:limit]

    def set_status(self, scan_id: str, status: str, error: str | None = None) -> None:
        with self._lock:
            job = self._jobs.get(scan_id)
            if job is not None:
                job.status = status
                job.error_message = error
                self.record_audit(
                    "STATUS_CHANGED",
                    {
                        "scan_id": scan_id,
                        "file_name": job.file_name,
                        "status": status,
                        "action": f"Trạng thái: {status}",
                        "error": error,
                    },
                )

    def attach_scan_result(self, scan_id: str, scan_result: ScanResult) -> None:
        with self._lock:
            job = self._jobs.get(scan_id)
            if job is not None:
                job.scan_result = scan_result
                job.status = "SCANNED"
                self.record_audit(
                    "SCAN_COMPLETED",
                    {
                        "scan_id": scan_id,
                        "verdict": scan_result.verdict,
                        "malware_probability": scan_result.malware_probability,
                        "latency_ms": scan_result.latency_ms,
                        "file_name": job.file_name,
                        "action": "Phát hiện mã độc" if scan_result.verdict == "MALICIOUS" else "Kiểm tra an toàn",
                    },
                )
                if scan_result.verdict == "MALICIOUS":
                    self.quarantine_bytes(job.raw_bytes, job.file_name, job.sha256)

    def attach_sanitized(self, scan_id: str, sanitized_bytes: bytes, cdr_audit: CDRAuditLog) -> None:
        with self._lock:
            job = self._jobs.get(scan_id)
            if job is not None:
                job.sanitized_bytes = sanitized_bytes
                job.cdr_audit = cdr_audit
                job.status = "DISARMED"
                self.record_audit(
                    "DISARM_COMPLETED",
                    {
                        "scan_id": scan_id,
                        "file_name": job.file_name,
                        "verdict": "BENIGN",
                        "sanitized_pages": cdr_audit.sanitized_pages,
                        "neutralized_scripts": cdr_audit.neutralized_scripts,
                        "latency_ms": cdr_audit.disarm_latency_ms,
                        "action": f"Đã gỡ {len(cdr_audit.removed_triggers)} thành phần nguy hiểm",
                    },
                )

    def delete_job(self, scan_id: str) -> bool:
        with self._lock:
            if scan_id in self._jobs:
                fname = self._jobs[scan_id].file_name
                del self._jobs[scan_id]
                self.record_audit(
                    "JOB_DELETED",
                    {"scan_id": scan_id, "file_name": fname, "action": "Đã xóa khỏi lịch sử"},
                )
                return True
            return False

    def quarantine_bytes(self, raw_bytes: bytes, file_name: str, sha256: str) -> Path:
        safe_name = f"{sha256[:16]}_{Path(file_name).name}"
        target_path = self._quarantine_dir / safe_name
        target_path.write_bytes(raw_bytes)
        self.record_audit(
            "QUARANTINE_ISOLATED",
            {
                "file_name": file_name,
                "verdict": "MALICIOUS",
                "sha256": sha256,
                "path": str(target_path),
                "action": "Đã lưu vào khu cách ly",
            },
        )
        return target_path

    def list_quarantine(self) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        if not self._quarantine_dir.exists():
            return entries
        for p in self._quarantine_dir.glob("*"):
            if p.is_file():
                stat = p.stat()
                parts = p.name.split("_", 1)
                sha_prefix = parts[0] if len(parts) > 1 else ""
                orig_name = parts[1] if len(parts) > 1 else p.name
                entries.append({
                    "file_name": orig_name,
                    "stored_name": p.name,
                    "sha256_prefix": sha_prefix,
                    "size_bytes": stat.st_size,
                    "quarantined_at": datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),
                    "path": str(p),
                })
        entries.sort(key=lambda x: x["quarantined_at"], reverse=True)
        return entries

    def get_quarantine_bytes(self, stored_name: str) -> bytes | None:
        target = (self._quarantine_dir / stored_name).resolve()
        if not str(target).startswith(str(self._quarantine_dir.resolve())):
            return None
        if target.is_file():
            return target.read_bytes()
        return None

    def record_audit(self, event_type: str, details: dict[str, Any]) -> None:
        entry = {
            "event_id": uuid.uuid4().hex,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event_type,
            "details": details,
        }
        self._audit_logs.appendleft(entry)

    def get_audit_logs(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._audit_logs)[:limit]


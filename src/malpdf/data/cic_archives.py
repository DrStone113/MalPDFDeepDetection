"""Bounded traversal of manually acquired CIC ZIP containers; PDF bytes stay inert."""

import hashlib
from pathlib import Path
import time
import zipfile

from malpdf.data.cic_normalization import bounded_archive_checksum
from malpdf.data.raw_downloads import AcquisitionError, extract_pdf_archive, inspect_zip_directory


def extract_nested_cic_archive(path, destination, limits, ledger, *, record=lambda entry: None,
                               progress=lambda **counts: None, depth=0):
    """Allow at most two nested levels; leave passwordless encrypted inputs unavailable."""
    if depth > 2:
        raise AcquisitionError("CIC nested ZIP depth exceeds two levels")
    members = inspect_zip_directory(path, limits)
    ledger["members"] += len(members)
    if ledger["members"] > 40_000:
        raise AcquisitionError("CIC ZIP tree exceeds its cumulative member cap")
    checksum = bounded_archive_checksum(path, ledger["boundary"], limits.max_download_bytes)
    if checksum["sha256"] in ledger["seen_archives"]:
        record({"archive": str(path), "status": "duplicate_archive", **checksum})
        return {"accepted": 0, "rejected": 0, "duplicates": 0, "pdf_bytes": 0, "blocked_archives": 0, "duplicate_archives": 1}
    if any(m.flag_bits & 1 for m in members):
        record({"archive": str(path), "status": "encrypted_archive_no_password", **checksum})
        return {"accepted": 0, "rejected": 0, "duplicates": 0, "pdf_bytes": 0, "blocked_archives": 1, "duplicate_archives": 0}
    ledger["seen_archives"].add(checksum["sha256"])
    files = [m for m in members if not m.is_dir()]
    containers = [m for m in files if Path(m.filename).suffix.lower() == ".zip"]
    if containers and len(containers) != len(files):
        raise AcquisitionError("Mixed ZIP containers and PDF members are unsupported")
    if not containers:
        def member_record(entry):
            record({"archive": str(path), **entry})
        result = extract_pdf_archive(path, destination / "pdfs", limits,
            remaining_bytes=limits.max_total_pdf_bytes - ledger["pdf_bytes"], record=member_record)
        ledger["pdf_bytes"] += result["pdf_bytes"]
        result.update(blocked_archives=0, duplicate_archives=0)
    else:
        if depth == 2:
            raise AcquisitionError("CIC nested ZIP depth exceeds two levels")
        if any(m.file_size > limits.max_download_bytes or m.file_size > max(1, m.compress_size) * limits.max_compression_ratio for m in containers):
            raise AcquisitionError("CIC nested ZIP exceeds its size/compression cap")
        if sum(m.file_size for m in containers) + ledger["container_bytes"] > limits.max_total_download_bytes:
            raise AcquisitionError("CIC nested ZIPs exceed their cumulative byte cap")
        folder = destination / "containers"
        folder.mkdir(exist_ok=True)
        result = {key: 0 for key in ("accepted", "rejected", "duplicates", "pdf_bytes", "blocked_archives", "duplicate_archives")}
        with zipfile.ZipFile(path) as archive:
            for member in containers:
                ledger["container_count"] += 1
                target = folder / f"child_{ledger['container_count']:04d}.zip"
                digest, total, started = hashlib.sha256(), 0, time.monotonic()
                with archive.open(member) as content, target.open("xb") as output:
                    header = content.read(4)
                    if header != b"PK\x03\x04":
                        raise AcquisitionError("CIC nested member fails ZIP magic")
                    output.write(header)
                    digest.update(header)
                    total = len(header)
                    while chunk := content.read(min(64 * 1024, limits.max_download_bytes - total + 1)):
                        total += len(chunk)
                        if total > limits.max_download_bytes or time.monotonic() - started > limits.max_transfer_seconds:
                            raise AcquisitionError("CIC nested ZIP exceeds its byte/deadline cap")
                        output.write(chunk)
                        digest.update(chunk)
                if total != member.file_size:
                    raise AcquisitionError("CIC nested ZIP is truncated")
                ledger["container_bytes"] += total
                record({"archive": str(path), "member": member.filename, "status": "nested_zip_crc_verified",
                        "output": str(target), "sha256": digest.hexdigest(), "bytes": total})
                summary = extract_nested_cic_archive(target, destination, limits, ledger, record=record,
                    progress=progress, depth=depth + 1)
                for key in result:
                    result[key] += summary[key]
                progress(containers=ledger["container_count"], directory_members=ledger["members"],
                         accepted=result["accepted"], rejected=result["rejected"])
    if bounded_archive_checksum(path, ledger["boundary"], limits.max_download_bytes) != checksum:
        raise AcquisitionError("CIC ZIP changed during traversal")
    return result

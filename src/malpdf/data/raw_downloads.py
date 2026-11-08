"""Explicitly authorized, bounded acquisition of opaque PDF bytes over HTTPS.

No PDF parser, viewer, remote scanner, source code or embedded action is invoked.
Only validated bytes are published as PDFs; detailed identities stay ignored.
"""

from __future__ import annotations

import csv
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import socket
import stat
import struct
import subprocess
import tempfile
import time
import tomllib
from urllib.parse import urlsplit, parse_qsl
from urllib.request import Request, HTTPRedirectHandler, build_opener
import zipfile
import zlib

from malpdf.data.rit_pdfmal import sha256_file
from malpdf.experiments.protocol_p import repository_git_state
from malpdf.static.safety import read_bounded_bytes


class AcquisitionError(ValueError):
    """The requested source or its bytes failed a closed safety check."""


@dataclass(frozen=True)
class DownloadLimits:
    max_pdf_bytes: int = 10 * 1024 * 1024
    max_download_bytes: int = 256 * 1024 * 1024
    max_total_download_bytes: int = 512 * 1024 * 1024
    max_total_pdf_bytes: int = 1024 * 1024 * 1024
    max_archive_members: int = 20_000
    max_compression_ratio: int = 200
    timeout_seconds: int = 30
    max_transfer_seconds: int = 600

    def __post_init__(self):
        if any(type(v) is not int or v <= 0 for v in asdict(self).values()):
            raise AcquisitionError("Resource limits must be positive integers")


def validate_url(url: str, allowed_hosts: list[str], *, resolve: bool = False) -> None:
    if not isinstance(url, str) or len(url) > 4096 or any(ord(c) < 33 for c in url):
        raise AcquisitionError("Invalid public HTTPS URL")
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname not in allowed_hosts
            or parsed.port not in (None, 443) or parsed.username or parsed.password
            or parsed.fragment):
        raise AcquisitionError("Require HTTPS on an explicitly reviewed host without credentials")
    if any(re.search(r"token|secret|password|signature|credential|api.?key", k, re.I)
           for k, _ in parse_qsl(parsed.query)):
        raise AcquisitionError("Credential-bearing URLs are not allowed")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        if parsed.hostname == "localhost" or parsed.hostname.endswith((".localhost", ".local")):
            raise AcquisitionError("Local hosts are not allowed")
    else:
        if not address.is_global:
            raise AcquisitionError("Nonpublic IP addresses are not allowed")
    if resolve:
        addresses = socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)
        if not addresses or any(not ipaddress.ip_address(item[4][0]).is_global for item in addresses):
            raise AcquisitionError("Host resolves to a nonpublic address")


class _ReviewedRedirects(HTTPRedirectHandler):
    def __init__(self, hosts):
        self.hosts = hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(newurl, self.hosts, resolve=True)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def validate_configuration(config: dict) -> None:
    if not isinstance(config, dict) or set(config) != {"allowed_hosts", "limits", "sources"}:
        raise AcquisitionError("Configuration needs allowed_hosts, limits and sources")
    hosts = config["allowed_hosts"]
    if not isinstance(hosts, list) or not hosts or any(not isinstance(h, str) or not re.fullmatch(r"[a-z0-9.-]+", h) for h in hosts):
        raise AcquisitionError("Invalid reviewed host list")
    DownloadLimits(**config["limits"])
    sources = config["sources"]
    if not isinstance(sources, list) or not 1 <= len(sources) <= 200:
        raise AcquisitionError("Require 1..200 explicitly reviewed sources")
    names = set()
    required = {"name", "url", "kind", "reference", "label", "label_source"}
    optional = {"expected_sha256", "expected_md5", "expected_bytes", "password_env", "password_candidates_env"}
    for source in sources:
        if not isinstance(source, dict) or not required <= source.keys() or source.keys() - required - optional:
            raise AcquisitionError("Invalid source schema")
        name = source["name"]
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,79}", name) or name in names:
            raise AcquisitionError("Source identifiers must be unique safe directory names")
        names.add(name)
        validate_url(source["url"], hosts)
        if source["kind"] not in {"pdf", "zip"} or source["label"] not in (None, 0, 1) or type(source["label"]) is bool:
            raise AcquisitionError("Require PDF/ZIP and a declared binary label or null")
        for key in ("reference", "label_source"):
            if not isinstance(source[key], str) or not source[key].strip():
                raise AcquisitionError("Source reference and label provenance are required")
        for key, length in (("expected_sha256", 64), ("expected_md5", 32)):
            if key in source and (not isinstance(source[key], str) or not re.fullmatch(rf"[0-9a-f]{{{length}}}", source[key])):
                raise AcquisitionError("Invalid expected checksum")
        if "expected_bytes" in source and (type(source["expected_bytes"]) is not int or source["expected_bytes"] <= 0):
            raise AcquisitionError("Invalid expected byte count")
        if "password_env" in source and "password_candidates_env" in source:
            raise AcquisitionError("Choose one password environment mechanism per source")
        for key in ("password_env", "password_candidates_env"):
            if key in source and (source["kind"] != "zip" or not isinstance(source[key], str) or not re.fullmatch(r"MALPDF_[A-Z0-9_]+", source[key])):
                raise AcquisitionError("Archive passwords must use a task-specific environment variable")


def _password_candidates(source: dict) -> tuple[bytes, ...]:
    """Read a short, explicitly supplied list without saving password values."""
    key = "password_candidates_env" if "password_candidates_env" in source else "password_env"
    if key not in source:
        return ()
    value = os.environ.get(source[key])
    if not value:
        raise AcquisitionError("Required archive password environment variable is unavailable")
    if len(value.encode()) > 4096:
        raise AcquisitionError("Archive password environment value exceeds its cap")
    try:
        candidates = json.loads(value) if key == "password_candidates_env" else [value]
    except json.JSONDecodeError:
        raise AcquisitionError("Password candidates require a JSON array of strings") from None
    if (not isinstance(candidates, list) or not 1 <= len(candidates) <= 8
            or any(not isinstance(p, str) or not p or len(p.encode()) > 256 or "\x00" in p for p in candidates)
            or len(set(candidates)) != len(candidates)):
        raise AcquisitionError("Require 1..8 unique nonempty bounded password candidates")
    return tuple(p.encode() for p in candidates)


def _reuse_payload(root: Path, run_id: str, source: dict, limits: DownloadLimits,
                   *, remaining_bytes: int, progress=lambda event: None) -> tuple[Path, dict]:
    """Verify an immutable local payload against its original acquisition locks."""
    if not isinstance(run_id, str) or not re.fullmatch(r"run_[A-Za-z0-9_-]{1,100}", run_id):
        raise AcquisitionError("Invalid reuse run identifier")
    audit = root / "artifacts/raw_downloads" / run_id
    previous = json.loads(read_bounded_bytes(audit / "configuration.json", boundary=root / "artifacts/raw_downloads", max_bytes=128 * 1024))
    validate_configuration(previous)
    prior = next((s for s in previous["sources"] if s["name"] == source["name"]), None)
    excluded = {"password_env", "password_candidates_env"}
    if prior is None or {k: v for k, v in prior.items() if k not in excluded} != {k: v for k, v in source.items() if k not in excluded}:
        raise AcquisitionError("Reused source identity or publisher integrity locks changed")
    saved = json.loads(read_bounded_bytes(audit / (source["name"] + "_download.json"), boundary=audit, max_bytes=4096))
    if (not isinstance(saved, dict) or type(saved.get("bytes")) is not int or saved["bytes"] <= 0
            or not isinstance(saved.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", saved["sha256"])
            or not isinstance(saved.get("md5"), str) or not re.fullmatch(r"[0-9a-f]{32}", saved["md5"])):
        raise AcquisitionError("Invalid original payload checksum evidence")
    boundary = root / "data/raw/public_pdf_sources" / run_id
    path = boundary / source["name"] / ("payload.zip" if source["kind"] == "zip" else "payload.download")
    cap = min(limits.max_download_bytes, remaining_bytes, limits.max_pdf_bytes if source["kind"] == "pdf" else limits.max_download_bytes)
    info = path.lstat()
    if (any(p.is_symlink() for p in (path, *path.parents)) or not stat.S_ISREG(info.st_mode)
            or info.st_size != saved["bytes"] or info.st_size > cap):
        raise AcquisitionError("Reused payload is unsafe, changed size, or exceeds its byte budget")
    for candidate in (path, audit / "configuration.json", audit / (source["name"] + "_download.json")):
        if subprocess.run(["git", "-C", str(root), "check-ignore", "-q", "--", str(candidate)], check=False).returncode:
            raise AcquisitionError("Reused samples and detailed metadata must be gitignored")
    sha, md5, total, last = hashlib.sha256(), hashlib.md5(), 0, time.monotonic()
    with path.open("rb") as handle:
        while chunk := handle.read(min(64 * 1024, cap - total + 1)):
            total += len(chunk)
            if total > cap:
                raise AcquisitionError("Reused payload grew beyond its byte cap")
            sha.update(chunk)
            md5.update(chunk)
            if time.monotonic() - last >= 10:
                progress({"event": "reuse_checksum_progress", "bytes": total})
                last = time.monotonic()
    if (total != saved["bytes"] or sha.hexdigest() != saved["sha256"] or md5.hexdigest() != saved["md5"]
            or source.get("expected_bytes", total) != total
            or source.get("expected_sha256", sha.hexdigest()) != sha.hexdigest()
            or source.get("expected_md5", md5.hexdigest()) != md5.hexdigest()):
        raise AcquisitionError("Reused payload checksum or publisher integrity lock mismatch")
    progress({"event": "payload_reused", "bytes": total})
    return path, {"bytes": total, "sha256": sha.hexdigest(), "md5": md5.hexdigest(),
                  "publisher_sha256_available": "expected_sha256" in source,
                  "publisher_md5_available": "expected_md5" in source, "reused_from_run": run_id}


def _safe_directory(path: Path, boundary: Path, *, new: bool = False) -> None:
    if not path.is_relative_to(boundary) or ".." in path.parts or any(p.is_symlink() for p in (path, *path.parents)):
        raise AcquisitionError("Output path escapes its boundary or uses a symbolic link")
    path.mkdir(parents=True, exist_ok=not new, mode=0o700)


def download_file(source: dict, destination: Path, hosts: list[str], limits: DownloadLimits,
                  *, remaining_bytes: int, progress=lambda event: None) -> dict:
    """Stream capped bytes; verify declared size and publisher checksums before publishing."""
    validate_url(source["url"], hosts, resolve=True)
    cap = min(limits.max_download_bytes, remaining_bytes)
    if source["kind"] == "pdf":
        cap = min(cap, limits.max_pdf_bytes)
    if cap <= 0 or source.get("expected_bytes", 0) > cap:
        raise AcquisitionError("Download would exceed its remaining byte budget")
    if destination.exists() or destination.is_symlink():
        raise AcquisitionError("Refusing to overwrite a download")
    opener = build_opener(_ReviewedRedirects(hosts))
    request = Request(source["url"], headers={"User-Agent": "MalPDFResearch/0.1", "Accept-Encoding": "identity"})
    partial = destination.with_suffix(destination.suffix + ".download-part")
    sha, md5 = hashlib.sha256(), hashlib.md5(usedforsecurity=False)
    started, last_progress, total = time.monotonic(), time.monotonic(), 0
    with opener.open(request, timeout=limits.timeout_seconds) as response:
        validate_url(response.geturl(), hosts, resolve=True)
        if response.status != 200 or response.headers.get("Content-Encoding", "identity").lower() != "identity":
            raise AcquisitionError("Require a full, unencoded HTTP 200 response")
        declared = response.headers.get("Content-Length")
        declared = int(declared) if declared is not None else None
        if declared is not None and (declared < 0 or declared > cap):
            raise AcquisitionError("HTTP Content-Length exceeds the cap")
        with partial.open("xb") as output:
            partial.chmod(0o600)
            while True:
                if time.monotonic() - started > limits.max_transfer_seconds:
                    raise AcquisitionError("Transfer exceeded its wall-clock limit")
                chunk = response.read(min(64 * 1024, cap - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                if total > cap:
                    output.write(chunk[:max(0, cap - (total - len(chunk)))])
                    raise AcquisitionError("Downloaded bytes exceed the cap")
                output.write(chunk)
                sha.update(chunk)
                md5.update(chunk)
                if time.monotonic() - last_progress >= 10:
                    progress({"event": "download_progress", "bytes": total})
                    last_progress = time.monotonic()
            output.flush()
            os.fsync(output.fileno())
    if total == 0 or (declared is not None and total != declared) or ("expected_bytes" in source and total != source["expected_bytes"]):
        raise AcquisitionError("Download is empty, truncated or differs from the publisher size")
    observed = {"sha256": sha.hexdigest(), "md5": md5.hexdigest()}
    for algorithm in observed:
        if "expected_" + algorithm in source and source["expected_" + algorithm] != observed[algorithm]:
            raise AcquisitionError("Downloaded checksum differs from the publisher lock")
    os.link(partial, destination)
    partial.unlink()
    return {"bytes": total, **observed, "publisher_sha256_available": "expected_sha256" in source,
            "publisher_md5_available": "expected_md5" in source}


def _publish_pdf(content, destination: Path, *, max_bytes: int) -> dict:
    """Validate strict leading magic and save bytes using a content-addressed name."""
    if max_bytes < 5:
        raise AcquisitionError("Insufficient PDF byte budget")
    descriptor, name = tempfile.mkstemp(prefix=".candidate-", dir=destination)
    temporary, digest, total = Path(name), hashlib.sha256(), 0
    try:
        with os.fdopen(descriptor, "wb") as output:
            header = content.read(5)
            if header != b"%PDF-":
                raise AcquisitionError("Missing %PDF- magic at byte offset zero")
            output.write(header)
            digest.update(header)
            total = len(header)
            while True:
                chunk = content.read(min(64 * 1024, max_bytes - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise AcquisitionError("PDF bytes exceed the cap")
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        sha = digest.hexdigest()
        path = destination / (sha + ".pdf")
        duplicate = path.exists()
        if duplicate:
            existing = read_bounded_bytes(path, boundary=destination, max_bytes=max_bytes)
            if hashlib.sha256(existing).hexdigest() != sha:
                raise AcquisitionError("Existing content-addressed PDF differs from its checksum")
        else:
            os.link(temporary, path)
        return {"path": str(path), "sha256": sha, "bytes": total, "duplicate": duplicate, "magic_verified": True}
    finally:
        temporary.unlink(missing_ok=True)


def inspect_zip_directory(path: Path, limits: DownloadLimits) -> list[zipfile.ZipInfo]:
    """Validate bounded ZIP metadata before any member is opened or published."""
    info = path.lstat()
    if any(p.is_symlink() for p in (path, *path.parents)) or not stat.S_ISREG(info.st_mode) or info.st_size > limits.max_download_bytes:
        raise AcquisitionError("Require a regular ZIP within the download cap")


    with path.open("rb") as handle:
        handle.seek(max(0, info.st_size - 65557))
        tail = handle.read(65557)
    position = tail.rfind(b"PK\x05\x06")
    if position < 0 or len(tail) - position < 22:
        raise AcquisitionError("Missing ZIP directory footer")
    footer = struct.unpack("<4s4H2IH", tail[position:position + 22])
    if (any(footer[i] != 0 for i in (1, 2)) or footer[3] != footer[4]
            or footer[4] > limits.max_archive_members or footer[4] == 65535
            or footer[5] > 16 * 1024 * 1024 or footer[5] + footer[6] > info.st_size
            or len(tail) - position != 22 + footer[7]):
        raise AcquisitionError("ZIP directory exceeds limits or is multipart/ZIP64")
    with zipfile.ZipFile(path) as archive:
        members, names = archive.infolist(), set()
        if len(members) != footer[4]:
            raise AcquisitionError("ZIP directory count mismatch")
        for member in members:
            member_path = PurePosixPath(member.filename)
            mode = member.external_attr >> 16
            if (member_path.is_absolute() or ".." in member_path.parts or "\\" in member.filename
                    or "\x00" in member.filename or ":" in member.filename or member.filename in names
                    or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR))
                    or member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
                raise AcquisitionError("Unsafe, duplicate or unsupported ZIP member")
            names.add(member.filename)
    return members


def extract_pdf_archive(path: Path, output: Path, limits: DownloadLimits, *,
                        remaining_bytes: int, password: bytes | None = None,
                        password_candidates: tuple[bytes, ...] = (), progress=lambda event: None,
                        record=lambda entry: None) -> dict:
    """Inspect the entire ZIP directory before extracting opaque capped PDF bytes."""
    members = inspect_zip_directory(path, limits)
    counts = {"members": 0, "accepted": 0, "rejected": 0, "duplicates": 0, "pdf_bytes": 0}
    if password is not None and password_candidates:
        raise AcquisitionError("Choose one password mechanism for extraction")
    candidates = (password,) if password is not None else password_candidates
    if (len(candidates) > 8 or any(not isinstance(p, bytes) or not p or len(p) > 256 or b"\x00" in p for p in candidates)
            or len(set(candidates)) != len(candidates)):
        raise AcquisitionError("Invalid bounded password candidates")
    if any(member.flag_bits & 1 for member in members) and not candidates:
        raise AcquisitionError("Encrypted ZIP requires an explicitly supplied password")
    with zipfile.ZipFile(path) as archive:
        if sum(m.file_size for m in members) > min(remaining_bytes, limits.max_total_pdf_bytes):
            raise AcquisitionError("ZIP output would exceed the remaining extraction budget")
        encrypted = [m for m in members if m.flag_bits & 1 and not m.is_dir()
                     and m.file_size <= limits.max_pdf_bytes
                     and m.file_size <= max(1, m.compress_size) * limits.max_compression_ratio]
        if encrypted:


            probe = min(encrypted, key=lambda m: m.file_size)
            for index, candidate in enumerate(candidates, start=1):
                try:
                    total = 0
                    with archive.open(probe, pwd=candidate) as content:
                        while chunk := content.read(min(64 * 1024, limits.max_pdf_bytes - total + 1)):
                            total += len(chunk)
                            if total > limits.max_pdf_bytes:
                                raise AcquisitionError("Password probe exceeds the PDF byte cap")
                    if total != probe.file_size:
                        raise AcquisitionError("Password probe size differs from its ZIP directory")
                except (RuntimeError, zipfile.BadZipFile, EOFError, zlib.error) as error:
                    progress({"event": "password_probe_rejected", "candidate_index": index, "error_type": type(error).__name__})
                else:
                    password = candidate
                    selection = {"candidate_count": len(candidates), "attempts": index, "selected_index": index, "probe_crc_verified": True}
                    counts["password_selection"] = selection
                    progress({"event": "password_selected", **selection})
                    break
            else:
                raise AcquisitionError("Archive decryption failed; all explicitly supplied candidates were rejected")
        _safe_directory(output, output.parent)
        for member in members:
            if member.is_dir():
                continue
            counts["members"] += 1
            try:
                if member.file_size > limits.max_pdf_bytes or member.file_size > max(1, member.compress_size) * limits.max_compression_ratio:
                    raise AcquisitionError("ZIP member exceeds the PDF size/compression cap")
                with archive.open(member, pwd=password) as content:
                    entry = _publish_pdf(content, output, max_bytes=limits.max_pdf_bytes)
                if entry["bytes"] != member.file_size:
                    raise AcquisitionError("Extracted PDF size differs from its ZIP directory")
            except RuntimeError as error:
                raise AcquisitionError("Archive decryption failed; source stopped") from error
            except (ValueError, zipfile.BadZipFile, NotImplementedError) as error:
                counts["rejected"] += 1
                record({"member": member.filename, "status": "rejected", "reason": str(error)})
            else:
                counts["accepted"] += 1
                counts["duplicates"] += int(entry["duplicate"])
                counts["pdf_bytes"] += entry["bytes"] if not entry["duplicate"] else 0
                record({"member": member.filename, "status": "accepted", **entry})
    return counts


def _json(path: Path, value) -> None:
    with path.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, allow_nan=False)
        handle.write("\n")


def _append_log(root: Path, summary: dict, status: str, notes: str) -> None:
    fields = [datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), summary["run_id"],
              "raw PDF acquisition / " + status, "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A",
              summary["code_commit"], summary["worktree"], summary["report_path"],
              notes + "; F1/MCC/ECE/Brier N/A: acquisition only, no model evaluation. Label=1 malicious; ECE convention: 10 equal-width probability bins when evaluated."]
    path = root / "reports/research_log.md"
    with path.open("a", encoding="utf-8") as handle:
        handle.write("| " + " | ".join(str(v).replace("|", "/").replace("\n", " ").replace("\r", " ") for v in fields) + " |\n")


def record_acquisition_refusal(root: Path, error: Exception, *, run_id: str | None = None,
                               module_sha256: str | None = None) -> dict:
    """Preserve authorized CLI attempts refused before the acquisition lifecycle."""
    root = root.absolute()
    commit = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    identifier = run_id
    if (not isinstance(identifier, str) or not re.fullmatch(r"run_[A-Za-z0-9_-]{1,100}", identifier)
            or (root / "reports/experiments/raw_downloads" / identifier).exists()):
        identifier = "run_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ_") + commit[:12]
    report = root / "reports/experiments/raw_downloads" / identifier
    _safe_directory(report, root, new=True)
    summary = {"run_id": identifier, "code_commit": commit, "worktree": repository_git_state(root)["status"],
               "status": "refused", "error_type": type(error).__name__, "unique_pdfs": 0,
               "report_path": str((report / "run_summary.json").relative_to(root)),
               "reason": "Invocation failed before an acquisition report was established; no successful acquisition is claimed."}
    _json(report / "locked_methodology.json", {"authorization": "Explicit human acquisition instruction",
            "configuration_lock": "N/A: invocation was refused before acquisition", "code_commit": commit,
            "worktree": summary["worktree"], "seed": None, "test_evaluations": 0,
            "metrics": "N/A: no model evaluation", "module_sha256": module_sha256 or sha256_file(Path(__file__))})
    _json(report / "environment_metadata.json", {"python": platform.python_version(), "git": repository_git_state(root)})
    _json(report / "run_summary.json", summary)
    with (report / "model_comparison.csv").open("x", encoding="utf-8", newline="") as handle:
        csv.writer(handle).writerows([["model", "partition", "status", "F1_malicious", "MCC", "ECE", "Brier", "reason"],
                ["N/A", "N/A", "refused", "N/A", "N/A", "N/A", "N/A", "Invocation refusal; no model evaluation"]])
    _append_log(root, summary, "refused", "Preflight/setup refusal preserved; error type=" + type(error).__name__)
    return summary


def acquire_raw_datasets(root: Path, configuration: dict, *, authorized: bool = False,
                         run_id: str | None = None, reuse_run: str | None = None,
                         progress=lambda event: None) -> dict:
    """Download only the reviewed inventory after explicit human authorization."""
    validate_configuration(configuration)
    if not authorized:
        raise AcquisitionError("Explicit authorization is required; use --execute-authorized")
    root = root.absolute()
    commit = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    identifier = run_id or "run_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ_") + commit[:12]
    if not re.fullmatch(r"run_[A-Za-z0-9_-]{1,100}", identifier):
        raise AcquisitionError("Invalid immutable run identifier")
    if reuse_run is not None and (not re.fullmatch(r"run_[A-Za-z0-9_-]{1,100}", reuse_run) or reuse_run == identifier):
        raise AcquisitionError("Invalid or colliding reuse run identifier")
    raw = root / "data/raw/public_pdf_sources" / identifier
    audit = root / "artifacts/raw_downloads" / identifier
    report = root / "reports/experiments/raw_downloads" / identifier
    for path in (raw, audit, report):
        if path.exists() or any(p.is_symlink() for p in (path, *path.parents)):
            raise AcquisitionError("Run collision or symbolic link; previous runs are immutable")

    for path in (raw / "guard.pdf", audit / "guard.json"):
        result = subprocess.run(["git", "-C", str(root), "check-ignore", "-q", "--", str(path)], check=False)
        if result.returncode != 0:
            raise AcquisitionError("Raw samples and detailed metadata must be gitignored")
    for path in (raw, audit, report):
        _safe_directory(path, root, new=True)
    limits = DownloadLimits(**configuration["limits"])
    _json(audit / "configuration.json", configuration)
    public_configuration = {"allowed_hosts": configuration["allowed_hosts"], "limits": asdict(limits),
            "sources": [{key: value for key, value in source.items() if key not in {"url", "expected_sha256", "expected_md5"}}
                        for source in configuration["sources"]]}
    summary = {"run_id": identifier, "code_commit": commit, "worktree": repository_git_state(root)["status"],
               "status": "started", "report_path": str((report / "run_summary.json").relative_to(root)),
               "raw_directory": str(raw.relative_to(root)), "manifest_path": str((audit / "source_pdf_manifest.csv").relative_to(root)),
               "events_path": str((audit / "progress.jsonl").relative_to(root)), "sources": [],
               "unique_pdfs": 0, "downloaded_bytes": 0, "reused_bytes": 0, "reuse_run": reuse_run,
               "published_pdf_bytes": 0}
    _json(report / "locked_methodology.json", {"configuration": public_configuration,
            "detailed_configuration_path": str((audit / "configuration.json").relative_to(root)),
            "authorization": "Explicit user instruction; this invocation uses --execute-authorized",
            "code_commit": commit, "worktree": summary["worktree"], "seed": None, "protocol": None,
            "policy": "Static opaque binary reads only; strict %PDF- at offset zero. No rendering, PDF parsing, code execution or uploads.",
            "cohort_policy": "Separate acquisition inventory; no RIT identities inferred and no Protocol G split changed.",
            "integrity_policy": "Local SHA-256 is an acquisition baseline; compare a publisher digest only when available. MD5 is an additional legacy publisher integrity lock, not authenticity proof.",
            "reuse_policy": {"source_run": reuse_run, "verification": "Read-only reuse requires original source identity, size, SHA-256, MD5 and available publisher checksums to match. Never fall back to HTTP on failure."},
            "password_policy": "Use only explicitly supplied environment candidates (max 8); inspect all ZIP paths and caps, then verify one bounded encrypted member's CRC before publishing. Record indices only, never password values.",
            "metric_policy": "N/A: no model evaluation; Label=1 malicious; ECE would use 10 equal-width probability bins."})
    packages = ["malpdf", "PyYAML", "pytest"]
    if (root / "pyproject.toml").exists():
        declared = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        packages.extend(re.split(r"[<>=!~\[; ]", dependency, maxsplit=1)[0] for dependency in declared["project"]["dependencies"])
    _json(report / "environment_metadata.json", {"python": platform.python_version(), "platform": platform.platform(),
            "packages": {name: importlib.metadata.version(name) for name in sorted(set(packages))},
            "git": repository_git_state(root), "module_sha256": sha256_file(Path(__file__)), "configuration_sha256": hashlib.sha256(json.dumps(configuration, sort_keys=True).encode()).hexdigest()})

    def event(payload):
        value = {"utc": datetime.now(timezone.utc).isoformat(), **payload}
        with (audit / "progress.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(value, allow_nan=False) + "\n")
        progress(value)

    _append_log(root, summary, "started", "Explicitly authorized public-source inventory locked; samples and identities remain ignored")
    manifest = audit / "source_pdf_manifest.csv"
    try:
        with manifest.open("x", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["sample_id", "Label", "pdf_relative_path", "pdf_sha256", "label_source", "source", "bytes", "magic_verified"])
            writer.writeheader()
            seen = {}
            last_pdf_progress = time.monotonic()
            for source in configuration["sources"]:
                state = {"name": source["name"], "status": "started", "unique_pdfs": 0, "accepted": 0, "rejected": 0}
                summary["sources"].append(state)
                event({"event": "source_started", "source": source["name"]})
                try:
                    if any(key in source and not os.environ.get(source[key]) for key in ("password_env", "password_candidates_env")):
                        state["status"] = "blocked_missing_password"
                        raise AcquisitionError("Required archive password environment variable is unavailable")
                    candidates = _password_candidates(source)
                    remaining = limits.max_total_download_bytes - summary["downloaded_bytes"] - summary["reused_bytes"]
                    budget = min(limits.max_download_bytes, remaining)
                    if shutil.disk_usage(raw).free < (0 if reuse_run else budget) + limits.max_total_pdf_bytes + 64 * 1024 * 1024:
                        raise AcquisitionError("Insufficient free disk for capped acquisition and extraction")
                    source_root = raw / source["name"]
                    _safe_directory(source_root, raw, new=True)
                    if reuse_run:
                        payload, download = _reuse_payload(root, reuse_run, source, limits, remaining_bytes=remaining,
                                progress=lambda e: event({"source": source["name"], **e}))
                        summary["reused_bytes"] += download["bytes"]
                    else:
                        payload = source_root / ("payload.zip" if source["kind"] == "zip" else "payload.download")
                        download = download_file(source, payload, configuration["allowed_hosts"], limits, remaining_bytes=remaining,
                                progress=lambda e: event({"source": source["name"], **e}))
                    state["download"] = {key: value for key, value in download.items() if key not in {"sha256", "md5"}}
                    _json(audit / (source["name"] + "_download.json"), download)
                    destination = source_root / "pdfs"
                    _safe_directory(destination, source_root, new=True)

                    def record(entry):
                        nonlocal last_pdf_progress
                        with (audit / (source["name"] + "_inventory.jsonl")).open("a", encoding="utf-8") as inventory:
                            inventory.write(json.dumps(entry, allow_nan=False) + "\n")
                        if entry["status"] != "accepted":
                            state["rejected"] += 1
                            return
                        state["accepted"] += 1
                        digest = entry["sha256"]
                        if digest in seen:
                            if seen[digest] != source["label"]:
                                raise AcquisitionError("Duplicate PDF has conflicting declared source labels")
                            return
                        seen[digest] = source["label"]
                        writer.writerow({"sample_id": "public_pdf:" + digest, "Label": source["label"] if source["label"] is not None else "",
                            "pdf_relative_path": str(Path(entry["path"]).relative_to(root)), "pdf_sha256": digest,
                            "label_source": source["label_source"], "source": source["name"], "bytes": entry["bytes"], "magic_verified": True})
                        handle.flush()
                        state["unique_pdfs"] += 1
                        summary["unique_pdfs"] += 1
                        summary["published_pdf_bytes"] += entry["bytes"]
                        if time.monotonic() - last_pdf_progress >= 10:
                            event({"event": "pdf_progress", "source": source["name"], "unique_pdfs": state["unique_pdfs"]})
                            last_pdf_progress = time.monotonic()

                    remaining_pdf = limits.max_total_pdf_bytes - summary["published_pdf_bytes"]
                    if source["kind"] == "zip":
                        state.update(extract_pdf_archive(payload, destination, limits, remaining_bytes=remaining_pdf,
                                password_candidates=candidates, record=record,
                                progress=lambda e: event({"source": source["name"], **e})))
                    else:
                        with payload.open("rb") as content:
                            entry = _publish_pdf(content, destination, max_bytes=min(limits.max_pdf_bytes, remaining_pdf))
                        record({"status": "accepted", **entry})
                        state["accepted"] = 1
                    state["status"] = "completed" if state["accepted"] > 0 and state["rejected"] == 0 else "completed_with_rejections" if state["accepted"] > 0 else "failed_no_valid_pdf"
                except Exception as error:
                    if state["status"] == "started":
                        state["status"] = "failed"
                    state["error_type"] = type(error).__name__

                    _json(audit / (source["name"] + "_error.json"), {"type": type(error).__name__, "message": str(error)})
                except BaseException:
                    state["status"] = "interrupted"
                    raise
                finally:


                    summary["downloaded_bytes"] = sum(p.stat().st_size for p in raw.glob("*/payload.*") if p.is_file())
                    summary["published_pdf_bytes"] = sum(p.stat().st_size for p in raw.glob("*/pdfs/*.pdf") if p.is_file())
                    event({"event": "source_finished", "source": source["name"], "status": state["status"], "unique_pdfs": state["unique_pdfs"]})
                    _append_log(root, summary, state["status"], f"Source {source['name']}: unique PDFs={state['unique_pdfs']}, accepted={state['accepted']}, rejected={state['rejected']}; details under ignored artifacts/raw_downloads")
        summary["status"] = "completed" if all(s["status"] == "completed" for s in summary["sources"]) else "partial" if summary["unique_pdfs"] else "failed"
    except BaseException as error:
        summary["status"] = "interrupted" if isinstance(error, (KeyboardInterrupt, SystemExit)) else "failed"
        summary["error_type"] = type(error).__name__
        error.acquisition_recorded = True
        raise
    finally:
        summary["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        if manifest.exists():
            summary["manifest_sha256"] = sha256_file(manifest)
        _json(report / "run_summary.json", summary)
        with (report / "model_comparison.csv").open("x", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["model", "partition", "status", "F1_malicious", "MCC", "ECE", "Brier", "reason"])
            writer.writerow(["N/A", "N/A", summary["status"], "N/A", "N/A", "N/A", "N/A", "Dataset acquisition only; no model evaluation"])
        _append_log(root, summary, summary["status"], f"Unique validated PDF count={summary['unique_pdfs']}; immutable manifest={summary['manifest_path']}; no Protocol G assignment or evaluation")
    return summary

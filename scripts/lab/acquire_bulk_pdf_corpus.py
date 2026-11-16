"""Resumable, 20 GB-capped bulk PDF corpus acquisition and deduplication for REMnux LAB."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

HARD_CAP_BYTES = 20_000_000_000
TARGET_BYTES = 19_500_000_000
MAX_SINGLE_PDF_BYTES = 64 * 1024 * 1024
MAX_METADATA_BYTES = 50 * 1024 * 1024
PDF_MAGIC = b"%PDF-"
DEFAULT_ARCHIVE_PASSWORDS = ("", "infected", "virus", "malware")
SKIP_SUFFIXES = frozenset({
    ".pkl", ".pickle", ".joblib", ".dill", ".pt", ".pth", ".onnx", ".npy", ".npz",
    ".py", ".pyc", ".sh", ".ps1", ".bat", ".exe", ".dll", ".so", ".dylib",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".md", ".rst", ".yml", ".yaml",
})
METADATA_SUFFIXES = frozenset({".csv", ".json", ".tsv", ".txt", ".parquet"})
CIC_MANIFEST_REL = Path(
    "data/processed/multi_cohort_v4/run_20261003T124714720715Z_c96868a21732/source_manifest.csv"
)


@dataclass(frozen=True)
class QueueItem:
    item_id: str
    priority: int
    source: str
    kind: str
    url: str
    expected_bytes: int
    label_source: str
    expected_md5: str | None = None
    filename: str | None = None
    files: tuple[dict, ...] = ()


def is_allowed_url(url: str) -> bool:
    parsed = urllib.parse.urlsplit(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not host or parsed.username or parsed.password:
        return False
    return (
        host in {"zenodo.org", "huggingface.co", "digitalcorpora.s3.amazonaws.com", "downloads.digitalcorpora.org"}
        or host.endswith((".hf.co", ".huggingface.co"))
    )


def _fetch_json(url: str) -> tuple[object, dict[str, str]]:
    if not is_allowed_url(url):
        raise ValueError(f"Disallowed URL: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "MalPDFCorpus/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        if not is_allowed_url(resp.geturl()):
            raise ValueError(f"Disallowed redirect: {resp.geturl()}")
        return json.loads(resp.read()), {k.lower(): v for k, v in resp.headers.items()}


def fetch_zenodo_files(record_id: str) -> list[dict]:
    data, _ = _fetch_json(f"https://zenodo.org/api/records/{record_id}")
    files = []
    for entry in data.get("files", []):
        checksum = entry.get("checksum", "")
        md5 = checksum.split(":", 1)[1] if checksum.startswith("md5:") else None
        files.append({
            "key": entry["key"],
            "size": int(entry["size"]),
            "md5": md5,
            "url": f"https://zenodo.org/api/records/{record_id}/files/{urllib.parse.quote(entry['key'])}/content",
        })
    return files


def fetch_hf_govdocs_files() -> list[dict]:
    files = []
    for sub in ("sample", "index"):
        url = f"https://huggingface.co/api/datasets/BEE-spoke-data/govdocs1-pdf-source/tree/main/{sub}?limit=1000"
        while url:
            if not is_allowed_url(url):
                raise ValueError(f"Disallowed HF URL: {url}")
            req = urllib.request.Request(url, headers={"User-Agent": "MalPDFCorpus/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                if not is_allowed_url(resp.geturl()):
                    raise ValueError(f"Disallowed redirect: {resp.geturl()}")
                items = json.loads(resp.read())
                for item in items:
                    if item.get("type") == "file":
                        path = item["path"]
                        files.append({
                            "path": path,
                            "size": int(item["size"]),
                            "url": f"https://huggingface.co/datasets/BEE-spoke-data/govdocs1-pdf-source/resolve/main/{urllib.parse.quote(path)}",
                        })
                link = resp.headers.get("Link", "")
                next_url = None
                for part in link.split(","):
                    if 'rel="next"' in part:
                        next_url = part[part.find("<") + 1:part.find(">")]
                url = next_url
    return files


def fetch_safedocs_zips() -> list[dict]:
    ns = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
    rows = []
    token = None
    for _ in range(16):
        url = "https://digitalcorpora.s3.amazonaws.com/?list-type=2&prefix=corpora/files/CC-MAIN-2021-31-PDF-UNTRUNCATED/zipfiles/&max-keys=1000"
        if token:
            url += "&continuation-token=" + urllib.parse.quote(token, safe="")
        with urllib.request.urlopen(url, timeout=30) as resp:
            root = ET.fromstring(resp.read())
        for content in root.findall("s3:Contents", ns):
            key = content.find("s3:Key", ns).text
            size = int(content.find("s3:Size", ns).text)
            etag = (content.find("s3:ETag", ns).text or "").strip('"')
            if key.endswith(".zip") and size > 0:
                rows.append({
                    "key": key,
                    "name": key.rsplit("/", 1)[-1],
                    "size": size,
                    "md5": etag if len(etag) == 32 and "-" not in etag else None,
                    "url": f"https://digitalcorpora.s3.amazonaws.com/{key}",
                })
        trunc = root.find("s3:IsTruncated", ns)
        if trunc is None or trunc.text != "true":
            break
        token = root.find("s3:NextContinuationToken", ns).text
    rows.sort(key=lambda item: (item["size"], item["name"]))
    return rows


def select_safedocs_within_budget(candidates: list[dict], remaining_bytes: int) -> list[dict]:
    selected = []
    used = 0
    for item in sorted(candidates, key=lambda row: (row["size"], row["name"])):
        if used + item["size"] <= remaining_bytes:
            selected.append(item)
            used += item["size"]
    return selected


def build_queue(
    *,
    hard_cap: int = HARD_CAP_BYTES,
    target_bytes: int = TARGET_BYTES,
    include_existing_zenodo: bool = False,
    zenodo_3464032: list[dict] | None = None,
    zenodo_15603773: list[dict] | None = None,
    hf_govdocs: list[dict] | None = None,
    safedocs_zips: list[dict] | None = None,
    hf_shard_size: int = 1000,
) -> dict:
    z34 = zenodo_3464032 if zenodo_3464032 is not None else fetch_zenodo_files("3464032")
    z15 = zenodo_15603773 if zenodo_15603773 is not None else fetch_zenodo_files("15603773")
    hf = hf_govdocs if hf_govdocs is not None else fetch_hf_govdocs_files()
    sd = safedocs_zips if safedocs_zips is not None else fetch_safedocs_zips()

    items: list[QueueItem] = []
    skipped = [
        {"source": "cic_pdfmal_2022", "reason": "tabular_only_no_raw_pdfs_published", "reference": "https://www.unb.ca/cic/datasets/pdfmal-2022.html"},
    ]

    z34_labels = {
        "CLEAN_PDF_9000_files.zip": ("zenodo_3464032_clean_9000", "publisher_reported_benign"),
        "MALWARE_PDF_PRE_04-2011.zip": ("zenodo_3464032_malware_2011", "publisher_reported_malicious_virustotal_2011"),
        "2017-12-05-PDF.7z": ("zenodo_3464032_malware_2017", "publisher_reported_malicious_virustotal_2017"),
    }
    for f in z34:
        if f["key"] not in z34_labels:
            continue
        if not include_existing_zenodo and f["key"] in ("CLEAN_PDF_9000_files.zip", "MALWARE_PDF_PRE_04-2011.zip"):
            skipped.append({"source": z34_labels[f["key"]][0], "filename": f["key"], "bytes": f["size"], "reason": "already_present_on_lab"})
            continue
        src_name, lbl = z34_labels[f["key"]]
        kind = "7z" if f["key"].endswith(".7z") else "zip"
        items.append(QueueItem(
            item_id=src_name, priority=1, source=src_name, kind=kind,
            url=f["url"], expected_bytes=f["size"], expected_md5=f.get("md5"),
            label_source=lbl, filename=f["key"],
        ))

    for f in z15:
        if f["key"] == "vapd_src.zip":
            items.append(QueueItem(
                item_id="vapd_v5", priority=2, source="vapd_v5", kind="zip",
                url=f["url"], expected_bytes=f["size"], expected_md5=f.get("md5"),
                label_source="vapd_v5_path_provenance", filename=f["key"],
            ))

    hf_sorted = sorted(hf, key=lambda row: row["path"])
    for idx in range(0, len(hf_sorted), hf_shard_size):
        chunk = hf_sorted[idx:idx + hf_shard_size]
        shard_num = idx // hf_shard_size
        items.append(QueueItem(
            item_id=f"govdocs1_sample_shard_{shard_num:02d}",
            priority=3,
            source="govdocs1_sample",
            kind="hf_files",
            url="https://huggingface.co/datasets/BEE-spoke-data/govdocs1-pdf-source",
            expected_bytes=sum(x["size"] for x in chunk),
            label_source="unverified_govdocs1_sample",
            files=tuple(chunk),
        ))

    used = sum(item.expected_bytes for item in items)
    if used > hard_cap:
        raise ValueError(f"Priority 1-3 bytes ({used}) exceed hard cap ({hard_cap})")

    budget = min(target_bytes, hard_cap) - used
    chosen_sd = select_safedocs_within_budget(sd, max(0, budget))
    # If packing to target leaves room under hard_cap for one smaller remaining ZIP, prefer target_bytes first and check hard_cap only if target wasn't reached.
    if used + sum(x["size"] for x in chosen_sd) < target_bytes:
        chosen_sd = select_safedocs_within_budget(sd, hard_cap - used)

    for item in chosen_sd:
        stem = item["name"].removesuffix(".zip")
        items.append(QueueItem(
            item_id=f"safedocs_{stem}",
            priority=5,
            source=f"safedocs_{stem}",
            kind="zip",
            url=item["url"],
            expected_bytes=item["size"],
            expected_md5=item.get("md5"),
            label_source="unlabeled_safedocs_cc_main_2021_31",
            filename=item["name"],
        ))

    total_bytes = sum(item.expected_bytes for item in items)
    if total_bytes > hard_cap:
        raise ValueError(f"Queued bytes {total_bytes} exceed hard cap {hard_cap}")

    return {
        "schema_version": 1,
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "hard_cap_bytes": hard_cap,
        "target_bytes": target_bytes,
        "total_queued_bytes": total_bytes,
        "safedocs_zip_count": len(chosen_sd),
        "skipped": skipped,
        "items": [
            {
                "item_id": it.item_id,
                "priority": it.priority,
                "source": it.source,
                "kind": it.kind,
                "url": it.url,
                "expected_bytes": it.expected_bytes,
                "expected_md5": it.expected_md5,
                "label_source": it.label_source,
                "filename": it.filename,
                "files": list(it.files),
            }
            for it in items
        ],
    }


def is_non_dataset_member(source: str, rel_posix: str) -> bool:
    norm = rel_posix.replace("\\", "/")
    if "/site-packages/matplotlib/mpl-data/images/" in norm:
        return True
    if source == "vapd_v5" and norm.endswith("/Artifact_Documentation__USENIX_Security_25.pdf"):
        return True
    return False


def _safe_member_relpath(raw_name: str) -> PurePosixPath | None:
    if not raw_name or "\x00" in raw_name or "\\" in raw_name:
        return None
    path = PurePosixPath(raw_name)
    if path.is_absolute() or ".." in path.parts or any(part.startswith(".") for part in path.parts):
        return None
    if "__MACOSX" in path.parts:
        return None
    return path


def _store_pdf_stream(stream, pdfs_root: Path, *, max_bytes: int = MAX_SINGLE_PDF_BYTES) -> tuple[str, int, bool] | None:
    first = stream.read(1024)
    if not first or PDF_MAGIC not in first:
        return None
    magic_offset0 = first.startswith(PDF_MAGIC)
    pdfs_root.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".pdf-", dir=pdfs_root)
    tmp_path = Path(tmp_name)
    digest = hashlib.sha256()
    total = 0
    try:
        with os.fdopen(fd, "wb") as out:
            chunk = first
            while chunk:
                total += len(chunk)
                if total > max_bytes:
                    return None
                digest.update(chunk)
                out.write(chunk)
                chunk = stream.read(min(64 * 1024, max_bytes - total + 1))
            out.flush()
            os.fsync(out.fileno())
        sha = digest.hexdigest()
        shard_dir = pdfs_root / sha[:2]
        shard_dir.mkdir(exist_ok=True)
        final_path = shard_dir / f"{sha}.pdf"
        if not final_path.exists():
            os.replace(tmp_path, final_path)
        return sha, total, magic_offset0
    finally:
        tmp_path.unlink(missing_ok=True)


def extract_zip_archive(
    archive_path: Path,
    *,
    source: str,
    label_source: str,
    pdfs_root: Path,
    metadata_root: Path,
    work_dir: Path,
    depth: int = 0,
    passwords: tuple[str, ...] = DEFAULT_ARCHIVE_PASSWORDS,
) -> tuple[list[dict], dict[str, int]]:
    records: list[dict] = []
    stats = {"pdfs": 0, "skipped_non_pdf": 0, "skipped_unsafe": 0, "metadata_saved": 0}
    work_dir.mkdir(parents=True, exist_ok=True)
    cached_pwd: bytes | None = None

    def open_member(zf_obj: zipfile.ZipFile, info_obj: zipfile.ZipInfo):
        nonlocal cached_pwd
        encrypted = bool(info_obj.flag_bits & 0x1)
        if not encrypted:
            return zf_obj.open(info_obj, "r")
        candidates = (cached_pwd,) + tuple(p.encode("utf-8") if p else None for p in passwords) if cached_pwd is not None else tuple(
            p.encode("utf-8") if p else None for p in passwords
        )
        last_err: Exception | None = None
        for cand in candidates:
            try:
                stream = zf_obj.open(info_obj, "r", pwd=cand)
                stream.peek(1) if hasattr(stream, "peek") else None
                cached_pwd = cand
                return stream
            except RuntimeError as exc:
                last_err = exc
        raise RuntimeError(f"Encrypted ZIP member failed for {info_obj.filename}: {last_err}")

    with zipfile.ZipFile(archive_path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                stats["skipped_unsafe"] += 1
                continue
            rel = _safe_member_relpath(info.filename)
            if rel is None:
                stats["skipped_unsafe"] += 1
                continue
            suffix = rel.suffix.lower()
            if suffix in (".zip", ".7z") and depth == 0 and info.file_size <= 1_600_000_000:
                with tempfile.NamedTemporaryFile(prefix="nested-", suffix=suffix, dir=work_dir, delete=False) as tmp_arc:
                    nested_path = Path(tmp_arc.name)
                    with open_member(zf, info) as src_stream:
                        shutil.copyfileobj(src_stream, tmp_arc, 64 * 1024)
                try:
                    if suffix == ".zip":
                        sub_recs, sub_stats = extract_zip_archive(
                            nested_path, source=source, label_source=f"{label_source}:{rel.as_posix()}",
                            pdfs_root=pdfs_root, metadata_root=metadata_root, work_dir=work_dir, depth=1,
                            passwords=passwords,
                        )
                    else:
                        sub_recs, sub_stats = extract_7z_archive(
                            nested_path, source=source, label_source=f"{label_source}:{rel.as_posix()}",
                            pdfs_root=pdfs_root, work_dir=work_dir, metadata_root=metadata_root, passwords=passwords,
                        )
                    records.extend(sub_recs)
                    for k, v in sub_stats.items():
                        stats[k] = stats.get(k, 0) + v
                finally:
                    nested_path.unlink(missing_ok=True)
                continue
            if suffix in SKIP_SUFFIXES or is_non_dataset_member(source, rel.as_posix()):
                stats["skipped_non_pdf"] += 1
                continue
            if suffix in METADATA_SUFFIXES and info.file_size <= MAX_METADATA_BYTES:
                target_meta = metadata_root / source / rel
                if not target_meta.resolve().is_relative_to((metadata_root / source).resolve()):
                    stats["skipped_unsafe"] += 1
                    continue
                target_meta.parent.mkdir(parents=True, exist_ok=True)
                with open_member(zf, info) as src_stream, target_meta.open("wb") as out_meta:
                    shutil.copyfileobj(src_stream, out_meta, 64 * 1024)
                stats["metadata_saved"] += 1
                continue
            if info.file_size > MAX_SINGLE_PDF_BYTES:
                stats["skipped_unsafe"] += 1
                continue
            with open_member(zf, info) as member_stream:
                stored = _store_pdf_stream(member_stream, pdfs_root)
            if stored is None:
                stats["skipped_non_pdf"] += 1
                continue
            sha, byte_count, magic0 = stored
            item_label = f"{label_source}:{rel.as_posix()}" if source == "vapd_v5" else label_source
            records.append({
                "sha256": sha,
                "source": source,
                "filename": rel.as_posix(),
                "bytes": byte_count,
                "label_source": item_label,
                "magic_offset0": magic0,
                "stored_relpath": f"pdfs/{sha[:2]}/{sha}.pdf",
            })
            stats["pdfs"] += 1
    return records, stats


def extract_7z_archive(
    archive_path: Path,
    *,
    source: str,
    label_source: str,
    pdfs_root: Path,
    work_dir: Path,
    metadata_root: Path | None = None,
    passwords: tuple[str, ...] = DEFAULT_ARCHIVE_PASSWORDS,
) -> tuple[list[dict], dict[str, int]]:
    records: list[dict] = []
    stats = {"pdfs": 0, "skipped_non_pdf": 0, "skipped_unsafe": 0, "metadata_saved": 0}
    tmp_dir = Path(tempfile.mkdtemp(prefix="extract7z-", dir=work_dir))
    seven_zip_bin = shutil.which("7z") or shutil.which("7za") or ("/usr/bin/7z" if Path("/usr/bin/7z").exists() else None)
    try:
        extracted = False
        for pwd in passwords:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            tmp_dir.mkdir(mode=0o700, exist_ok=True)
            if seven_zip_bin is not None:
                proc = subprocess.run(
                    [seven_zip_bin, "x", "-y", f"-p{pwd}", f"-o{tmp_dir}", str(archive_path)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=600,
                    check=False,
                )
                if proc.returncode == 0:
                    extracted = True
                    break
            else:
                import py7zr

                try:
                    with py7zr.SevenZipFile(archive_path, mode="r", password=pwd or None) as szf:
                        for member in szf.getnames():
                            if _safe_member_relpath(member) is None:
                                raise ValueError(f"Unsafe 7z member path: {member}")
                        szf.extractall(path=tmp_dir)
                    extracted = True
                    break
                except Exception:
                    continue
        if not extracted:
            raise RuntimeError(f"7z extraction failed for {archive_path.name}")
        for dirpath, dirnames, filenames in os.walk(tmp_dir, followlinks=False):
            current = Path(dirpath)
            dirnames[:] = [d for d in dirnames if not (current / d).is_symlink()]
            for fname in filenames:
                fpath = current / fname
                if fpath.is_symlink() or not fpath.is_file():
                    stats["skipped_unsafe"] += 1
                    continue
                if fpath.stat().st_size > MAX_SINGLE_PDF_BYTES:
                    stats["skipped_unsafe"] += 1
                    continue
                rel_obj = fpath.relative_to(tmp_dir)
                rel = rel_obj.as_posix()
                suffix = fpath.suffix.lower()
                if suffix in SKIP_SUFFIXES or is_non_dataset_member(source, rel):
                    stats["skipped_non_pdf"] += 1
                    continue
                if suffix in METADATA_SUFFIXES:
                    if metadata_root is not None and fpath.stat().st_size <= MAX_METADATA_BYTES:
                        target_meta = metadata_root / source / rel_obj
                        if target_meta.resolve().is_relative_to((metadata_root / source).resolve()):
                            target_meta.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(fpath, target_meta)
                            stats["metadata_saved"] += 1
                        else:
                            stats["skipped_unsafe"] += 1
                    else:
                        stats["skipped_non_pdf"] += 1
                    continue
                with fpath.open("rb") as stream:
                    stored = _store_pdf_stream(stream, pdfs_root)
                if stored is None:
                    stats["skipped_non_pdf"] += 1
                    continue
                sha, byte_count, magic0 = stored
                records.append({
                    "sha256": sha,
                    "source": source,
                    "filename": rel,
                    "bytes": byte_count,
                    "label_source": label_source,
                    "magic_offset0": magic0,
                    "stored_relpath": f"pdfs/{sha[:2]}/{sha}.pdf",
                })
                stats["pdfs"] += 1
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
    return records, stats


def download_resumable(
    client,
    url: str,
    dest_part: Path,
    *,
    expected_bytes: int | None = None,
    expected_md5: str | None = None,
) -> int:
    if not is_allowed_url(url):
        raise ValueError(f"Disallowed URL: {url}")
    dest_part.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(5):
        try:
            existing = dest_part.stat().st_size if dest_part.exists() else 0
            if expected_bytes is not None and existing > expected_bytes:
                dest_part.unlink(missing_ok=True)
                existing = 0
            if expected_bytes is not None and existing == expected_bytes:
                break
            headers = {"User-Agent": "MalPDFCorpus/1.0"}
            if existing > 0:
                headers["Range"] = f"bytes={existing}-"
            with client.stream("GET", url, headers=headers) as resp:
                if not is_allowed_url(str(resp.url)):
                    raise ValueError(f"Disallowed redirect URL: {resp.url}")
                if existing > 0 and resp.status_code == 416 and expected_bytes is not None and existing == expected_bytes:
                    break
                if resp.status_code == 206:
                    mode = "ab"
                elif resp.status_code == 200:
                    mode = "wb"
                    existing = 0
                else:
                    raise RuntimeError(f"HTTP {resp.status_code} for {url}")
                with dest_part.open(mode) as out:
                    for chunk in resp.iter_bytes(chunk_size=128 * 1024):
                        out.write(chunk)
                        existing += len(chunk)
                        if expected_bytes is not None and existing > expected_bytes:
                            raise RuntimeError(f"Exceeded expected bytes for {url}")
                    out.flush()
                    os.fsync(out.fileno())
            if expected_bytes is None or dest_part.stat().st_size == expected_bytes:
                break
        except Exception:
            if attempt == 4:
                raise
            time.sleep(2 ** attempt)
    actual = dest_part.stat().st_size
    if expected_bytes is not None and actual != expected_bytes:
        raise RuntimeError(f"Size mismatch for {url}: got {actual}, expected {expected_bytes}")
    if expected_md5 is not None:
        h = hashlib.md5(usedforsecurity=False)
        with dest_part.open("rb") as fh:
            while buf := fh.read(1024 * 1024):
                h.update(buf)
        if h.hexdigest() != expected_md5:
            dest_part.unlink(missing_ok=True)
            raise RuntimeError(f"MD5 mismatch for {url}: got {h.hexdigest()}, expected {expected_md5}")
    return actual


def _load_existing_sha256s(repo_root: Path) -> tuple[set[str], set[str]]:
    cic_set: set[str] = set()
    all_set: set[str] = set()
    manifest = repo_root / CIC_MANIFEST_REL
    if manifest.is_file():
        with manifest.open("r", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                sha = (row.get("pdf_sha256") or "").strip().lower()
                if len(sha) == 64:
                    all_set.add(sha)
                    if not (row.get("source") or "").strip():
                        cic_set.add(sha)
    return cic_set, all_set


def summarize_manifest(out_dir: Path, repo_root: Path, queue: dict) -> dict:
    cic_1452, baseline_all = _load_existing_sha256s(repo_root)
    manifest_csv = out_dir / "manifest.csv"
    per_source: dict[str, dict] = {}
    source_shas: dict[str, set[str]] = {}
    all_new_shas: set[str] = set()
    total_rows = 0

    if manifest_csv.is_file():
        with manifest_csv.open("r", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                total_rows += 1
                src = row["source"]
                sha = row["sha256"]
                sz = int(row["bytes"])
                bucket = per_source.setdefault(src, {"raw_files": 0, "total_pdf_bytes": 0})
                bucket["raw_files"] += 1
                bucket["total_pdf_bytes"] += sz
                source_shas.setdefault(src, set()).add(sha)
                all_new_shas.add(sha)

    for src, bucket in per_source.items():
        shas = source_shas[src]
        bucket["unique_sha256"] = len(shas)
        bucket["overlap_cic_1452"] = len(shas & cic_1452)
        bucket["overlap_baseline_all"] = len(shas & baseline_all)
        bucket["net_new_vs_baseline"] = len(shas - baseline_all)

    summary = {
        "schema_version": 1,
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "hard_cap_bytes": queue["hard_cap_bytes"],
        "total_queued_bytes": queue["total_queued_bytes"],
        "baseline_cic_1452_count": len(cic_1452),
        "baseline_all_count": len(baseline_all),
        "total_extracted_records": total_rows,
        "unique_new_batch_sha256": len(all_new_shas),
        "overlap_with_cic_1452": len(all_new_shas & cic_1452),
        "overlap_with_baseline_all": len(all_new_shas & baseline_all),
        "net_new_unique_vs_cic_1452": len(all_new_shas - cic_1452),
        "net_new_unique_vs_baseline_all": len(all_new_shas - baseline_all),
        "per_source": dict(sorted(per_source.items())),
        "skipped_sources": queue.get("skipped", []),
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def execute_queue(out_dir: Path, repo_root: Path, queue: dict, *, workers: int = 3) -> dict:
    if sys.platform != "linux":
        raise RuntimeError("Bulk PDF acquisition must run on Linux REMnux LAB")
    import httpx

    pdfs_root = out_dir / "pdfs"
    meta_root = out_dir / "metadata"
    work_dir = out_dir / "_work"
    done_dir = out_dir / "done"
    for d in (out_dir, pdfs_root, meta_root, work_dir, done_dir):
        d.mkdir(parents=True, exist_ok=True)

    manifest_csv = out_dir / "manifest.csv"
    write_lock = threading.Lock()
    if not manifest_csv.exists():
        with manifest_csv.open("w", encoding="utf-8", newline="") as fh:
            csv.writer(fh).writerow(["sha256", "source", "filename", "bytes", "label_source", "magic_offset0", "stored_relpath"])

    passwords = tuple(os.environ.get("MALPDF_ARCHIVE_PASSWORDS", "").split(",")) if os.environ.get("MALPDF_ARCHIVE_PASSWORDS") else DEFAULT_ARCHIVE_PASSWORDS

    def append_records(records: list[dict]) -> None:
        if not records:
            return
        with write_lock, manifest_csv.open("a", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh)
            for r in records:
                w.writerow([r["sha256"], r["source"], r["filename"], r["bytes"], r["label_source"], r["magic_offset0"], r["stored_relpath"]])

    def process_item(item: dict) -> dict:
        item_id = item["item_id"]
        done_file = done_dir / f"{item_id}.json"
        if done_file.is_file():
            return {"item_id": item_id, "status": "already_done"}

        with httpx.Client(follow_redirects=True, timeout=60.0) as client:
            if item["kind"] in ("zip", "7z"):
                part_path = work_dir / f"{item_id}.{item['kind']}.part"
                archive_path = work_dir / f"{item_id}.{item['kind']}"
                if not archive_path.exists():
                    download_resumable(
                        client, item["url"], part_path,
                        expected_bytes=item["expected_bytes"], expected_md5=item.get("expected_md5"),
                    )
                    os.replace(part_path, archive_path)
                try:
                    if item["kind"] == "zip":
                        records, stats = extract_zip_archive(
                            archive_path, source=item["source"], label_source=item["label_source"],
                            pdfs_root=pdfs_root, metadata_root=meta_root, work_dir=work_dir,
                            passwords=passwords,
                        )
                    else:
                        records, stats = extract_7z_archive(
                            archive_path, source=item["source"], label_source=item["label_source"],
                            pdfs_root=pdfs_root, work_dir=work_dir, metadata_root=meta_root, passwords=passwords,
                        )
                    append_records(records)
                finally:
                    archive_path.unlink(missing_ok=True)
            elif item["kind"] == "hf_files":
                records = []
                stats = {"pdfs": 0, "skipped_non_pdf": 0, "metadata_saved": 0}
                shard_state_file = work_dir / f"{item_id}.done.jsonl"
                done_paths = set()
                if shard_state_file.is_file():
                    for line in shard_state_file.read_text(encoding="utf-8").splitlines():
                        if line.strip():
                            done_paths.add(line.strip())
                for entry in item["files"]:
                    rel = _safe_member_relpath(entry["path"])
                    if rel is None:
                        continue
                    if rel.as_posix() in done_paths:
                        continue
                    if rel.suffix.lower() in METADATA_SUFFIXES and not rel.as_posix().lower().endswith(".pdf"):
                        target_meta = meta_root / item["source"] / rel
                        target_meta.parent.mkdir(parents=True, exist_ok=True)
                        tmp_meta = work_dir / f"{item_id}_{hashlib.sha256(rel.as_posix().encode()).hexdigest()[:12]}.part"
                        download_resumable(client, entry["url"], tmp_meta, expected_bytes=entry["size"])
                        os.replace(tmp_meta, target_meta)
                        stats["metadata_saved"] += 1
                    else:
                        tmp_pdf = work_dir / f"{item_id}_{hashlib.sha256(rel.as_posix().encode()).hexdigest()[:12]}.part"
                        download_resumable(client, entry["url"], tmp_pdf, expected_bytes=entry["size"])
                        try:
                            with tmp_pdf.open("rb") as fh:
                                stored = _store_pdf_stream(fh, pdfs_root)
                        finally:
                            tmp_pdf.unlink(missing_ok=True)
                        if stored is None:
                            stats["skipped_non_pdf"] += 1
                        else:
                            sha, byte_count, magic0 = stored
                            rec = {
                                "sha256": sha,
                                "source": item["source"],
                                "filename": rel.as_posix(),
                                "bytes": byte_count,
                                "label_source": item["label_source"],
                                "magic_offset0": magic0,
                                "stored_relpath": f"pdfs/{sha[:2]}/{sha}.pdf",
                            }
                            append_records([rec])
                            records.append(rec)
                            stats["pdfs"] += 1
                    with shard_state_file.open("a", encoding="utf-8") as sf:
                        sf.write(rel.as_posix() + "\n")
            else:
                raise ValueError(f"Unsupported item kind: {item['kind']}")

        result = {"item_id": item_id, "status": "completed", "stats": stats, "completed_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        done_file.write_text(json.dumps(result) + "\n", encoding="utf-8")
        print(json.dumps(result), flush=True)
        return result

    errors: list[dict] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {pool.submit(process_item, item): item["item_id"] for item in queue["items"]}
        for fut in as_completed(future_map):
            item_id = future_map[fut]
            try:
                fut.result()
            except Exception as exc:
                err = {"item_id": item_id, "error_type": type(exc).__name__, "error": str(exc)}
                errors.append(err)
                print(json.dumps({"item_id": item_id, "status": "failed", **err}), flush=True)

    summary = summarize_manifest(out_dir, repo_root, queue)
    summary["errors"] = errors
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--out-dir", type=Path, default=Path(__file__).resolve().parents[2] / "data/raw/bulk_20261116")
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--include-existing-zenodo", action="store_true")
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--summarize-only", action="store_true")
    args = parser.parse_args(argv)

    queue_path = args.out_dir / "queue_manifest.json"
    if args.summarize_only:
        queue = json.loads(queue_path.read_text(encoding="utf-8"))
        print(json.dumps(summarize_manifest(args.out_dir, args.repo_root, queue), indent=2))
        return 0

    if queue_path.is_file() and args.execute:
        queue = json.loads(queue_path.read_text(encoding="utf-8"))
    else:
        queue = build_queue(include_existing_zenodo=args.include_existing_zenodo)
        args.out_dir.mkdir(parents=True, exist_ok=True)
        queue_path.write_text(json.dumps(queue, indent=2) + "\n", encoding="utf-8")

    if args.plan_only or not args.execute:
        compact = {k: v for k, v in queue.items() if k != "items"}
        compact["items"] = [{k: v for k, v in it.items() if k != "files"} | {"file_count": len(it.get("files", []))} for it in queue["items"]]
        print(json.dumps(compact, indent=2))
        return 0

    summary = execute_queue(args.out_dir, args.repo_root, queue, workers=max(1, min(args.workers, 4)))
    print(json.dumps(summary, indent=2))
    return 2 if summary.get("errors") else 0


if __name__ == "__main__":
    raise SystemExit(main())

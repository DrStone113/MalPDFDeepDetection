"""Prepare CIC PDF bytes without inventing labels or adapting the frozen v3 model."""

from concurrent.futures import ProcessPoolExecutor
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import re
import stat

import numpy as np
import pandas as pd

from malpdf.data.markov_preparation import effective_cpu_count
from malpdf.data.raw_cohort import RAW_FEATURES, isolated_features
from malpdf.static.cache_manager import cache_markov_pdf
from malpdf.static.safety import read_bounded_bytes


def locked_bytes(root, specification, boundary, cap=32 * 1024**2):
    content = read_bounded_bytes(root / specification["path"], boundary=root / boundary, max_bytes=cap)
    if hashlib.sha256(content).hexdigest() != specification["sha256"]:
        raise ValueError("Input differs from its checksum lock")
    return content


def plan_cic_rows(target, source):
    """Keep publisher labels; exclude every known source identity, including agreeing labels."""
    if (not {"FileName", "Class"}.issubset(target) or target.empty
            or target.FileName.isna().any() or not target.FileName.is_unique
            or not target.Class.isin(["Benign", "Malicious"]).all()
            or not {"sample_id", "pdf_sha256", "Label", "pdf_relative_path"}.issubset(source)
            or not source.pdf_sha256.is_unique or source.pdf_sha256.isna().any()
            or not source.pdf_sha256.astype(str).str.fullmatch(r"[0-9a-f]{64}").all()
            or not source.Label.isin([0, 1, "0", "1", "", None]).all()):
        raise ValueError("CIC/source identity or label schema is invalid")
    source = source.set_index("pdf_sha256")
    rows = []
    seen = set()
    for position, (identifier, label) in enumerate(zip(target.FileName, target.Class)):
        identifier = str(identifier)
        digest = identifier.lower() if re.fullmatch(r"[0-9a-fA-F]{64}", identifier) else ""
        if digest and digest in seen:
            raise ValueError("CIC contains case-equivalent duplicate identities")
        if digest:
            seen.add(digest)
        known = source.loc[digest] if digest in source.index else None
        source_label = int(known.Label) if known is not None and known.Label in (0, 1, "0", "1") else None
        target_label = {"Benign": 0, "Malicious": 1}[label]
        rows.append({"sample_id": f"cic_{position:06d}", "cic_identifier": identifier,
                     "pdf_sha256": digest, "Label": target_label, "source_Label": source_label,
                     "target_label_source": "CIC-Evasive-PDFMal2022 supplied Parquet Class; not independently adjudicated",
                     "source_sample_id": "" if known is None else known.sample_id,
                     "source_label_source": "" if known is None else known.get("label_source", "not_supplied"),
                     "source_overlap": known is not None,
                     "label_conflict": source_label is not None and source_label != target_label,
                     "source_pdf_relative_path": "" if known is None else known.pdf_relative_path,
                     "exclusion_reason": "source_identity_overlap" if known is not None else
                         ("unsupported_identifier_requires_publisher_mapping" if not digest else ""),
                     "ground_truth_status": "unresolved_conflict" if source_label is not None and source_label != target_label
                         else "publisher_label_not_independently_adjudicated"})
    return pd.DataFrame(rows)


def inventory_local_pdfs(root, directory, *, max_pdf_bytes=10 * 1024**2, max_files=20_000):
    """Index only capped, stable PDF bytes; never infer a label from a filename or token."""
    directory = Path(directory).absolute()
    boundary = root / "data/raw"
    if (not directory.is_relative_to(boundary) or ".." in directory.parts
            or any(p.is_symlink() for p in (directory, *directory.parents))):
        raise ValueError("Raw CIC directory escapes the safe boundary")
    if not directory.exists():
        return {}
    result, count = {}, 0
    for path in directory.rglob("*"):
        count += 1
        if count > max_files:
            raise ValueError("Raw CIC inventory exceeds its file cap")
        if path.is_symlink():
            raise ValueError("Raw CIC inventory contains a symbolic link")
        if not path.is_file() or (path.suffix.lower() != ".pdf" and not re.fullmatch(r"[0-9a-fA-F]{64}", path.name)):
            continue
        data = read_bounded_bytes(path, boundary=boundary, max_bytes=max_pdf_bytes)
        if not data.startswith(b"%PDF-"):
            raise ValueError("CIC candidate fails %PDF- magic")
        digest = hashlib.sha256(data).hexdigest()
        relative = str(path.relative_to(root))
        result[digest] = min(relative, result.get(digest, relative))
    return result


def bounded_archive_checksum(path, boundary, cap):
    """Stream an inert archive without allocating its entire body or trusting symlinks."""
    path = Path(path).absolute()
    if (not path.is_relative_to(boundary) or ".." in path.parts
            or any(p.is_symlink() for p in (path, *path.parents))):
        raise ValueError("Local ZIP must remain in ignored data/raw without symbolic links")
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= cap:
        raise ValueError("Local ZIP exceeds its regular-file/byte cap")
    digest, total = hashlib.sha256(), 0
    def opener(name, flags):
        return os.open(name, flags | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    with open(path, "rb", opener=opener) as handle:
        if identity(os.fstat(handle.fileno())) != identity(before):
            raise ValueError("Local ZIP changed before checksum verification")
        while chunk := handle.read(min(64 * 1024, cap - total + 1)):
            total += len(chunk)
            if total > cap:
                raise ValueError("Local ZIP grew beyond its byte cap")
            digest.update(chunk)
        if total != before.st_size or identity(os.fstat(handle.fileno())) != identity(before):
            raise ValueError("Local ZIP changed during checksum verification")
    return {"bytes": total, "sha256": digest.hexdigest()}


def _cache_job(job):
    root, row = job
    return row["sample_id"], cache_markov_pdf(root / row["pdf_relative_path"], row["pdf_sha256"],
        raw_boundary=root / "data/raw", cache_directory=root / "data/processed/markov_cache",
        max_pdf_bytes=10 * 1024**2)


def extract_cic_rows(root, inventory, output, *, workers=2, progress=lambda **counts: None):
    """Reuse the v3 isolated parser and SHA-addressed cache, retaining unavailable metadata."""
    workers = min(workers, effective_cpu_count(), 2)
    if (workers < 1 or output.exists() or inventory.empty or not inventory.sample_id.is_unique
            or not inventory.pdf_sha256.is_unique):
        raise ValueError("Invalid worker budget or output collision")
    output.mkdir(parents=True, exist_ok=False)
    feature_rows, errors = [], []
    for position, result in isolated_features(inventory, root, workers=workers, progress=progress):
        row = inventory.iloc[position]
        feature_rows.append({"sample_id": row.sample_id, "Label": int(row.Label),
                             **{name: result["features"].get(name) for name in RAW_FEATURES},
                             "parser_failed": not result["complete"]})
        if result["errors"] or result["warnings"]:
            errors.append({"sample_id": row.sample_id, "errors": result["errors"], "warnings": result["warnings"]})
    columns = ["sample_id", "Label", *RAW_FEATURES, "parser_failed"]
    features = pd.DataFrame(feature_rows, columns=columns).set_index("sample_id").loc[inventory.sample_id].reset_index()
    # Save raw nulls/errors before subsequent cache or inference failures.
    features.to_csv(output / "raw_v3_features.csv", index=False)
    with (output / "parser_errors.json").open("x", encoding="utf-8") as stream:
        json.dump(errors, stream, indent=2)
    jobs = [(root, row) for row in inventory.to_dict("records")]
    identifiers = inventory.set_index("sample_id")
    cache_rows = []
    with ProcessPoolExecutor(max_workers=workers, mp_context=multiprocessing.get_context("spawn")) as pool:
        for offset in range(0, len(jobs), workers):
            futures = [pool.submit(_cache_job, job) for job in jobs[offset:offset + workers]]
            for future in futures:
                identifier, result = future.result()
                cache_rows.append({"sample_id": identifier, "pdf_sha256": identifiers.loc[identifier, "pdf_sha256"],
                                   "cache_relative_path": str(result["path"].relative_to(root)),
                                   "npy_sha256": result["npy_sha256"], "status": result["status"]})
            if len(cache_rows) % 500 < workers:
                progress(cached=len(cache_rows), total=len(jobs))
    cache = pd.DataFrame(cache_rows)
    cache.to_csv(output / "cache_manifest.csv", index=False)
    return features, cache


def validate_external_features(features):
    """Missing structural measurements fail closed; raw metadata nulls remain permitted."""
    from malpdf.models.v3_base_learners import METADATA_FEATURES
    security = [name for name in RAW_FEATURES if name not in METADATA_FEATURES]
    values = features.loc[:, security].to_numpy(float)
    if not np.isfinite(values).all():
        raise ValueError("External security measurements are unavailable; no fabricated values allowed")
    if not features.parser_failed.isin([True, False]).all():
        raise ValueError("Parser failure flags are unavailable")
    all_values = features.loc[:, list(RAW_FEATURES)].to_numpy(float)
    if np.isinf(all_values).any() or (np.isnan(all_values).any(axis=1) & ~features.parser_failed.to_numpy(bool)).any():
        raise ValueError("Only explicitly flagged unavailable metadata may remain null")

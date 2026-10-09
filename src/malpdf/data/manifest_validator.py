"""Validate an immutable PDF manifest and map its hashes to acquired raw files."""

from __future__ import annotations

import csv
from dataclasses import dataclass
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re

from malpdf.static.safety import read_bounded_bytes

REQUIRED_COLUMNS = {"sample_id", "Label", "pdf_relative_path", "pdf_sha256"}


@dataclass(frozen=True)
class PdfSample:
    sample_id: str
    label: int | None
    raw_path: Path
    pdf_sha256: str
    label_source: str
    split: str | None


def validate_sha256(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("Expected a lowercase SHA-256 digest")
    return value


def _local_path(root: Path, name: str) -> Path:
    if not isinstance(name, str) or not name or "\\" in name:
        raise ValueError("Invalid repository-relative path")
    relative = PurePosixPath(name)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("Unsafe repository-relative path")
    return root / relative


def validate_locked_source_manifest(
    repository_root: Path,
    manifest_path: Path,
    preparation_report_path: Path,
    *,
    max_pdf_bytes: int = 10 * 1024 * 1024,
    max_metadata_bytes: int = 2 * 1024 * 1024,
    max_samples: int = 100_000,
) -> tuple[list[PdfSample], dict]:
    """Use the preparation checksum lock; never choose or generate a manifest.

    The prepared CVE manifest names copied PDFs. A unique SHA-256 match in the
    completed preparation inventory resolves each row to its original raw PDF.
    This is an independent CVE cohort, not a RIT Protocol G sample mapping.
    """
    root = Path(repository_root).resolve()
    if any(type(value) is not int or value <= 0 for value in (max_pdf_bytes, max_metadata_bytes, max_samples)):
        raise ValueError("Manifest limits must be positive integers")
    manifest_path = _local_path(root, manifest_path.as_posix()) if not manifest_path.is_absolute() else manifest_path
    preparation_report_path = _local_path(root, preparation_report_path.as_posix()) if not preparation_report_path.is_absolute() else preparation_report_path
    raw_cohort = preparation_report_path.is_relative_to(root / "artifacts/raw_pdf_cohort")
    report_boundary = root / "artifacts/raw_pdf_cohort" if raw_cohort else root / "artifacts/source_preparation"
    report_bytes = read_bounded_bytes(preparation_report_path, boundary=report_boundary, max_bytes=max_metadata_bytes)
    report = json.loads(report_bytes)
    if not isinstance(report, dict) or report.get("status") != "completed":
        raise ValueError("Source preparation must be completed")
    if raw_cohort:
        if report.get("cohort_type") != "public_raw_pdf_v1" or not isinstance(report.get("cohort"), dict):
            raise ValueError("Preparation report requires an explicit public raw PDF cohort")
        cve = report["cohort"]
    else:
        datasets = report.get("datasets")
        if not isinstance(datasets, dict) or not isinstance(datasets.get("cve"), dict):
            raise ValueError("Preparation report requires a CVE cohort object")
        cve = datasets["cve"]
    if type(cve.get("sample_count")) is not int or cve["sample_count"] <= 0:
        raise ValueError("Locked sample count must be a positive integer")
    permitted_labels = {"benign", "malicious", "unlabeled"} if raw_cohort else {"benign", "malicious"}
    if not isinstance(cve.get("labels"), dict) or set(cve["labels"]) - permitted_labels:
        raise ValueError("Locked cohort must have binary label counts")
    if any(type(value) is not int or value < 0 for value in cve["labels"].values()):
        raise ValueError("Locked label counts must be nonnegative integers")
    if _local_path(root, cve["manifest_path"]) != manifest_path:
        raise ValueError("Manifest path differs from the preparation lock")
    manifest_bytes = read_bounded_bytes(manifest_path, boundary=root / "data/processed", max_bytes=max_metadata_bytes)
    digest = hashlib.sha256(manifest_bytes).hexdigest()
    if digest != validate_sha256(cve["manifest_sha256"]):
        raise ValueError("Manifest checksum differs from the preparation lock")
    inventory = report["source_inventory"]
    if not isinstance(inventory, list) or len(inventory) > max_samples + 16:
        raise ValueError("Source inventory exceeds the sample cap")
    by_hash: dict[str, list[Path]] = {}
    for item in inventory:
        if not isinstance(item, dict):
            raise ValueError("Source inventory records must be objects")
        path = _local_path(root, item["path"])
        if path.suffix.lower() != ".pdf":
            continue
        if not path.is_relative_to(root / "data/raw"):
            raise ValueError("Acquisition inventory PDF is outside data/raw")
        by_hash.setdefault(validate_sha256(item["sha256"]), []).append(path)
    reader = csv.DictReader(io.StringIO(manifest_bytes.decode("utf-8-sig"), newline=""))
    header = reader.fieldnames or []
    if not REQUIRED_COLUMNS.issubset(header) or len(header) != len(set(header)) or len(header) > 32:
        raise ValueError("Manifest requires unique sample_id, Label, PDF path and SHA-256 columns")
    samples: list[PdfSample] = []
    identifiers: set[str] = set()
    hash_assignments: dict[str, tuple[int, str | None]] = {}
    label_counts = {name: 0 for name in sorted(permitted_labels)}
    for row in reader:
        if len(samples) >= max_samples or None in row or any(value is None for value in row.values()):
            raise ValueError("Invalid manifest row width or sample cap")
        sample_id = row["sample_id"]
        if not sample_id or sample_id != sample_id.strip() or sample_id in identifiers:
            raise ValueError("Manifest sample IDs must be nonempty and unique")
        identifiers.add(sample_id)
        if row["Label"] not in ({"0", "1", ""} if raw_cohort else {"0", "1"}):
            raise ValueError("Manifest Label must be 0 or 1 (malicious)")
        label = int(row["Label"]) if row["Label"] else None
        pdf_sha = validate_sha256(row["pdf_sha256"])
        if raw_cohort and sample_id != "public_pdf:" + pdf_sha:
            raise ValueError("Raw cohort sample identity differs from its PDF hash")
        declared_path = _local_path(root, row["pdf_relative_path"])
        if declared_path.suffix.lower() != ".pdf":
            raise ValueError("Manifest must reference a PDF path")
        candidates = by_hash.get(pdf_sha, [])
        if len(candidates) != 1:
            raise ValueError("Manifest PDF has no unique acquired raw-file mapping")
        raw_path = candidates[0]
        if declared_path != raw_path and not declared_path.is_relative_to(_local_path(root, cve["path"])):
            raise ValueError("Manifest PDF path is outside its locked cohort")
        split = row.get("split")
        if split is not None and split not in {"train", "validation", "test"}:
            raise ValueError("Unrecognized manifest partition")
        if pdf_sha in hash_assignments and hash_assignments[pdf_sha] != (label, split):
            raise ValueError("Duplicate PDF hash has conflicting labels or crosses partitions")
        hash_assignments[pdf_sha] = (label, split)
        data = read_bounded_bytes(raw_path, boundary=root / "data/raw", max_bytes=max_pdf_bytes)
        if len(data) < 2 or hashlib.sha256(data).hexdigest() != pdf_sha:
            raise ValueError("Raw PDF checksum or minimum byte length differs from the manifest")
        if raw_cohort and data[:5] != b"%PDF-":
            raise ValueError("Raw cohort requires strict leading PDF magic")
        samples.append(PdfSample(sample_id, label, raw_path, pdf_sha, row.get("label_source", "unspecified"), split))
        label_counts["unlabeled" if label is None else "malicious" if label else "benign"] += 1
    if not samples or len(samples) != cve["sample_count"] or len(by_hash) != len(hash_assignments):
        raise ValueError("Manifest does not cover the full acquired PDF cohort")
    if any(label_counts[name] != cve["labels"].get(name, 0) for name in label_counts):
        raise ValueError("Manifest labels differ from the locked cohort summary")
    provenance = {
        "manifest_path": str(manifest_path.relative_to(root)),
        "manifest_sha256": digest,
        "preparation_report_path": str(preparation_report_path.relative_to(root)),
        "preparation_report_sha256": hashlib.sha256(report_bytes).hexdigest(),
        "sample_count": len(samples),
        "unique_pdf_hashes": len(hash_assignments),
        "label_counts": label_counts,
        "scope": "Independent acquired raw PDF cohort; historical RIT split unchanged" if raw_cohort else "Independent CVE-T4PDF cohort; no RIT Protocol G assignment",
        "raw_checksum_match_fraction": 1.0,
    }
    return samples, provenance

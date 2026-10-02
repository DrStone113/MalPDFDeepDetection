"""Bounded local dataset preparation and historical Protocol G verification.

PDFs are copied and hashed as opaque bytes. Only reviewed CSV/Parquet archive
members are decompressed; no source is modified, rendered, executed or fetched.
"""

from __future__ import annotations

import csv
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path, PurePosixPath
import platform
import stat
import subprocess
import tempfile
from typing import Any
import zipfile

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from malpdf.data.cic_source_fidelity import inspect_cic_sources
from malpdf.data.rit_pdfmal import load_rit_pdfmal, sha256_file
from malpdf.data.rit_pdfmal_split import create_rit_pdfmal_split
from malpdf.experiments.protocol_g_benchmark import load_saved_protocol_g_split
from malpdf.experiments.protocol_p import repository_git_state
from malpdf.reproducibility import set_random_seed
from malpdf.static.schema import RIT_FEATURES


class SourcePreparationError(ValueError):
    """A source, resource cap or immutable provenance check failed."""


@dataclass(frozen=True)
class PreparationLimits:
    max_file_bytes: int = 16 * 1024 * 1024
    max_archive_members: int = 16
    max_compression_ratio: int = 200
    max_total_output_bytes: int = 32 * 1024 * 1024
    max_rows: int = 100_000
    max_columns: int = 128

    def __post_init__(self) -> None:
        if any(type(value) is not int or value <= 0 for value in asdict(self).values()):
            raise SourcePreparationError("Resource limits must be positive integers")


SOURCE_DIRECTORIES = {
    "rit_pdfmal_2026": "data/raw/RIT-PDFMal-2026",
    "cic_evasive_kaggle": "data/raw/cic_evasive",
    "cve_t4pdf": "data/raw/cve_t4pdf",
}
CVE_MANIFEST_COLUMNS = ["sample_id", "Label", "pdf_relative_path", "pdf_sha256", "label_source"]


def _write_json(path: Path, data: Any) -> None:
    with path.open("x", encoding="utf-8") as output:
        json.dump(data, output, indent=2, ensure_ascii=False, allow_nan=False)
        output.write("\n")


def _regular_file(path: Path, boundary: Path, limit: int) -> None:
    if not path.is_relative_to(boundary):
        raise SourcePreparationError("Source path escapes its allowed directory")
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise SourcePreparationError("Symbolic links are not allowed")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise SourcePreparationError("Input must be a regular file within the size cap")


def extract_table_archive(
    archive_path: Path,
    output_path: Path,
    *,
    expected_member: str,
    limits: PreparationLimits,
    password: bytes | None = None,
    max_output_bytes: int | None = None,
) -> None:
    """Extract exactly one reviewed table, rejecting unsafe paths and ZIP bombs."""
    _regular_file(archive_path, archive_path.parent, limits.max_file_bytes)
    with zipfile.ZipFile(archive_path) as archive:
        members = archive.infolist()
        if len(members) > limits.max_archive_members:
            raise SourcePreparationError("Archive member count exceeds the cap")
        for member in members:
            path = PurePosixPath(member.filename)
            if (
                path.is_absolute() or ".." in path.parts or "\\" in member.filename
                or stat.S_ISLNK(member.external_attr >> 16) or member.is_dir()
                or member.file_size > min(limits.max_file_bytes, max_output_bytes if max_output_bytes is not None else limits.max_file_bytes)
                or member.file_size > max(member.compress_size, 1) * limits.max_compression_ratio
                or member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
            ):
                raise SourcePreparationError("Unsafe archive member or resource limit")
        if len(members) != 1 or members[0].filename != expected_member:
            raise SourcePreparationError("Archive differs from the reviewed table inventory")
        if Path(expected_member).suffix.lower() not in {".csv", ".parquet"}:
            raise SourcePreparationError("Only CSV/Parquet extraction is allowed")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(members[0], pwd=password) as content, output_path.open("xb") as output:
            total = 0
            for chunk in iter(lambda: content.read(64 * 1024), b""):
                total += len(chunk)
                if total > min(limits.max_file_bytes, max_output_bytes if max_output_bytes is not None else limits.max_file_bytes):
                    raise SourcePreparationError("Decompressed bytes exceed the cap")
                output.write(chunk)
        output_path.chmod(0o600)
        if total != members[0].file_size:
            raise SourcePreparationError("Decompressed size does not match the ZIP directory")


def _acquisition_reference(root: Path, category: str, limits: PreparationLimits) -> dict[str, Any]:
    candidates = []
    for path in sorted((root / "artifacts/dataset_acquisition" / category).glob("run_*/download_manifest.json")):
        _regular_file(path, root, limits.max_file_bytes)
        metadata = json.loads(path.read_text(encoding="utf-8"))
        if metadata.get("status") == "completed" and metadata.get("destination") == SOURCE_DIRECTORIES[category]:
            candidates.append((path, metadata))
    if len(candidates) != 1:
        raise SourcePreparationError(f"Expected one completed acquisition manifest for {category}")
    path, metadata = candidates[0]
    records = list(metadata["files"])
    if metadata.get("archive"):
        records.append(metadata["archive"])
    checksums = {}
    for record in records:
        name = record["path"]
        relative = PurePosixPath(name)
        checksum = record.get("sha256", record.get("local_sha256"))
        if relative.is_absolute() or ".." in relative.parts or "\\" in name or name in checksums:
            raise SourcePreparationError("Unsafe or duplicate acquisition inventory path")
        if not isinstance(checksum, str) or len(checksum) != 64 or any(c not in "0123456789abcdef" for c in checksum):
            raise SourcePreparationError("Invalid acquisition SHA-256")
        checksums[name] = checksum
    return {"path": str(path.relative_to(root)), "sha256": sha256_file(path), "checksums": checksums}


def _verify_input(path: Path, raw_root: Path, reference: dict[str, Any], limits: PreparationLimits) -> str:
    _regular_file(path, raw_root, limits.max_file_bytes)
    observed = sha256_file(path)
    expected = reference["checksums"].get(str(path.relative_to(raw_root).as_posix()))
    if expected != observed:
        raise SourcePreparationError("Source checksum differs from its acquisition manifest")
    return observed


def _copy_bytes(source: Path, output: Path, max_bytes: int) -> None:
    if source.stat().st_size > max_bytes:
        raise SourcePreparationError("Binary copy exceeds the remaining output cap")
    output.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as content, output.open("xb") as destination:
        total = 0
        for chunk in iter(lambda: content.read(64 * 1024), b""):
            total += len(chunk)
            if total > max_bytes:
                raise SourcePreparationError("Binary copy exceeds the byte cap")
            destination.write(chunk)
    output.chmod(0o600)


def _publish_manifest(candidate: Path, destination: Path) -> None:
    """Publish complete bytes atomically and refuse an existing manifest."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".protocol-g-", dir=destination.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output, candidate.open("rb") as content:
            for chunk in iter(lambda: content.read(64 * 1024), b""):
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        os.link(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def verify_protocol_g(
    frame: pd.DataFrame,
    dataset_path: Path,
    root: Path,
    output_directory: Path,
    *,
    create_missing_manifest: bool = False,
    manifest_path: Path | None = None,
    limits: PreparationLimits = PreparationLimits(),
) -> dict[str, Any]:
    """Verify the historical lock; creation is an explicit, absence-only option."""
    reference_path = root / "reports/experiments/protocol_g/seed42/split_summary.json"
    _regular_file(reference_path, root, limits.max_file_bytes)
    reference = json.loads(reference_path.read_text(encoding="utf-8"))
    dataset_sha = sha256_file(dataset_path)
    if reference.get("seed") != 42 or reference.get("dataset_sha256") != dataset_sha:
        raise SourcePreparationError("Dataset/seed differs from the historical Protocol G lock")
    selected = manifest_path or root / "data/processed/rit-pdfmal-2026_split_manifest.csv"
    if not selected.is_absolute():
        selected = root / selected
    if (
        not selected.is_relative_to(root / "data/processed") or ".." in selected.parts
        or selected.suffix.lower() != ".csv" or "protocol_p" in {part.casefold() for part in selected.parts}
        or any(part.is_symlink() for part in selected.parents)
    ):
        raise SourcePreparationError("Manifest must be inside data/processed")
    created = False
    if not selected.exists():
        if selected.is_symlink():
            raise SourcePreparationError("Manifest must not be a symbolic link")
        if not create_missing_manifest:
            return {"status": "missing_manifest", "match_fraction": None, "manifest": str(selected.relative_to(root))}
        manifest, _ = create_rit_pdfmal_split(frame, seed=42)
        candidate = output_directory / "rit-pdfmal-2026_split_manifest.csv"
        # The historical Windows CSV uses CRLF; preserve its exact locked bytes.
        content = manifest.to_csv(index=False, lineterminator="\r\n").encode("utf-8")
        existing_bytes = sum(path.stat().st_size for path in output_directory.parent.rglob("*") if path.is_file())
        if len(content) > limits.max_file_bytes or existing_bytes + len(content) > limits.max_total_output_bytes:
            raise SourcePreparationError("Manifest exceeds the prepared-output cap")
        with candidate.open("xb") as output:
            output.write(content)
        candidate.chmod(0o600)
        if sha256_file(candidate) != reference["split_manifest_sha256"]:
            raise SourcePreparationError("Generated manifest differs from the historical checksum")
        load_saved_protocol_g_split(frame, dataset_sha, root, seed=42, manifest_path=candidate)
        _publish_manifest(candidate, selected)
        created = True
    _regular_file(selected, root / "data/processed", limits.max_file_bytes)
    before = sha256_file(selected)
    if before != reference["split_manifest_sha256"]:
        raise SourcePreparationError("Saved manifest differs from the historical checksum")
    _, _, summary = load_saved_protocol_g_split(frame, dataset_sha, root, seed=42, manifest_path=selected)
    if sha256_file(selected) != before:
        raise SourcePreparationError("Saved manifest changed during validation")
    sample_overlap = {}
    saved = pd.read_csv(selected)
    for left, right in (("train", "validation"), ("train", "test"), ("validation", "test")):
        sample_overlap[f"{left}_{right}"] = len(set(saved.loc[saved.split == left, "sample_id"]) & set(saved.loc[saved.split == right, "sample_id"]))
    if any(sample_overlap.values()):
        raise SourcePreparationError("Sample identifiers overlap across partitions")
    return {"status": "verified", "match_fraction": 1.0, "manifest_created": created, "manifest": str(selected.relative_to(root)), "sample_id_overlap": sample_overlap, **summary}


def _append_log(root: Path, report: dict[str, Any]) -> None:
    sources = report["datasets"]
    counts = "; ".join(f"{name}: {item['sample_count']} {item['unit']}, labels {json.dumps(item['labels'], sort_keys=True)}" for name, item in sources.items())
    g = sources.get("rit", {}).get("protocol_g", {})
    notes = f"Local extraction/copy and schema audit; {counts}. Protocol G: {g.get('status', 'not_evaluated')}; seed 42. Creation of an absent manifest explicitly enabled: {report['create_missing_manifest']}. Source bytes/checksums preserved; PDFs only copied/hashed; CIC/CVE are separate from the RIT split. ML metrics N/A: no model evaluation."
    if g.get("status") == "verified":
        partitions = {name: item["rows"] for name, item in g["partition_statistics"].items()}
        notes += f" RIT match fraction {g['match_fraction']}; partition rows {json.dumps(partitions, sort_keys=True)}; sample-ID overlap {json.dumps(g['sample_id_overlap'], sort_keys=True)}; group-overlap checks passed. Locked manifest SHA-256 `{g['split_manifest_sha256']}`; manifest created {g['manifest_created']}."
    if "cve" in sources:
        cve = sources["cve"]
        notes += f" CVE manifest `{cve['manifest_path']}`; Label={cve['label_assignment']['Label']}, label source `{cve['label_assignment']['label_source']}`; PDF paths are repository-relative."
    if report.get("error"):
        notes += " Failure details are in the ignored preparation report."
    fields = [report["finished_at_utc"], report["run_id"], f"preparation / {report['status']}", "G / 42", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", f"`{report['code_commit_sha']}`", report["environment"]["git_worktree"]["status"], f"`{report['report_path']}`; `{report['output_directory']}/`", notes]
    row = "| " + " | ".join(str(field).replace("|", "\\|").replace("\n", " ") for field in fields) + " |\n"
    with (root / "reports/research_log.md").open("a", encoding="utf-8") as output:
        output.write(row)


def prepare_source_datasets(
    repository_root: str | Path,
    *,
    limits: PreparationLimits = PreparationLimits(),
    seed: int = 42,
    create_missing_manifest: bool = False,
    label_cve_malicious: bool = False,
    manifest_path: Path | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    """Prepare all three local sources into new ignored run directories."""
    if type(seed) is not int or seed != 42:
        raise SourcePreparationError("This preparation locks Protocol G seed to 42")
    if type(label_cve_malicious) is not bool:
        raise SourcePreparationError("CVE malicious labeling requires an explicit boolean option")
    set_random_seed(seed)
    root = Path(repository_root).resolve()
    revision = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, check=False)
    commit = revision.stdout.strip() if revision.returncode == 0 else "unavailable"
    identifier = run_id or f"run_{datetime.now(timezone.utc):%Y%m%dT%H%M%S%fZ}_{commit[:12]}"
    if not identifier or identifier in {".", ".."} or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in identifier):
        raise SourcePreparationError("Unsafe run identifier")
    output_root = root / "data/processed/source_preparation" / identifier
    audit_root = root / "artifacts/source_preparation" / identifier
    for directory in (output_root, audit_root):
        if directory.exists() or any(part.is_symlink() for part in (directory, *directory.parents)):
            raise SourcePreparationError("Run path exists or contains a symbolic link")
    output_root.mkdir(parents=True, exist_ok=False)
    audit_root.mkdir(parents=True, exist_ok=False)
    environment = {"python": platform.python_version(), "packages": {name: importlib.metadata.version(name) for name in ("malpdf", "numpy", "pandas", "pyarrow")}, "git_worktree": repository_git_state(root), "preparation_module_sha256": sha256_file(Path(__file__)), "protocol_g_logic_sha256": sha256_file(Path(create_rit_pdfmal_split.__code__.co_filename))}
    report: dict[str, Any] = {"run_id": identifier, "started_at_utc": datetime.now(timezone.utc).isoformat(), "code_commit_sha": commit, "seed": seed, "create_missing_manifest": create_missing_manifest, "status": "started", "environment": environment, "datasets": {}, "source_inventory": [], "output_directory": str(output_root.relative_to(root)), "report_path": str((audit_root / "preparation_report.json").relative_to(root))}
    try:
        cve_label_assignment = {"Label": 1 if label_cve_malicious else None, "label_source": "user_requested_malicious" if label_cve_malicious else "unlabeled", "scope": "CVE PDF inventory from the verified acquisition manifest"}
        _write_json(audit_root / "locked_methodology.json", {"seed": seed, "limits": asdict(limits), "split_proportions": {"train": 0.6, "validation": 0.2, "test": 0.2}, "create_missing_manifest": create_missing_manifest, "manifest_csv_line_ending": "CRLF; historical byte-level lock", "sources": SOURCE_DIRECTORIES, "pdf_policy": "Opaque binary copy/hash only; explicit label assignment recorded separately", "cve_label_assignment": cve_label_assignment, "cic_policy": "Separate third-party cohort; no RIT split assignment", "code_commit_sha": commit})
        _write_json(audit_root / "environment_metadata.json", environment)
        references = {category: _acquisition_reference(root, category, limits) for category in SOURCE_DIRECTORIES}
        _write_json(audit_root / "acquisition_references.json", references)

        def verify_input(category: str, source: Path) -> str:
            digest = _verify_input(source, root / SOURCE_DIRECTORIES[category], references[category], limits)
            report["source_inventory"].append({"path": str(source.relative_to(root)), "sha256": digest})
            return digest

        def remaining_output_bytes() -> int:
            used = sum(path.stat().st_size for path in output_root.rglob("*") if path.is_file())
            return limits.max_total_output_bytes - used

        rit_archive = root / SOURCE_DIRECTORIES["rit_pdfmal_2026"] / "rit-pdfmal-2026.csv.zip"
        verify_input("rit_pdfmal_2026", rit_archive)
        rit_path = output_root / "rit/rit-pdfmal-2026.csv"
        # Public archive password documented by the dataset publisher.
        extract_table_archive(rit_archive, rit_path, expected_member=rit_path.name, limits=limits, password=b"pdfmal", max_output_bytes=remaining_output_bytes())
        with rit_path.open(encoding="utf-8-sig", newline="") as content:
            reader = csv.reader(content)
            header = next(reader, None)
            if header != [*RIT_FEATURES, "Label"] or len(header) > limits.max_columns:
                raise SourcePreparationError("RIT header differs from the canonical schema")
            for position, row in enumerate(reader, start=1):
                if position > limits.max_rows or len(row) != len(RIT_FEATURES) + 1:
                    raise SourcePreparationError("RIT row count or width exceeds the schema cap")
        rit = load_rit_pdfmal(rit_path)
        if list(rit.columns) != [*RIT_FEATURES, "Label"] or len(rit) > limits.max_rows or len(rit.columns) > limits.max_columns:
            raise SourcePreparationError("RIT schema/dimensions differ from the canonical table")
        if not all(pd.api.types.is_numeric_dtype(rit[column]) for column in rit) or not np.isfinite(rit.to_numpy(dtype=float)).all() or set(rit.Label.unique()) != {0, 1}:
            raise SourcePreparationError("RIT requires finite numeric features and binary raw labels")
        report["datasets"]["rit"] = {"path": str(rit_path.relative_to(root)), "sha256": sha256_file(rit_path), "sample_count": len(rit), "columns": list(rit.columns), "data_types": {column: str(rit[column].dtype) for column in rit}, "unit": "rows", "labels": {"benign": int((rit.Label == 0).sum()), "malicious": int((rit.Label == 1).sum())}, "schema_status": "verified"}
        report["datasets"]["rit"]["protocol_g"] = verify_protocol_g(rit, rit_path, root, rit_path.parent, create_missing_manifest=create_missing_manifest, manifest_path=manifest_path, limits=limits)

        cic_root = root / SOURCE_DIRECTORIES["cic_evasive_kaggle"]
        cic_archive = cic_root / "cic-evasive-pdfmal2022-v2.zip"
        verify_input("cic_evasive_kaggle", cic_archive)
        source_cic_sha = verify_input("cic_evasive_kaggle", cic_root / "PDFMalware2022.parquet")
        cic_path = output_root / "cic_evasive/PDFMalware2022.parquet"
        extract_table_archive(cic_archive, cic_path, expected_member=cic_path.name, limits=limits, max_output_bytes=remaining_output_bytes())
        if sha256_file(cic_path) != source_cic_sha:
            raise SourcePreparationError("Extracted CIC table differs from the acquired Parquet")
        with cic_path.open("rb") as content:
            header = content.read(4)
            content.seek(-4, 2)
            if header != b"PAR1" or content.read(4) != b"PAR1":
                raise SourcePreparationError("Invalid Parquet signatures")
        metadata = pq.ParquetFile(cic_path).metadata
        decoded_bytes = sum(metadata.row_group(index).total_byte_size for index in range(metadata.num_row_groups))
        if metadata.num_rows > limits.max_rows or metadata.num_columns > limits.max_columns or decoded_bytes > limits.max_total_output_bytes:
            raise SourcePreparationError("CIC dimensions exceed the audit cap")
        cic = inspect_cic_sources(cic_path.parent)[0]["summary"]
        if cic["target_summary"]["target_column"] is None or cic["target_summary"]["unexpected_raw_label_counts"]:
            raise SourcePreparationError("CIC target labels cannot be validated")
        report["datasets"]["cic"] = {"path": str(cic_path.relative_to(root)), "sha256": cic["sha256"], "sample_count": cic["dimensions"]["rows"], "columns": cic["columns_in_original_order"], "data_types": cic["data_types"], "unit": "rows", "labels": cic["target_summary"]["recognized_class_counts"], "schema_status": "verified", "population_fidelity": cic["population_fidelity_classification"], "candidate_predictive_feature_count": cic["candidate_predictive_feature_count"], "identifier_column": cic["identifier_column"], "unexpected_row_diagnostics": cic["unexpected_row_diagnostics"], "protocol_g": {"status": "not_applicable", "reason": "Independent CIC feature-table cohort, not RIT sample identities"}}

        cve_root = root / SOURCE_DIRECTORIES["cve_t4pdf"]
        expected_pdf_paths = sorted(name for name in references["cve_t4pdf"]["checksums"] if name.lower().endswith(".pdf"))
        actual_pdf_paths = sorted(path.relative_to(cve_root).as_posix() for path in cve_root.rglob("*") if path.suffix.lower() == ".pdf")
        if not expected_pdf_paths or actual_pdf_paths != expected_pdf_paths or len(expected_pdf_paths) > limits.max_archive_members:
            raise SourcePreparationError("CVE PDF inventory differs from the acquisition lock")
        pdf_inventory = []
        for name in expected_pdf_paths:
            source = cve_root / name
            digest = verify_input("cve_t4pdf", source)
            output = output_root / "cve_t4pdf" / name
            _copy_bytes(source, output, min(limits.max_file_bytes, remaining_output_bytes()))
            if sha256_file(output) != digest:
                raise SourcePreparationError("CVE binary copy checksum mismatch")
            pdf_inventory.append({"sample_id": f"cve_t4pdf:{name}", "path": str(output.relative_to(root)), "sha256": digest, "bytes": output.stat().st_size, "label": cve_label_assignment["Label"], "label_source": cve_label_assignment["label_source"]})
        _write_json(audit_root / "cve_pdf_inventory.json", pdf_inventory)
        cve_manifest = output_root / "cve_t4pdf/source_pdf_manifest.csv"
        with cve_manifest.open("x", encoding="utf-8", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=CVE_MANIFEST_COLUMNS)
            writer.writeheader()
            for item in pdf_inventory:
                writer.writerow({"sample_id": item["sample_id"], "Label": item["label"], "pdf_relative_path": item["path"], "pdf_sha256": item["sha256"], "label_source": item["label_source"]})
        cve_manifest.chmod(0o600)
        _regular_file(cve_manifest, output_root, limits.max_file_bytes)
        report["datasets"]["cve"] = {"path": str((output_root / "cve_t4pdf").relative_to(root)), "sample_count": len(pdf_inventory), "columns": [], "unit": "pdf_files", "labels": {"malicious" if label_cve_malicious else "unlabeled": len(pdf_inventory)}, "label_assignment": cve_label_assignment, "manifest_path": str(cve_manifest.relative_to(root)), "manifest_sha256": sha256_file(cve_manifest), "manifest_columns": CVE_MANIFEST_COLUMNS, "schema_status": "no_tabular_schema", "protocol_g": {"status": "not_applicable", "reason": "Separate CVE PDF cohort without RIT sample mapping"}}
        for item in report["source_inventory"]:
            if sha256_file(root / item["path"]) != item["sha256"]:
                raise SourcePreparationError("A source changed during preparation")
        output_bytes = sum(path.stat().st_size for path in output_root.rglob("*") if path.is_file())
        if output_bytes > limits.max_total_output_bytes:
            raise SourcePreparationError("Total prepared bytes exceed the cap")
        report["total_output_bytes"] = output_bytes
        for item in report["datasets"].values():
            item["label_distribution"] = {label: {"count": count, "fraction": count / item["sample_count"] if item["sample_count"] else None} for label, count in item["labels"].items()}
        with (audit_root / "dataset_summary.csv").open("x", encoding="utf-8", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=["dataset", "samples", "unit", "columns", "benign", "malicious", "unlabeled", "protocol_g_status"])
            writer.writeheader()
            for name, item in report["datasets"].items():
                writer.writerow({"dataset": name, "samples": item["sample_count"], "unit": item["unit"], "columns": len(item["columns"]) if item["columns"] else "N/A", **{label: item["labels"].get(label, 0) for label in ("benign", "malicious", "unlabeled")}, "protocol_g_status": item["protocol_g"]["status"]})
        with (audit_root / "SHA256SUMS").open("x", encoding="ascii") as output:
            for path in sorted(output_root.rglob("*")):
                if path.is_file():
                    output.write(f"{sha256_file(path)}  {path.relative_to(output_root).as_posix()}\n")
        report["status"] = "completed" if report["datasets"]["rit"]["protocol_g"]["status"] == "verified" else "prepared_protocol_g_unverified"
    except Exception as error:
        report["status"] = "failed"
        report["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        report["finished_at_utc"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        _write_json(audit_root / "preparation_report.json", report)
        _append_log(root, report)
    return report

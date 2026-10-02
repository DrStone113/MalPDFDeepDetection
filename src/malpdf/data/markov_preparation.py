"""Manifest-locked Markov cache preparation with append-only research evidence."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import importlib.metadata
import json
from pathlib import Path
import platform
import subprocess

from malpdf.data.manifest_validator import validate_locked_source_manifest
from malpdf.data.rit_pdfmal import sha256_file
from malpdf.experiments.protocol_p import repository_git_state
from malpdf.reproducibility import set_random_seed
from malpdf.static.cache_manager import cache_markov_pdf
from malpdf.static.markov import MARKOV_ALGORITHM


def _write_json(path: Path, value: dict) -> None:
    with path.open("x", encoding="utf-8") as output:
        json.dump(value, output, indent=2, allow_nan=False)
        output.write("\n")


def build_markov_cache(
    repository_root: Path,
    manifest_path: Path,
    preparation_report_path: Path,
    *,
    seed: int = 42,
    max_pdf_bytes: int = 10 * 1024 * 1024,
    max_metadata_bytes: int = 2 * 1024 * 1024,
    max_samples: int = 100_000,
    run_id: str | None = None,
) -> dict:
    if type(seed) is not int or seed != 42:
        raise ValueError("This preparation records seed 42")
    if any(type(value) is not int or value <= 0 for value in (max_pdf_bytes, max_metadata_bytes, max_samples)):
        raise ValueError("Resource caps must be positive integers")
    root = Path(repository_root).resolve()
    set_random_seed(seed)
    commit = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, check=False).stdout.strip() or "unavailable"
    identifier = run_id or f"run_{datetime.now(timezone.utc):%Y%m%dT%H%M%S%fZ}_{commit[:12]}"
    if not identifier or identifier in {".", ".."} or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in identifier):
        raise ValueError("Unsafe run identifier")
    report_directory = root / "reports/experiments/markov_cache" / identifier
    artifact_directory = root / "artifacts/markov_cache" / identifier
    cache_directory = root / "data/processed/markov_cache"
    for directory in (report_directory, artifact_directory):
        if directory.exists() or any(part.is_symlink() for part in (directory, *directory.parents)):
            raise ValueError("Run directory exists or contains a symbolic link")
    report_directory.mkdir(parents=True, exist_ok=False)
    artifact_directory.mkdir(parents=True, exist_ok=False)
    records = []
    report = {"run_id": identifier, "started_at_utc": datetime.now(timezone.utc).isoformat(), "seed": seed, "code_commit_sha": commit, "git_worktree": repository_git_state(root), "status": "started", "created": 0, "reused": 0, "sample_count": None, "cache_directory": str(cache_directory.relative_to(root)), "report_path": str((report_directory / "run_summary.json").relative_to(root)), "inventory_path": str((artifact_directory / "cache_inventory.csv").relative_to(root))}
    try:
        _write_json(report_directory / "locked_methodology.json", {"algorithm": MARKOV_ALGORITHM, "seed": seed, "manifest_path": str(manifest_path), "preparation_report_path": str(preparation_report_path), "limits": {"max_pdf_bytes": max_pdf_bytes, "max_metadata_bytes": max_metadata_bytes, "max_samples": max_samples}, "matrix_shape": [256, 256], "channels": 1, "dtype": "float32", "normalization": "P(next byte | current byte); unobserved rows stay zero", "cache_filename": "<pdf_sha256>.npy", "safety": "Bounded static binary reads only; no parser/rendering/execution", "existing_cache_policy": "Checksum/header/normalization validation; refuse corruption and overwrites", "metrics": "N/A: cache preparation only", "protocol_g": "RIT split untouched; independent CVE cohort", "code_commit_sha": commit})
        _write_json(report_directory / "environment_metadata.json", {"python": platform.python_version(), "packages": {name: importlib.metadata.version(name) for name in ("malpdf", "numpy", "pyyaml")}, "code_commit_sha": commit, "git_worktree": report["git_worktree"], "code_sha256": {name: sha256_file(root / name) for name in ("src/malpdf/data/markov_preparation.py", "src/malpdf/data/manifest_validator.py", "src/malpdf/static/markov.py", "src/malpdf/static/cache_manager.py", "src/malpdf/static/safety.py", "scripts/02_build_markov_cache.py", "configs/markov_cache.yaml") if (root / name).is_file()}})
        with (report_directory / "model_comparison.csv").open("x", encoding="utf-8", newline="") as output:
            writer = csv.writer(output)
            writer.writerow(["model", "partition", "f1_malicious", "mcc", "ece", "brier_score", "status", "reason"])
            writer.writerow(["N/A"] * 6 + ["not_evaluated", "Static cache preparation; no model or calibration evaluation"])
        samples, provenance = validate_locked_source_manifest(root, manifest_path, preparation_report_path, max_pdf_bytes=max_pdf_bytes, max_metadata_bytes=max_metadata_bytes, max_samples=max_samples)
        report["sample_count"] = len(samples)
        report["provenance"] = provenance
        _write_json(report_directory / "source_provenance.json", provenance)
        for sample in samples:
            result = cache_markov_pdf(sample.raw_path, sample.pdf_sha256, raw_boundary=root / "data/raw", cache_directory=cache_directory, max_pdf_bytes=max_pdf_bytes)
            records.append({"sample_id": sample.sample_id, "Label": sample.label, "label_source": sample.label_source, "raw_relative_path": str(sample.raw_path.relative_to(root)), "pdf_sha256": sample.pdf_sha256, "cache_relative_path": str(result["path"].relative_to(root)), "npy_sha256": result["npy_sha256"], "pdf_bytes": result["pdf_bytes"], "status": result["status"]})
            report[result["status"]] += 1
        report["status"] = "completed"
    except BaseException as error:
        report["status"] = "interrupted" if isinstance(error, KeyboardInterrupt) else "failed"
        report["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        report["finished_at_utc"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        with (artifact_directory / "cache_inventory.csv").open("x", encoding="utf-8", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=["sample_id", "Label", "label_source", "raw_relative_path", "pdf_sha256", "cache_relative_path", "npy_sha256", "pdf_bytes", "status"])
            writer.writeheader()
            writer.writerows(records)
        _write_json(report_directory / "run_summary.json", report)
        notes = f"Static byte Markov cache; {len(records)} samples processed, {report['created']} created, {report['reused']} reused. Float32 (256,256), one channel; zero rows for unseen source bytes. SHA-256 source/cache validation; binary-read cap {max_pdf_bytes} bytes; no PDF parser/rendering/execution. RIT Protocol G manifest untouched; independent CVE cohort. Sample hashes stay in ignored data/artifacts. Metrics and ECE bins N/A: no model evaluation."
        fields = [report["finished_at_utc"], identifier, f"cache preparation / {report['status']}", "N/A / 42", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", f"`{commit}`", report["git_worktree"]["status"], f"`{report['report_path']}`; `{report['inventory_path']}`", notes]
        with (root / "reports/research_log.md").open("a", encoding="utf-8") as output:
            output.write("| " + " | ".join(str(value).replace("|", "\\|").replace("\n", " ") for value in fields) + " |\n")
    return report

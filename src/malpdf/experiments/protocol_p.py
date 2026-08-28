"""Output and provenance infrastructure for Protocol P.

Protocol P is a paper-aligned attempt, not an exact reproduction. The paper does
not specify all seeds, hyperparameters, preprocessing decisions, or the exact
zero-variance treatment. This module only prepares a run; it never trains a
model or changes Protocol G artifacts.
"""

from __future__ import annotations

import ctypes
import importlib.metadata
import json
import os
import platform
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from malpdf.data.protocol_p import (
    DEFAULT_PROTOCOL_P_SEED,
    FEATURE_VARIANTS,
    create_protocol_p_split_from_file,
    write_protocol_p_manifest,
)
from malpdf.data.rit_pdfmal import sha256_file
from malpdf.data.rit_pdfmal_paper_alignment import PAPER_BASELINE_RESULTS
from malpdf.models.classical import model_configurations


def _command_output(command: list[str]) -> str | None:
    try:
        result = subprocess.run(command, capture_output=True, check=False, text=True, timeout=3)
    except (OSError, subprocess.SubprocessError):
        return None
    output = result.stdout.strip()
    return output if result.returncode == 0 and output else None


def repository_git_state(repository_root: str | Path) -> dict[str, Any]:
    """Describe the current Git worktree without changing it.

    A benchmark can only claim a clean code revision when Git itself reports an
    empty porcelain status. Failures to inspect Git are reported as unavailable.
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(Path(repository_root)), "status", "--porcelain"],
            capture_output=True,
            check=False,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.SubprocessError):
        return {"status": "unavailable", "porcelain_entries": []}
    if result.returncode != 0:
        return {"status": "unavailable", "porcelain_entries": []}
    entries = [line for line in result.stdout.splitlines() if line]
    return {
        "status": "clean" if not entries else "dirty",
        "porcelain_entries": entries,
    }


def _windows_cpu_model() -> str | None:
    return _command_output(
        ["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name).Trim()"]
    )


def _cpu_model() -> str | None:
    if platform.system() == "Windows":
        return _windows_cpu_model() or platform.processor() or None
    if platform.system() == "Darwin":
        return _command_output(["sysctl", "-n", "machdep.cpu.brand_string"])
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", maxsplit=1)[1].strip()
    except OSError:
        pass
    return platform.processor() or None


def _system_ram_bytes() -> int | None:
    if platform.system() == "Windows":
        class MemoryStatus(ctypes.Structure):
            _fields_ = [
                ("length", ctypes.c_ulong), ("memory_load", ctypes.c_ulong),
                ("total_physical", ctypes.c_ulonglong), ("available_physical", ctypes.c_ulonglong),
                ("total_page_file", ctypes.c_ulonglong), ("available_page_file", ctypes.c_ulonglong),
                ("total_virtual", ctypes.c_ulonglong), ("available_virtual", ctypes.c_ulonglong),
                ("available_extended_virtual", ctypes.c_ulonglong),
            ]

        status = MemoryStatus()
        status.length = ctypes.sizeof(MemoryStatus)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return int(status.total_physical)
        return None
    try:
        return int(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES"))
    except (AttributeError, OSError, ValueError):
        return None


def _nvidia_gpus() -> list[dict[str, Any]] | None:
    output = _command_output(
        ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader,nounits"]
    )
    if output is None:
        return None
    gpus: list[dict[str, Any]] = []
    for line in output.splitlines():
        parts = [part.strip() for part in line.split(",")]
        if len(parts) != 2:
            continue
        try:
            memory_mib: int | None = int(parts[1])
        except ValueError:
            memory_mib = None
        gpus.append({"model": parts[0] or "unavailable", "vram_mib": memory_mib})
    return gpus or None


def _package_version(distribution: str) -> str:
    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return "unavailable"


def collect_environment_metadata(dataset_path: str | Path, repository_root: str | Path) -> dict[str, Any]:
    """Collect detected environment/provenance fields, reporting failures as unavailable."""
    root = Path(repository_root)
    git_sha = _command_output(["git", "-C", str(root), "rev-parse", "HEAD"])
    ram_bytes = _system_ram_bytes()
    gpus = _nvidia_gpus()
    return {
        "python_version": platform.python_version(),
        "implementation": platform.python_implementation(),
        "os_platform": platform.platform(),
        "cpu_model": _cpu_model() or "unavailable",
        "gpu": gpus if gpus is not None else "unavailable",
        "system_ram_bytes": ram_bytes if ram_bytes is not None else "unavailable",
        "library_versions": {
            "numpy": _package_version("numpy"),
            "pandas": _package_version("pandas"),
            "scikit_learn": _package_version("scikit-learn"),
            "xgboost": _package_version("xgboost"),
        },
        "dataset_sha256": sha256_file(dataset_path),
        "git_commit_sha": git_sha or "unavailable",
        "git_working_tree": repository_git_state(root),
    }


@dataclass(frozen=True)
class ProtocolPRunPaths:
    """All derived locations for one immutable Protocol P preparation run."""

    run_id: str
    processed_directory: Path
    artifact_directory: Path
    split_manifest: Path
    split_metadata: Path
    experiment_configuration: Path
    environment_metadata: Path
    metrics_directory: Path
    summary_csv: Path
    confusion_matrices_directory: Path
    model_artifacts_directory: Path


def _safe_run_id(run_id: str) -> str:
    if not run_id or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_." for character in run_id):
        raise ValueError("run_id must be non-empty and contain only letters, numbers, '-', '_', or '.'")
    return run_id


def protocol_p_run_paths(
    repository_root: str | Path, run_id: str
) -> ProtocolPRunPaths:
    """Return dedicated Protocol P paths; no path can point at Protocol G."""
    root = Path(repository_root)
    safe_id = _safe_run_id(run_id)
    processed = root / "data" / "processed" / "protocol_p" / safe_id
    artifacts = root / "artifacts" / "protocol_p" / safe_id
    return ProtocolPRunPaths(
        run_id=safe_id,
        processed_directory=processed,
        artifact_directory=artifacts,
        split_manifest=processed / "protocol_p_split_manifest.csv",
        split_metadata=artifacts / "split_metadata.json",
        experiment_configuration=artifacts / "config" / "experiment_configuration.json",
        environment_metadata=artifacts / "environment" / "environment_metadata.json",
        metrics_directory=artifacts / "metrics",
        summary_csv=artifacts / "metrics" / "summary.csv",
        confusion_matrices_directory=artifacts / "confusion_matrices",
        model_artifacts_directory=artifacts / "models",
    )


def paper_comparison_template() -> list[dict[str, Any]]:
    """Return paper values with empty local slots for a future, honest comparison."""
    return [
        {
            "model": result["model"],
            "paper_metrics": {key: result[key] for key in ("accuracy", "precision", "recall", "f1", "inference_time_ms")},
            "local_metrics": None,
            "absolute_difference": None,
        }
        for result in PAPER_BASELINE_RESULTS
    ]


def prepare_protocol_p_run(
    repository_root: str | Path,
    dataset_path: str | Path,
    *,
    seed: int = DEFAULT_PROTOCOL_P_SEED,
    run_id: str | None = None,
) -> tuple[ProtocolPRunPaths, dict[str, Any]]:
    """Create a new, non-overwriting Protocol P split/provenance run.

    No models are fit. The returned manifest statistics make the eventual run
    reproducible; metrics, confusion matrices, and model locations are prepared
    but intentionally left empty until an explicitly requested benchmark.
    """
    identifier = run_id or f"p-seed{seed}-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}"
    paths = protocol_p_run_paths(repository_root, identifier)
    if paths.processed_directory.exists() or paths.artifact_directory.exists():
        raise FileExistsError(f"Protocol P run already exists; refusing to overwrite: {identifier}")

    manifest, split_result = create_protocol_p_split_from_file(dataset_path, seed=seed)
    paths.artifact_directory.mkdir(parents=True, exist_ok=False)
    paths.metrics_directory.mkdir(parents=True, exist_ok=False)
    paths.confusion_matrices_directory.mkdir(parents=True, exist_ok=False)
    paths.model_artifacts_directory.mkdir(parents=True, exist_ok=False)
    paths.experiment_configuration.parent.mkdir(parents=True, exist_ok=False)
    paths.environment_metadata.parent.mkdir(parents=True, exist_ok=False)
    write_protocol_p_manifest(manifest, paths.split_manifest)

    environment = collect_environment_metadata(dataset_path, repository_root)
    configuration = {
        "protocol": "P",
        "purpose": "Paper-aligned reproduction attempt; not an exact paper reproduction.",
        "paper_ambiguities": [
            "The paper does not publish its split random seed; seed 42 is a project choice.",
            "The paper does not publish full model hyperparameters.",
            "The paper does not fully specify scaling, imputation, encoding, or normalization details.",
            "The paper recommends removing three zero-variance features but does not state exact inclusion for every reported fit.",
        ],
        "dataset": {"path": str(Path(dataset_path)), "sha256": environment["dataset_sha256"]},
        "split": split_result,
        "feature_variants": [asdict(variant) for variant in FEATURE_VARIANTS.values()],
        "model_configurations": model_configurations(seed),
        "paper_comparison_template": paper_comparison_template(),
        "output_locations": {
            "split_manifest": str(paths.split_manifest), "metrics_json_directory": str(paths.metrics_directory),
            "summary_csv": str(paths.summary_csv), "confusion_matrices_directory": str(paths.confusion_matrices_directory),
            "model_artifacts_directory": str(paths.model_artifacts_directory),
        },
        "scope": "No model fitting, hyperparameter optimization, multi-seed evaluation, or cross-validation was performed while preparing this run.",
    }
    paths.split_metadata.write_text(json.dumps(split_result, indent=2) + "\n", encoding="utf-8")
    paths.experiment_configuration.write_text(json.dumps(configuration, indent=2) + "\n", encoding="utf-8")
    paths.environment_metadata.write_text(json.dumps(environment, indent=2) + "\n", encoding="utf-8")
    return paths, {"split": split_result, "environment": environment, "configuration": configuration}

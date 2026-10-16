"""Metadata-only job preparation and console-only CIC static extraction.

This development diagnostic does not fit/evaluate any model and does not
reopen the consumed v9 Final campaign. All per-sample evidence stays private.
"""

from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import zlib

import yaml

from malpdf.extraction.contracts import VERSION
from malpdf.extraction.orchestrator import extract_pdf
from malpdf.provenance.research_runs import ResearchRun, write_json
from malpdf.reproducibility import set_random_seed
from malpdf.static.code_inspector import CodeInspectionLimits, _worker_count
from malpdf.static.lab_guard import require_offline_lab
from malpdf.static.safety import read_bounded_bytes

MANIFESTS = ("split_manifest", "source_manifest", "normalization_manifest")
PREPARE = "pdf_extraction_prepare"


def _read(root, relative, cap=32 * 1024**2):
    return read_bounded_bytes(root / relative, boundary=root, max_bytes=cap)


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def fingerprint(root, limits, arlington_lock=None):
    """Pin generating source, declared environment and effective resource caps."""
    import pikepdf
    import pymupdf
    from malpdf.extraction.byte_images import ByteImageLimits,ALGORITHM
    from malpdf.extraction.plugins import PluginLimits,API_VERSION
    from malpdf.extraction.triggers import TriggerLimits,VERSION as TRIGGER_VERSION
    sources = {}
    for directory in ("src/malpdf", "scripts", "configs"):
        for path in sorted((root / directory).rglob("*")):
            if path.is_file() and path.suffix in {".py", ".yaml", ".toml", ".json"}:
                relative = str(path.relative_to(root))
                sources[relative] = _hash(_read(root, relative))
    sources["pyproject.toml"] = _hash(_read(root, "pyproject.toml"))
    reference={}
    if arlington_lock is not None:
        from malpdf.extraction.arlington_model import load_model
        reference=load_model(root,arlington_lock).provenance
    return {"schema_version": VERSION, "sources": sources, "limits": asdict(limits),
            "arlington_reference":reference,
            "byte_images":{"algorithm":ALGORITHM,"limits":asdict(ByteImageLimits())},
            "plugins":{"api_version":API_VERSION,"enabled":[],"limits":asdict(PluginLimits())},
            "trigger_planner":{"version":TRIGGER_VERSION,"limits":asdict(TriggerLimits())},
            "python": platform.python_version(),
            "platform": platform.platform(), "machine": platform.machine(),
            "native_libraries": {"QPDF":pikepdf.__libqpdf_version__,"MuPDF":pymupdf.VersionFitz,
                                 "zlib_compile":zlib.ZLIB_VERSION,"zlib_runtime":zlib.ZLIB_RUNTIME_VERSION},
            "packages": {name: importlib.metadata.version(name) for name in
                         ("pypdf", "PyMuPDF", "pikepdf", "esprima", "numpy", "pandas", "scikit-learn", "PyYAML")}}


def _configuration(root, config):
    path = Path(config)
    relative = str(path.absolute().relative_to(root))
    cfg = yaml.safe_load(_read(root, relative, 64 * 1024))
    if (not isinstance(cfg,dict) or set(cfg)-{'arlington_lock'} != {"cohort_config", "profile", "seed", "workers", "samples_per_partition", "limits"}
            or cfg["seed"] != 42 or cfg["workers"] != 1 or cfg["samples_per_partition"] != 32
            or cfg["profile"] not in {"fast-static", "deep-static"}):
        raise ValueError("Extraction diagnostic configuration changed")
    if 'arlington_lock' in cfg:
        from malpdf.extraction.arlington_model import load_model
        if cfg['profile']!='deep-static' or not isinstance(cfg['arlington_lock'],str):
            raise ValueError('Invalid Arlington extraction configuration')
        load_model(root,cfg['arlington_lock'])
    cohort = yaml.safe_load(_read(root, cfg["cohort_config"], 64 * 1024))
    if cohort["seed"] != 42 or cohort["samples_per_partition"] != 32:
        raise ValueError("Saved cohort selection changed")
    candidates = {}
    # Related CIC configs must agree; a newer/older incompatible candidate is
    # reported rather than silently chosen by mtime, count, or favorable outcome.
    for candidate in sorted((root / "configs").glob("cic*.yaml")):
        other = yaml.safe_load(_read(root, str(candidate.relative_to(root)), 64 * 1024))
        if isinstance(other, dict) and other.get("prepared_cohort") == cohort.get("prepared_cohort"):
            specs = {key: other[key] for key in MANIFESTS if key in other}
            if specs:
                candidates[str(candidate.relative_to(root))] = specs
    expected = {key: cohort[key] for key in MANIFESTS}
    conflicting = {name: specs for name, specs in candidates.items()
                   if any(spec != expected[key] for key, spec in specs.items())}
    if conflicting:
        raise ValueError("Conflicting CIC manifest candidates: " + json.dumps(conflicting, sort_keys=True))
    return cfg, cohort, CodeInspectionLimits(**cfg["limits"]), candidates


def prepare_job(root, config):
    """Lock 64 metadata records without stat/open/hash of any PDF path.

    Preparation may record a dirty worktree for review. Actual execution requires
    clean committed code matching the sealed source/environment fingerprint.
    """
    from malpdf.experiments.cic_static_benchmark import checked_table, select_subset, verify_label_provenance

    root = Path(root).absolute()
    try:
        cfg, cohort, limits, candidates = _configuration(root, config)
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError):
        with ResearchRun(root, "pdf_extraction_prepare_refused", {
            "protocol": "CIC metadata-only extraction preparation preflight", "pdf_bytes_read": False,
            "test_access": False}, maintenance=True) as refused:
            refused.state.update(status="refused", notes="Configuration/manifest candidate preflight failed; no selection/PDF access. Metrics N/A.")
        raise
    method = {"protocol": "CIC saved Protocol G Train/Validation extraction development",
        "configuration": cfg, "manifest_provenance": {key: cohort[key] for key in MANIFESTS},
        "manifest_candidates": candidates, "test_access": False, "fitting": False,
        "selection": "existing seed42 class/partition SHA rank; 32 Train and 32 exposed Validation; no split regeneration",
        "interpretation": "extraction-only diagnostic; no classifier accuracy/coverage gain claimed",
        "execution": "offline non-root console after clean commit; no rendering, JS execution or CAPE"}
    with ResearchRun(root, PREPARE, method, maintenance=True) as run:
        set_random_seed(42)
        rows = select_subset(checked_table(root, cohort["split_manifest"]), checked_table(root, cohort["source_manifest"]), 32, 42)
        verify_label_provenance(rows, checked_table(root, cohort["normalization_manifest"]))
        lock = {"schema_version": VERSION, "rows": rows, "configuration": cfg,
                "manifest_provenance": {key: cohort[key] for key in MANIFESTS},
                "fingerprint": fingerprint(root, limits,cfg.get('arlington_lock')), "prepared_run": run.identifier,
                "preparation_commit": run.commit, "preparation_worktree": run.state["code_worktree"],
                "selection_sha256": _hash(json.dumps(rows, sort_keys=True, allow_nan=False).encode())}
        write_json(run.artifacts / "job_lock.json", lock)
        counts = Counter((row["split"], row["Label"]) for row in rows)
        write_json(run.report / "preparation_checks.json", {
            "rows": len(rows), "class_partition_counts": {f"{key[0]}/{key[1]}": value for key, value in counts.items()},
            "manifest_provenance": lock["manifest_provenance"], "manifest_candidates": candidates,
            "pdf_bytes_read": False, "test_selected": False, "models_loaded": False,
            "execution_status": "not_run; offline console isolation and clean matching code required"})
        run.state.update(status="completed", rows=len(rows),
            job_lock_sha256=_hash((run.artifacts / "job_lock.json").read_bytes()),
            notes="Metadata-only preparation; 32 Train/32 exposed Validation. PDF bytes not read. Execution not run; no metrics applicable.")
    return run.state


def load_job(root, prepared_run):
    """Revalidate sealed rows against locked manifests, never PDF bytes."""
    from malpdf.experiments.cic_static_benchmark import checked_table, select_subset, verify_label_provenance

    if not re.fullmatch(r"run_[A-Za-z0-9_-]{1,100}", prepared_run):
        raise ValueError("Unsafe prepared-run identifier")
    summary = json.loads(_read(root, f"reports/experiments/{PREPARE}/{prepared_run}/run_summary.json"))
    path = f"artifacts/tmp/maintenance/{PREPARE}/{prepared_run}/job_lock.json"
    content = _read(root, path)
    if summary["status"] != "completed" or _hash(content) != summary["job_lock_sha256"]:
        raise ValueError("Prepared extraction lock changed or incomplete")
    lock = json.loads(content)
    cfg = lock["configuration"]
    limits = CodeInspectionLimits(**cfg["limits"])
    if lock["schema_version"] != VERSION or lock["prepared_run"] != prepared_run or cfg["seed"] != 42 or cfg["workers"] != 1:
        raise ValueError("Extraction lock configuration changed")
    specs = lock["manifest_provenance"]
    expected = select_subset(checked_table(root, specs["split_manifest"]), checked_table(root, specs["source_manifest"]), 32, 42)
    verify_label_provenance(expected, checked_table(root, specs["normalization_manifest"]))
    if (expected != lock["rows"] or _hash(json.dumps(expected, sort_keys=True, allow_nan=False).encode()) != lock["selection_sha256"]
            or any(row["split"] not in {"train", "validation"} for row in expected)):
        raise ValueError("Extraction rows no longer match the locked Train/Validation subset")
    if fingerprint(root, limits,cfg.get('arlington_lock')) != lock["fingerprint"]:
        raise ValueError("Generating code/environment changed; prepare a new job without changing the saved split")
    return lock, limits


def require_extraction_lab(attested, *, repository_root=None):
    """Add credential checks to the established offline/non-root/console guard.

    Check names/presence only; never read credential files or print their contents.
    The human console attestation still covers hypervisor controls we cannot see.
    """
    state = require_offline_lab(attested)
    home = Path.home()
    sensitive = [home / ".aws/credentials", home / ".kaggle/kaggle.json", home / ".git-credentials",
                 home / ".netrc", home / ".config/gcloud/application_default_credentials.json"]
    if repository_root is not None:
        root = Path(repository_root)
        sensitive.extend(root / name for name in (".aws/credentials", ".kaggle/kaggle.json", ".netrc", ".env"))
    ssh = home / ".ssh"
    private_keys = ssh.is_dir() and any(path.name.startswith("id_") and path.suffix != ".pub" for path in ssh.iterdir())
    credential_env = any(value and (name in {"SSH_AUTH_SOCK", "GITHUB_TOKEN", "GH_TOKEN", "OPENAI_API_KEY", "KAGGLE_KEY",
        "KAGGLE_API_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS"}
        or name.endswith(("_TOKEN", "_API_KEY", "_PASSWORD", "_SECRET"))) for name, value in os.environ.items())
    if credential_env or private_keys or any(path.exists() or path.is_symlink() for path in sensitive):
        raise ValueError("Credential presence blocks PDF analysis; use the approved credential-free console LAB")
    return {**state, "agent_forwarding_present": False, "known_credentials_present": False,
            "credential_check_scope": "known paths, SSH id_* keys and credential environment names; console attestation required"}


def run_job(root, prepared_run, *, lab_attested=False):
    """Run once per sealed job, preserving failures and primary evidence."""
    from malpdf.experiments.cic_static_benchmark import clean_code

    root = Path(root).absolute()
    # All preconditions run before the claim or PDF access. We never change NICs.
    try:
        lab = require_extraction_lab(lab_attested, repository_root=root)
        clean_code(root)
        lock, limits = load_job(root, prepared_run)
        _worker_count(1, limits)
    except (OSError, ValueError):
        with ResearchRun(root, "pdf_extraction_refused", {"protocol": "CIC static extraction preflight",
            "test_access": False, "pdf_bytes_read": False}, maintenance=True) as refused:
            refused.state.update(status="refused", notes="Offline LAB, credentials, clean code, locked metadata or worker admission precondition failed; no claim/PDF access. Metrics N/A.")
        raise
    campaign = root / "data/processed/pdf_extraction"
    if any(path.is_symlink() for path in (campaign, *campaign.parents)):
        raise ValueError("Unsafe extraction output path")
    if subprocess.run(["git", "-C", str(root), "check-ignore", "-q", "--", str(campaign / "guard.json")]).returncode:
        raise ValueError("Extraction output must be gitignored")
    campaign.mkdir(parents=True, exist_ok=True, mode=0o700)
    claim = campaign / (prepared_run + ".claim.json")
    method = {"protocol": "CIC saved Protocol G Train/Validation extraction development", "prepared_run": prepared_run,
        "configuration": lock["configuration"], "manifest_provenance": lock["manifest_provenance"],
        "fingerprint": lock["fingerprint"], "test_access": False, "fitting": False,
        "execution": "one attempt; partial rows remain in coverage denominators; no renderer, JS evaluator, Reader or CAPE",
        "metrics": "extraction status/timing only; F1/MCC/ECE/Brier N/A"}
    with ResearchRun(root, "pdf_extraction", method, maintenance=True) as run:
        run.state.update(rows=0, planned=len(lock["rows"]))
        with claim.open("x", encoding="utf-8") as handle:
            json.dump({"prepared_run": prepared_run, "run_id": run.identifier,
                       "claimed_utc": datetime.now(timezone.utc).isoformat()}, handle)
        set_random_seed(42)
        destination = campaign / run.identifier
        destination.mkdir(mode=0o700)
        write_json(run.report / "lab_checks.json", lab)
        statuses, rows, timings, memory = Counter(), 0, [], []
        try:
            for index, row in enumerate(lock["rows"]):
                result = extract_pdf(root / row["pdf_relative_path"], boundary=root / "data/raw/cic_pdf",
                    expected_sha256=row["pdf_sha256"], limits=limits, profile=lock["configuration"]["profile"],
                    **({'arlington_lock':lock['configuration']['arlington_lock'],'repository_root':root}
                       if 'arlington_lock' in lock['configuration'] else {}),
                    raw_artifact_dir=(destination / f"sample_{index:04d}_streams") if lock["configuration"]["profile"] == "deep-static" else None)
                record = {"sample_id": row["sample_id"], "split": row["split"], "Label": int(row["Label"]), "bundle": result}
                write_json(destination / f"sample_{index:04d}.json", record)
                statuses[result["status"]] += 1
                worker = result.get("coverage_report", {}).get("worker", {})
                if type(worker.get("worker_seconds")) in (int, float):
                    timings.append(worker["worker_seconds"])
                if type(worker.get("peak_rss_bytes")) is int:
                    memory.append(worker["peak_rss_bytes"])
                rows += 1
                run.progress("sample_finished", completed=rows, planned=len(lock["rows"]), status=result["status"])
        finally:
            import numpy as np
            write_json(run.report / "coverage_summary.json", {"completed": rows, "planned": len(lock["rows"]),
                "not_completed": len(lock["rows"]) - rows, "statuses": dict(statuses),
                "worker_seconds_median": float(np.median(timings)) if timings else None,
                "worker_seconds_p99": float(np.percentile(timings, 99, method="linear")) if timings else None,
                "timed_rows": len(timings), "peak_worker_rss_bytes": max(memory) if memory else None,
                "pdf_evidence_directory": str(destination.relative_to(root)),
                "test_access": False, "model_evaluation": False,
                "interpretation": "status counts describe requested module scopes; comprehensive extraction coverage unverified"})
            run.state.update(rows=rows, planned=len(lock["rows"]), output_path=str(destination.relative_to(root)),
                notes="Static-only extraction; every planned row remains in coverage denominator. No classifier or Test evaluation; metrics N/A.")
    return run.state

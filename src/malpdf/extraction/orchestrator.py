"""One sample, disposable v9 worker, immutable three-store output."""

from datetime import datetime, timezone
from dataclasses import asdict
from copy import deepcopy
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import subprocess

from malpdf.extraction.normalize import normalize_profile
from malpdf.static.code_inspector import CodeInspectionLimits
from malpdf.static.profile_worker import profile_pdf
from malpdf.static.safety import read_bounded_bytes


def extract_pdf(path, *, boundary=None, profile="deep-static", limits=None, expected_sha256=None, raw_artifact_dir=None,
                arlington_lock=None, repository_root=None,plugins=None):
    """Inspect inert bytes only; admission/input failures remain explicit.

    An explicitly configured Arlington reference may be loaded locally. No
    classifier is loaded, no partition is selected, and no sample is uploaded.
    Resource limits, checkpoints, BLAS budgets and child cleanup are the existing
    v9 implementation. This is process resource isolation, not malware containment.
    """
    if profile not in {"fast-static", "deep-static"}:
        raise ValueError("Unknown extraction profile; full-hybrid requires a separate approved environment")
    limits = limits or CodeInspectionLimits(wall_seconds=20, cpu_seconds=12)
    from malpdf.extraction.plugins import registry
    plugins=registry(plugins)
    if plugins is not None and profile!='deep-static':raise ValueError('Plugins require deep-static')
    catalog=None
    arlington=None
    if arlington_lock is not None:
        from malpdf.extraction.arlington_model import load_model,ModelUnavailable
        if repository_root is None or profile!='deep-static':
            raise ValueError('Arlington requires an explicit repository root and deep-static profile')
        try:
            catalog=load_model(repository_root,arlington_lock)
            arlington={'status':'not_run','complete':False,'reason_codes':['arlington_worker_pass_not_reached'],
                'model':{key:value for key,value in catalog.provenance.items() if key!='files'}}
        except ModelUnavailable as error:
            arlington={'status':'not_run','complete':False,'reason_codes':['arlington_model_unavailable',str(error)],
                       'model':{'status':'unavailable'}}
    path = Path(path).absolute()
    boundary = path.parent if boundary is None else Path(boundary).absolute()
    digest = None
    try:
        data = read_bounded_bytes(path, boundary=boundary, max_bytes=limits.max_file_bytes)
        digest = hashlib.sha256(data).hexdigest()
        del data
        if expected_sha256 is not None and digest != expected_sha256:
            raise ValueError("input_checksum_mismatch")
    except (OSError, ValueError) as error:
        code = "input_checksum_mismatch" if str(error) == "input_checksum_mismatch" else "input_read_failed"
        result = {"status": "input_error", "errors": [code]}
    else:
        try:
            result = profile_pdf(path, boundary=boundary, digest=digest, limits=limits,
                analysis_version="v9", extraction_profile=profile, raw_artifact_dir=raw_artifact_dir,
                **({'plugins':plugins} if plugins is not None else {}),
                **({'arlington_catalog':catalog} if catalog is not None else {}))
        except (OSError, ValueError) as error:
            # Admission errors contain available/required counts, not sample data.
            result = {"status": "worker_error", "errors": ["worker_admission_failed"],
                      "worker_cleanup_complete": True}
    if arlington is not None:
        result.setdefault('arlington_analysis',{**arlington,'document_sha256':digest})
    if plugins is not None:result.setdefault('plugin_registry',plugins.describe())
    provenance = {"python": platform.python_version(),
                  "packages": {name: importlib.metadata.version(name) for name in ("pypdf", "PyMuPDF", "pikepdf", "esprima")},
                  "seed": 42, "requested_limits": asdict(limits),
                  "raw_artifact_directory":str(Path(raw_artifact_dir).absolute()) if raw_artifact_dir is not None else None,
                  "fitting_performed": False, "test_evaluation_performed": False}
    if plugins is not None:
        provenance.update(seed=plugins.seed,plugins=plugins.describe())
    bundle = normalize_profile(result, digest, profile, provenance=provenance)
    from malpdf.extraction.triggers import plan_triggers
    bundle["trigger_plan"] = plan_triggers(bundle)
    return bundle


def private_artifact_directory(repository_root,path):
    """CLI admission for fresh private binary output, before any PDF access."""
    root=Path(repository_root).absolute();target=Path(path).absolute()
    if ('..' in target.parts or not any(target.is_relative_to(root/name) for name in ('data/processed','artifacts'))
            or any(part.is_symlink() for part in (target,*target.parents)) or target.exists()):
        raise ValueError('Raw artifacts require a fresh private data/processed or artifacts directory')
    if subprocess.run(['git','-C',str(root),'check-ignore','-q','--',str(target/'guard.bin')]).returncode:
        raise ValueError('Raw artifacts must be gitignored')
    return target


def processed_output_root(repository_root,output_root):
    """Validate a private processed-data output root without creating files."""
    repository_root = Path(repository_root).absolute()
    output_root = Path(output_root).absolute()
    if ".." in output_root.parts or not output_root.is_relative_to(repository_root / "data/processed"):
        raise ValueError("Extraction output must be under data/processed")
    if any(part.is_symlink() for part in (output_root, *output_root.parents)):
        raise ValueError("Extraction output must not use symbolic links")
    guard = subprocess.run(["git", "-C", str(repository_root), "check-ignore", "-q", "--", str(output_root / "guard.json")])
    if guard.returncode:
        raise ValueError("Extraction output must be gitignored")
    return output_root


def write_bundle(bundle, output_root, *, repository_root):
    """Write only to fresh ignored processed-data storage; refuse collisions."""
    from malpdf.extraction.contracts import validate_bundle
    from malpdf.extraction.schemas import schemas

    validate_bundle(bundle)
    repository_root=Path(repository_root).absolute()
    output_root=processed_output_root(repository_root,output_root)
    commit = subprocess.check_output(["git", "-C", str(repository_root), "rev-parse", "HEAD"], text=True).strip()
    from malpdf.experiments.protocol_p import repository_git_state
    bundle = deepcopy(bundle)
    bundle["coverage_report"]["provenance"].update(generating_commit=commit,
        worktree=repository_git_state(repository_root))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ_")
    directory = output_root / ("run_" + stamp + commit[:12])
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    documents = {name + ".json": bundle[name] for name in ("evidence_store", "feature_store", "coverage_report")}
    documents.update(schemas())
    documents["bundle.json"] = bundle
    if "trigger_plan" in bundle:
        documents["trigger_plan.json"] = bundle["trigger_plan"]
    for name, content in documents.items():
        with (directory / name).open("x", encoding="utf-8") as output:
            json.dump(content, output, indent=2, allow_nan=False)
            output.write("\n")
    return directory

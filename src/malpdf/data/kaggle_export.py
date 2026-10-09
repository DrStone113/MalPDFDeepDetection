"""Prepare a local numeric-only handoff; no network or Kaggle upload calls."""

import hashlib
import io
import json
from pathlib import Path
import time
import zipfile

import pandas as pd

from malpdf.data.kaggle_notebook import render_kaggle_notebook
from malpdf.experiments.raw_tri_modal_v3 import load_locked_cohort, validate_configuration
from malpdf.provenance.research_runs import ResearchRun, write_json
from malpdf.static.cache_manager import load_cached_markov_pdf
from malpdf.static.safety import read_bounded_bytes

CODE_FILES = (
    "__init__.py", "reproducibility.py", "models/__init__.py", "models/vision_resnet.py",
    "data/__init__.py", "data/markov_arrays.py", "deep_learning/__init__.py", "deep_learning/models.py",
    "deep_learning/training.py", "evaluation/__init__.py", "evaluation/binary.py",
    "experiments/__init__.py", "experiments/kaggle_vision_runner.py",
)


def export_performance_notebook(root, code_root, prior_export_run, *, run_id=None):
    """Reuse an existing numeric ZIP and pin two optimized code updates."""
    if not prior_export_run.startswith('run_') or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in prior_export_run):
        raise ValueError('Invalid prior export run identifier')
    prior_report = root / 'reports/experiments/kaggle_handoff' / prior_export_run
    inventory = json.loads(read_bounded_bytes(prior_report / 'bundle_inventory.json', boundary=prior_report, max_bytes=1024 * 1024))
    prior = json.loads(read_bounded_bytes(prior_report / 'run_summary.json', boundary=prior_report, max_bytes=1024 * 1024))
    if prior['status'] != 'completed' or prior['archive_sha256'] != inventory['archive_sha256']:
        raise ValueError('A completed, checksum-locked numeric export is required')
    with ResearchRun(root, 'kaggle_performance', {'seed': 42, 'prior_export_run': prior_export_run,
            'input_archive_sha256': inventory['archive_sha256'], 'metadata_sha256': inventory['metadata_sha256'],
            'policy': 'Notebook-only performance handoff; preserve ZIP, PDFs, split, raw features and historical reports; no upload or training'},
            code_root=code_root, run_id=run_id) as run:
        if run.state['code_worktree']['status'] != 'clean':
            raise ValueError('GPU code must be generated from a clean committed checkout')
        archive = root / prior['archive']
        boundary = root / 'artifacts/kaggle_handoff'
        if archive.is_symlink() or not archive.resolve().is_relative_to(boundary.resolve()) or archive.stat().st_size != inventory['archive_bytes']:
            raise ValueError('Existing archive path or byte count changed')
        digest = hashlib.sha256()
        with archive.open('rb') as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b''): digest.update(block)
        if digest.hexdigest() != inventory['archive_sha256']:
            raise ValueError('Existing numeric ZIP changed')
        with zipfile.ZipFile(archive) as source:
            info = source.getinfo('bundle_metadata.json')
            if info.file_size > 1024 * 1024:
                raise ValueError('Metadata exceeds its resource cap')
            content = source.read(info)
        if hashlib.sha256(content).hexdigest() != inventory['metadata_sha256']:
            raise ValueError('Existing bundle metadata changed')
        overrides = {}
        for relative in ('experiments/kaggle_vision_runner.py', 'deep_learning/training.py'):
            content = (code_root / 'src/malpdf' / relative).read_bytes()
            overrides['code/src/malpdf/' + relative] = {'source': content.decode('utf-8'), 'sha256': hashlib.sha256(content).hexdigest()}
        provenance = {'generating_commit': run.commit, 'worktree': 'clean', 'base_bundle_code_commit': inventory['code_commit'],
                      'file_sha256': {name: item['sha256'] for name, item in overrides.items()}}
        template = code_root / 'notebooks/kaggle_vision_resnet18.ipynb'
        notebook = render_kaggle_notebook(template, inventory['metadata_sha256'], overrides=overrides, code_provenance=provenance)
        output = run.artifacts / 'kaggle_vision_resnet18_performance.ipynb'
        write_json(output, notebook)
        write_json(run.report / 'optimized_code_provenance.json', provenance)
        run.state.update(notebook=str(output.relative_to(root)), notebook_sha256=hashlib.sha256(output.read_bytes()).hexdigest(),
            template_sha256=hashlib.sha256(template.read_bytes()).hexdigest(), prior_export_run=prior_export_run,
            input_archive_sha256=digest.hexdigest(), metadata_sha256=inventory['metadata_sha256'], samples=prior['samples'],
            code_provenance=provenance, dataset_upload_performed=False, pdf_reads=0, training_performed=False,
            test_evaluation_performed=False,
            notes='Performance notebook prepared from clean committed code for the existing numeric ZIP. RAM preload, persistent fork workers, pinned batches and CUDA AMP; no matrix renormalization or quantization. GPU speed/AMP and final Test stacking metrics await external execution.')
    return run.state


def anonymize_rows(labeled, manifest, sources, unknown, roles):
    """Replace local PDF identities/groups without altering saved membership."""
    full = pd.concat((labeled, unknown), ignore_index=True).sort_values("sample_id", kind="stable")
    identity = {sid: f"sample_{position:06}" for position, sid in enumerate(full.sample_id, 1)}
    group_map = {group: f"group_{position:06}" for position, group in enumerate(sorted(manifest.duplicate_group_id.unique()), 1)}
    locked = manifest.set_index("sample_id")
    rows, private = [], []
    unknown_groups = {}
    for item in full.itertuples():
        identifier = identity[item.sample_id]
        source = sources.loc[item.sample_id]
        if pd.notna(item.Label):
            saved = locked.loc[item.sample_id]
            label, split, group = int(item.Label), saved.split, group_map[saved.duplicate_group_id]
        else:
            token = source.related_group_id
            unknown_groups.setdefault(token, f"unknown_group_{len(unknown_groups) + 1:06}")
            label, split, group = None, "unlabeled", unknown_groups[token]
        rows.append({"sample_id": identifier, "Label": label, "split": split, "group_id": group,
                     "cache_relative_path": "markov_cache/" + identifier + ".npy", "parser_failed": bool(item.parser_failed)})
        private.append({"export_sample_id": identifier, "sample_id": item.sample_id, "pdf_sha256": source.pdf_sha256})
    exported_roles = roles.loc[:, ["sample_id", "role"]].copy()
    exported_roles["sample_id"] = exported_roles.sample_id.map(identity)
    if exported_roles.sample_id.isna().any():
        raise ValueError("Saved validation role IDs do not belong to the cohort")
    return pd.DataFrame(rows), pd.DataFrame(private), exported_roles


def export_kaggle_bundle(root, code_root, config, vision_config, tabular_run, *, run_id=None):
    with ResearchRun(root, "kaggle_handoff", {"configuration": vision_config, "input_locks": config["inputs"],
            "seed": 42, "policy": "Local numeric-only ZIP; no raw PDFs, raw PDF hashes/paths, credentials or upload calls",
            "split_policy": "Copy established split and four validation roles with reversible opaque IDs"}, code_root=code_root, run_id=run_id) as run:
        validate_configuration(config)
        if run.state["code_worktree"]["status"] != "clean":
            raise ValueError("A sealed GPU handoff requires clean committed generating code")
        if not tabular_run.startswith("run_") or "/" in tabular_run or "\\" in tabular_run:
            raise ValueError("Invalid tabular run identifier")
        prior_report = root / "reports/experiments/raw_tri_modal_v3" / tabular_run
        prior = json.loads(read_bounded_bytes(prior_report / "run_summary.json", boundary=root / "reports/experiments/raw_tri_modal_v3", max_bytes=512 * 1024))
        if prior["inputs"] != config["inputs"] or (prior_report / "test_evaluation_started.json").exists():
            raise ValueError("Handoff must reuse the same untouched-Test tabular cohort")
        prior_artifacts = root / "artifacts/raw_tri_modal_v3" / tabular_run
        fits = list((prior_artifacts / "tabular").glob("*/*/fit_metadata.json"))
        if len(fits) != 25:
            raise ValueError("Exactly 25 completed tabular folds are required for reuse")
        checkpoints = []
        for path in fits:
            info = json.loads(read_bounded_bytes(path, boundary=prior_artifacts, max_bytes=128 * 1024))
            checkpoint = Path(info["checkpoint"])
            content = read_bounded_bytes(checkpoint, boundary=prior_artifacts, max_bytes=128 * 1024**2)
            if hashlib.sha256(content).hexdigest() != info["checkpoint_sha256"]:
                raise ValueError("Completed tabular checkpoint changed")
            checkpoints.append({"model": info["model"], "path": str(checkpoint.relative_to(root)), "sha256": info["checkpoint_sha256"]})
        labeled, manifest, sources, unknown = load_locked_cohort(root, config)
        role_bytes = read_bounded_bytes(prior_artifacts / "validation_roles.csv", boundary=prior_artifacts, max_bytes=16 * 1024**2)
        roles = pd.read_csv(io.BytesIO(role_bytes))
        val = manifest.loc[manifest.split.eq("validation")].set_index("sample_id")
        if not roles.sample_id.is_unique or set(roles.sample_id) != set(val.index) or not roles.set_index("sample_id").loc[val.index, ["Label", "duplicate_group_id"]].equals(val.loc[:, ["Label", "duplicate_group_id"]]):
            raise ValueError("Saved validation roles contradict the established split")
        portable, mapping, exported_roles = anonymize_rows(labeled, manifest, sources, unknown, roles)
        private_hashes = mapping.set_index("export_sample_id").pdf_sha256.to_dict()
        portable["Label"] = portable.Label.astype("Int64")
        mapping.to_csv(run.artifacts / "private_id_map.csv", index=False)
        write_json(run.artifacts / "local_tabular_reuse_plan.json", {"prior_run": tabular_run, "code_commit": prior["code_commit"],
            "input_locks": config["inputs"], "validation_roles_sha256": hashlib.sha256(role_bytes).hexdigest(), "checkpoints": checkpoints})
        archive = run.artifacts / "malpdf-markov-cache.zip"
        code_hashes = {}
        with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as output:
            started, last = time.monotonic(), time.monotonic()
            for position, row in enumerate(portable.itertuples(), 1):
                digest = private_hashes[row.sample_id]
                _, cache_metadata = load_cached_markov_pdf(digest, cache_directory=root / "data/processed/markov_cache")
                content = read_bounded_bytes(root / "data/processed/markov_cache" / (digest + ".npy"), boundary=root / "data/processed/markov_cache", max_bytes=1024 * 1024)
                if hashlib.sha256(content).hexdigest() != cache_metadata["npy_sha256"]:
                    raise ValueError("Markov cache changed during handoff export")
                portable.loc[position - 1, "npy_sha256"] = cache_metadata["npy_sha256"]
                output.writestr(row.cache_relative_path, content)
                if time.monotonic() - last >= 10:
                    run.progress("numeric_zip_progress", matrices=position, total=len(portable))
                    last = time.monotonic()
            if portable.loc[portable.split.ne("unlabeled")].groupby("npy_sha256").split.nunique().max() != 1:
                raise ValueError("Identical Vision matrices cross the established partitions")
            manifests = {"manifest.csv": portable.to_csv(index=False).encode(), "validation_roles.csv": exported_roles.to_csv(index=False).encode(),
                         "vision_configuration.json": json.dumps(vision_config, indent=2, allow_nan=False).encode()}
            for name, content in manifests.items():
                output.writestr(name, content)
                code_hashes[name] = hashlib.sha256(content).hexdigest()
            for name in CODE_FILES:
                relative = "code/src/malpdf/" + name
                content = (code_root / "src/malpdf" / name).read_bytes()
                output.writestr(relative, content)
                code_hashes[relative] = hashlib.sha256(content).hexdigest()
            metadata = {"seed": 42, "shape": [1, 256, 256], "dtype": "float32", "code_commit": run.commit,
                "raw_pdfs_included": False, "raw_pdf_hashes_included": False, "original_split_regenerated": False,
                "partition_rows": portable.split.value_counts().to_dict(), "validation_roles": exported_roles.role.value_counts().to_dict(),
                "file_sha256": code_hashes, "dataset_identity": "opaque IDs; private lookup retained in Codespace"}
            metadata_bytes = json.dumps(metadata, indent=2, allow_nan=False).encode()
            output.writestr("bundle_metadata.json", metadata_bytes)
        with zipfile.ZipFile(archive) as check:
            members = check.infolist()
            if len(members) != len(portable) + len(code_hashes) + 1 or any(item.filename.endswith(".pdf") for item in members):
                raise ValueError("Unexpected raw data or member count in the numeric archive")
            uncompressed = sum(item.file_size for item in members)
        digest = hashlib.sha256()
        with archive.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""): digest.update(block)
        expected_metadata = hashlib.sha256(metadata_bytes).hexdigest()
        notebook = render_kaggle_notebook(code_root / "notebooks/kaggle_vision_resnet18.ipynb", expected_metadata)
        write_json(run.artifacts / "kaggle_vision_resnet18.ipynb", notebook)
        run.state.update(archive=str(archive.relative_to(root)), archive_bytes=archive.stat().st_size,
            archive_sha256=digest.hexdigest(), uncompressed_bytes=uncompressed, samples=len(portable),
            metadata_sha256=expected_metadata, notebook=str((run.artifacts / "kaggle_vision_resnet18.ipynb").relative_to(root)),
            private_mapping=str((run.artifacts / "private_id_map.csv").relative_to(root)), prior_tabular_run=tabular_run,
            tabular_checkpoints_verified=len(checkpoints), upload_performed=False,
            notes="Local Kaggle handoff prepared; no PDF/raw hash upload. All split membership and disjoint validation roles retained. Vision GPU training and final Test stacking metrics pending external results.")
        write_json(run.report / "bundle_inventory.json", {**metadata, "archive_bytes": run.state["archive_bytes"], "archive_sha256": run.state["archive_sha256"],
            "uncompressed_bytes": uncompressed, "metadata_sha256": expected_metadata})
        run.progress("numeric_bundle_completed", samples=len(portable), zip_bytes=run.state["archive_bytes"], elapsed_seconds=time.monotonic() - started)
    return run.state

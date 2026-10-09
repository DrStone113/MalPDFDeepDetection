"""Private Kaggle launch and checksum-verified aggregate result import."""
from datetime import datetime, timezone
import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import zlib

import pandas as pd
import yaml

from malpdf.experiments.protocol_p import repository_git_state
from malpdf.provenance.research_runs import ResearchRun, write_json


def sealed_training_script(code_root, configuration, commit):
    """Seal committed source, not local data, tokens, sample identities or hashes."""
    sources = {}
    for path in sorted((code_root / "src/malpdf").rglob("*.py")):
        if path.is_symlink():
            raise ValueError("Source symlinks are not permitted in cloud handoffs")
        content = path.read_text(encoding="utf-8")
        if len(content.encode()) > 1024**2:
            raise ValueError("Source file exceeds its cap")
        sources[str(path.relative_to(code_root / "src"))] = {
            "source": content, "sha256": hashlib.sha256(content.encode()).hexdigest()}
    prefix = """import os
os.environ['OMP_NUM_THREADS'] = '2'
os.environ['OPENBLAS_NUM_THREADS'] = '2'
os.environ['MKL_NUM_THREADS'] = '2'
from pathlib import Path, PurePosixPath
import base64, hashlib, json, sys, tempfile, zlib
"""
    compressed = zlib.compress(json.dumps(sources).encode(), level=9)
    payload = ("COMPRESSED_SOURCE = " + repr(base64.b64encode(compressed).decode())
               + "\nCOMPRESSED_SHA256 = " + repr(hashlib.sha256(compressed).hexdigest())
               + "\nCONFIGURATION = " + repr(configuration)
               + "\nCODE_COMMIT = " + repr(commit) + "\n")
    suffix = """compressed = base64.b64decode(COMPRESSED_SOURCE, validate=True)
if hashlib.sha256(compressed).hexdigest() != COMPRESSED_SHA256:
    raise ValueError('Compressed trusted source checksum differs')
decoder = zlib.decompressobj()
source_bytes = decoder.decompress(compressed, 4 * 1024**2 + 1)
if len(source_bytes) > 4 * 1024**2 or decoder.unconsumed_tail or decoder.unused_data or not decoder.eof:
    raise ValueError('Source expansion exceeds its cap or has trailing data')
SOURCE_PAYLOAD = json.loads(source_bytes)
code_root = Path(tempfile.mkdtemp(prefix='malpdf_development_code_'))
for name, item in SOURCE_PAYLOAD.items():
    relative = PurePosixPath(name)
    content = item['source'].encode('utf-8')
    if (relative.is_absolute() or '..' in relative.parts or relative.parts[0] != 'malpdf'
            or relative.suffix != '.py' or '\\\\' in name or len(content) > 1024**2
            or hashlib.sha256(content).hexdigest() != item['sha256']):
        raise ValueError('Invalid sealed source')
    target = code_root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open('xb') as handle: handle.write(content)
sys.path.insert(0, str(code_root))
output_root = Path('/kaggle/working/static_development')
output_root.mkdir(exist_ok=False)
with (output_root / 'code_provenance.json').open('x') as handle:
    json.dump({'code_commit': CODE_COMMIT, 'source_sha256': {k: v['sha256'] for k, v in SOURCE_PAYLOAD.items()}}, handle, indent=2)
try:
    from malpdf.experiments.static_development import numeric_input, train_static_development
    bundle = numeric_input(Path('/kaggle/input'), CONFIGURATION['bundle_metadata_sha256'],
        Path(tempfile.mkdtemp(prefix='malpdf_numeric_')) / 'bundle')
    result = train_static_development(bundle, output_root, CONFIGURATION, CODE_COMMIT, input_root=Path('/kaggle/input'))
    print(json.dumps({'status': 'completed', 'output_directory': str(result)}), flush=True)
except BaseException as error:
    with (output_root / 'launch_error.json').open('x') as handle:
        json.dump({'type': type(error).__name__, 'message': str(error), 'code_commit': CODE_COMMIT}, handle)
    with (output_root / 'locked_methodology.json').open('x') as handle:
        json.dump({'configuration': CONFIGURATION, 'code_commit': CODE_COMMIT, 'status': 'failed_startup_or_training'}, handle)
    with (output_root / 'model_comparison.csv').open('x') as handle:
        handle.write('model,partition,accuracy,f1_malicious,mcc,brier,ece,status\\nN/A,N/A,N/A,N/A,N/A,N/A,N/A,failed\\n')
    with (output_root / 'research_log.md').open('x') as handle:
        handle.write('Failed cloud invocation; metrics N/A. See launch_error.json; generating commit: ' + CODE_COMMIT + '\\n')
    raise
"""
    return prefix + payload + suffix


def launch(root, code_root, configuration_path):
    if repository_git_state(code_root)["status"] != "clean":
        raise ValueError("Official cloud training starts from a clean committed code worktree")
    configuration = yaml.safe_load(configuration_path.read_text())
    with ResearchRun(root, "static_development_gpu_launch", {
        "protocol": "retrospective saved multi-cohort Protocol G development",
        "configuration": configuration, "test_policy": "no Test inference or metrics",
        "authorized_input": "existing private opaque numeric Kaggle dataset only; no new dataset upload",
    }, code_root=code_root) as run:
        slug = "malpdf-static-development-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        kernel = "nguyenkhang294/" + slug
        upload = run.artifacts / "kernel_upload"
        upload.mkdir(exist_ok=False)
        script = sealed_training_script(code_root, configuration, run.commit)
        (upload / "train.py").write_text(script)
        metadata = {"id": kernel, "title": slug.replace("-", " "),
            "code_file": "train.py", "language": "python", "kernel_type": "script", "is_private": True,
            "enable_gpu": True, "enable_internet": False, "machine_shape": "NvidiaTeslaT4",
            "dataset_sources": [configuration["kaggle_dataset"], *configuration.get("additional_existing_datasets", [])], "competition_sources": [],
            "kernel_sources": [], "model_sources": []}
        write_json(upload / "kernel-metadata.json", metadata)
        if shutil.disk_usage(root).free < 1024**3:
            raise ValueError("Reserve at least 1 GiB Codespace space for checks and small output import")
        result = subprocess.run(["kaggle", "kernels", "push", "-p", str(upload), "-t", str(configuration["max_run_seconds"])],
                                text=True, capture_output=True, timeout=120)
        (run.artifacts / "submission_stdout.txt").write_text(result.stdout)
        (run.artifacts / "submission_stderr.txt").write_text(result.stderr)
        if result.returncode or "error" in (result.stdout + result.stderr).lower():
            raise RuntimeError("Kaggle rejected submission; preserved CLI response in ignored artifacts")
        receipt = {"kernel": kernel, "url": "https://www.kaggle.com/code/" + kernel,
            "code_commit": run.commit, "dataset": configuration["kaggle_dataset"],
            "training_script_sha256": hashlib.sha256(script.encode()).hexdigest(),
            "configuration": configuration, "test_evaluations": 0,
            "existing_datasets": metadata["dataset_sources"]}
        write_json(run.report / "submission_receipt.json", receipt)
        run.state.update(kernel=kernel, url=receipt["url"], notes="Private GPU submission accepted; training results pending; no datasets uploaded")
    return run.state


def collect(root, code_root, launch_run):
    launch_report = root / "reports/experiments/static_development_gpu_launch" / launch_run
    receipt = json.loads((launch_report / "submission_receipt.json").read_text())
    status = subprocess.run(["kaggle", "kernels", "status", receipt["kernel"]], text=True, capture_output=True, timeout=60)
    if status.returncode or '"KernelWorkerStatus.COMPLETE"' not in status.stdout:
        raise ValueError("Kaggle training is not COMPLETE: " + status.stdout.strip())
    with ResearchRun(root, "static_development_validation", {"protocol": "retrospective saved multi-cohort Protocol G development",
        "kernel": receipt["kernel"], "training_commit": receipt["code_commit"],
        "test_policy": "no Test inference or metrics", "ECE": "10 equal-width bins; p=1 last bin",
        "interpretation": "Validation diagnostics and selection; not independent Test evidence"}, code_root=code_root) as run:
        download = run.artifacts / "kaggle_output"
        download.mkdir(exist_ok=False)
        # Preserve cloud checkpoints on Kaggle; avoid hundreds of MB of RF
        # binaries on a nearly full Codespace. Read no pickle/joblib/model here.
        response = subprocess.run(["kaggle", "kernels", "output", receipt["kernel"], "-p", str(download),
            "--file-pattern", r"\.(json|csv|md|log)$", "-q"], text=True, capture_output=True, timeout=180)
        (run.artifacts / "download_stdout.txt").write_text(response.stdout)
        (run.artifacts / "download_stderr.txt").write_text(response.stderr)
        if response.returncode:
            raise RuntimeError("Kaggle output download failed; partial output preserved")
        summaries = list(download.rglob("run_summary.json"))
        if len(summaries) != 1:
            raise ValueError("Expected one unique cloud training run")
        directory = summaries[0].parent
        provenance_paths = list(download.rglob("code_provenance.json"))
        if len(provenance_paths) != 1:
            raise ValueError("Expected one sealed generating-code provenance record")
        provenance = json.loads(provenance_paths[0].read_text())
        if provenance["code_commit"] != receipt["code_commit"]:
            raise ValueError("Cloud generating revision differs from its submission")
        committed_files = subprocess.check_output(["git", "-C", str(code_root), "ls-tree", "-r", "--name-only",
            receipt["code_commit"], "src/malpdf"], text=True).splitlines()
        expected_files = {name.removeprefix("src/") for name in committed_files if name.endswith(".py")}
        if set(provenance["source_sha256"]) != expected_files:
            raise ValueError("Cloud source inventory differs from the committed package")
        for name, digest in provenance["source_sha256"].items():
            content = subprocess.check_output(["git", "-C", str(code_root), "show", receipt["code_commit"] + ":src/" + name])
            if hashlib.sha256(content).hexdigest() != digest:
                raise ValueError("Cloud source checksum differs from its generating Git revision")
        checksums = json.loads((directory / "output_checksums.json").read_text())
        verified, remote_models = [], []
        for name, digest in checksums.items():
            relative = Path(name)
            if relative.is_absolute() or ".." in relative.parts or "\\" in name:
                raise ValueError("Unsafe cloud output checksum path")
            path = directory / name
            if relative.suffix not in (".json", ".csv", ".md", ".log"):
                remote_models.append(name)
                continue
            if (path.is_symlink() or not path.is_file() or path.stat().st_size > 16 * 1024**2
                    or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
                raise ValueError("Cloud numeric evidence checksum differs")
            verified.append(name)
        state = json.loads(summaries[0].read_text())
        if (state["status"] != "completed" or state["code_commit"] != receipt["code_commit"]
                or state["test_evaluations"] != 0 or state["test_inference"] != 0
                or len(state["completed_fits"]) != 50):
            raise ValueError("Cloud study failed or violated the locked 50-fit/Test-exclusion contract")
        models = pd.read_csv(directory / "model_comparison.csv", float_precision="round_trip")
        if (len(models) != 96 or models.duplicated(["scheme", "model", "partition"]).any()
                or not models.partition.str.startswith("validation_").all()):
            raise ValueError("Expected the complete Validation-only model comparison")
        for name in ("selection_lock.json", "routing_analysis.json", "environment_metadata.json", "locked_methodology.json"):
            write_json(run.report / ("cloud_" + name), json.loads((directory / name).read_text()))
        models.to_csv(run.report / "validation_comparison.csv", index=False)
        for row in models.to_dict("records"):
            key = row["scheme"] + ":" + row["model"] + "/" + row["partition"]
            run.state["metrics"][key] = {k: row[k] for k in ("accuracy", "f1_malicious", "mcc", "brier", "log_loss", "ece")}
        write_json(run.report / "output_verification.json", {"verified_numeric_files": len(verified),
            "verified_committed_source_files": len(expected_files),
            "cloud_checkpoints_preserved": len(remote_models), "kernel": receipt["kernel"],
            "model_downloaded_or_deserialized": False, "cloud_run": directory.name})
        run.state.update(training_commit=receipt["code_commit"], selected=state["selected"], elapsed_seconds=state["elapsed_seconds"],
            notes="Validation-only static ablation; Test untouched. Existing Vision unchanged. Checkpoints retained in private Kaggle Output. See cloud_input_provenance for cohort/role group counts.")
        write_json(run.report / "cloud_input_provenance.json", json.loads((directory / "input_provenance.json").read_text()))
    return run.state

"""Manifest-only jobs and fail-closed execution, with synthetic cohorts."""

import csv
import hashlib
import json
from pathlib import Path
import subprocess

import pytest
import yaml

from malpdf.extraction import jobs


@pytest.fixture
def root(tmp_path):
    (tmp_path / "configs").mkdir()
    (tmp_path / "reports").mkdir()
    (tmp_path / "reports/research_log.md").write_text("# Synthetic run register\n")
    (tmp_path / "pyproject.toml").write_text("# synthetic provenance\n")
    (tmp_path / ".gitignore").write_text("artifacts/**\ndata/processed/**\n")
    sources, splits, normalized = [], [], []
    for split in ("train", "validation", "test"):
        for label in ("0", "1"):
            for index in range(16 if split != "test" else 2):
                identity = f"{split}_{label}_{index}"
                digest = hashlib.sha256(identity.encode()).hexdigest()
                path = f"data/raw/cic_pdf/{identity}.pdf"
                sources.append({"sample_id": identity, "Label": label, "pdf_relative_path": path,
                                "pdf_sha256": digest, "related_group_id": identity})
                splits.append({"sample_id": identity, "duplicate_group_id": identity, "split": split,
                               "Label": label, "cohort": "cic"})
                normalized.append({"pdf_sha256": digest, "pdf_relative_path": path, "Label": label,
                                   "target_pdf_byte_verified": "True", "target_label_source": "synthetic label"})
    cohort = {"seed": 42, "samples_per_partition": 32, "prepared_cohort": "synthetic"}
    for key, rows in (("split_manifest", splits), ("source_manifest", sources), ("normalization_manifest", normalized)):
        relative = Path("data/processed/synthetic") / (key + ".csv")
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        cohort[key] = {"path": str(relative), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    (tmp_path / "configs/cic_synthetic.yaml").write_text(yaml.safe_dump(cohort))
    config = {"cohort_config": "configs/cic_synthetic.yaml", "profile": "deep-static", "seed": 42,
              "workers": 1, "samples_per_partition": 32, "limits": {"wall_seconds": 20, "cpu_seconds": 12}}
    (tmp_path / "configs/extraction.yaml").write_text(yaml.safe_dump(config))
    for args in (["init", "-q"], ["add", "."],
                 ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "Synthetic fixture"]):
        subprocess.run(["git", "-C", str(tmp_path), *args], check=True, capture_output=True)
    return tmp_path


def prepare(root):
    return jobs.prepare_job(root, root / "configs/extraction.yaml")


def test_prepare_and_check_never_touch_pdfs_or_select_test(root, monkeypatch):
    monkeypatch.setattr(jobs, "extract_pdf", lambda *a, **k: pytest.fail("Preparation must not access PDFs"))
    state = prepare(root)
    lock, _ = jobs.load_job(root, state["run_id"])
    assert len(lock["rows"]) == 64
    assert {row["split"] for row in lock["rows"]} == {"train", "validation"}
    assert not (root / "data/raw").exists()
    report = root / state["report_path"]
    assert (report.parent / "locked_methodology.json").is_file()
    assert (report.parent / "model_comparison.csv").is_file()
    assert "completed" in (root / "reports/research_log.md").read_text()


def test_manifest_hash_drift_fails_and_retains_failed_invocation(root):
    path = root / "data/processed/synthetic/split_manifest.csv"
    path.write_text(path.read_text() + "\n")
    with pytest.raises(ValueError, match="checksum changed"):
        prepare(root)
    reports = list((root / "reports/experiments/pdf_extraction_prepare").glob("*/run_summary.json"))
    assert len(reports) == 1 and json.loads(reports[0].read_text())["status"] == "failed"
    assert "failed" in (root / "reports/research_log.md").read_text()


def test_shell_launcher_source_is_sealed_and_refuses_drift(root):
    scripts = root / "scripts"
    scripts.mkdir()
    shell = scripts / "launcher.sh"
    shell.write_text("#!/bin/sh\nexit 0\n")
    state = prepare(root)
    lock, _ = jobs.load_job(root, state["run_id"])
    assert "scripts/launcher.sh" in lock["fingerprint"]["sources"]
    shell.write_text("#!/bin/sh\nexit 1\n")
    with pytest.raises(ValueError, match="Generating code/environment changed"):
        jobs.load_job(root, state["run_id"])


def test_conflicting_manifest_candidates_are_reported_without_selection(root):
    cfg = yaml.safe_load((root / "configs/cic_synthetic.yaml").read_text())
    cfg["split_manifest"]["sha256"] = "0" * 64
    (root / "configs/cic_conflict.yaml").write_text(yaml.safe_dump(cfg))
    with pytest.raises(ValueError, match="Conflicting CIC manifest candidates.*cic_conflict"):
        prepare(root)
    assert not (root / "data/raw").exists()
    assert "pdf_extraction_prepare_refused" in (root / "reports/research_log.md").read_text()


def test_job_fingerprint_drift_blocks_execution(root):
    state = prepare(root)
    (root / "configs/extraction.yaml").write_text("# changed\n")
    with pytest.raises(ValueError, match="code/environment changed"):
        jobs.load_job(root, state["run_id"])


def test_optional_arlington_reference_is_sealed_and_drift_refused(root,monkeypatch):
    from malpdf.extraction import arlington_model
    cfgpath=root/'configs/extraction.yaml'
    cfg=yaml.safe_load(cfgpath.read_text());cfg['arlington_lock']='configs/arlington.lock.json'
    cfgpath.write_text(yaml.safe_dump(cfg))
    metadata={'status':'available','commit':'a'*40,'files':{'synthetic.tsv':{'sha256':'b'*64}}}
    monkeypatch.setattr(arlington_model,'load_model',lambda *args:arlington_model.Catalog({},dict(metadata)))
    state=prepare(root)
    lock,_=jobs.load_job(root,state['run_id'])
    assert lock['fingerprint']['arlington_reference']==metadata
    metadata['commit']='c'*40
    with pytest.raises(ValueError,match='code/environment changed'):
        jobs.load_job(root,state['run_id'])


def test_locked_subset_cannot_be_swapped_for_test_even_with_resealed_file(root):
    state = prepare(root)
    lock_path = root / state["artifact_path"] / "job_lock.json"
    lock = json.loads(lock_path.read_text())
    lock["rows"][0]["split"] = "test"
    lock_path.write_text(json.dumps(lock))
    report = root / state["report_path"]
    state["job_lock_sha256"] = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    report.write_text(json.dumps(state))
    with pytest.raises(ValueError, match="locked Train/Validation"):
        jobs.load_job(root, state["run_id"])


def test_offline_job_refuses_before_pdf_or_claim_when_lab_not_attested(root, monkeypatch):
    monkeypatch.setattr(jobs, "extract_pdf", lambda *a, **k: pytest.fail("No PDF reads before guard"))
    with pytest.raises(ValueError, match="Offline LAB"):
        jobs.run_job(root, "run_synthetic")
    assert not (root / "data/processed/pdf_extraction").exists()


def test_offline_guard_checks_agent_credentials_and_keys_without_reading_contents(tmp_path, monkeypatch):
    monkeypatch.setattr(jobs, "lab_state", lambda: {"uid": 1000, "ssh_session": False,
        "connected_interfaces": [], "unknown_interfaces": [], "shared_mounts": []})
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(jobs.os, "environ", {})
    assert jobs.require_extraction_lab(True)["known_credentials_present"] is False
    monkeypatch.setattr(jobs.os, "environ", {"SSH_AUTH_SOCK": "private fixture socket"})
    with pytest.raises(ValueError, match="Credential presence"):
        jobs.require_extraction_lab(True)
    monkeypatch.setattr(jobs.os, "environ", {})
    (tmp_path / ".ssh").mkdir()
    (tmp_path / ".ssh/id_ed25519").write_text("synthetic sentinel; never read")
    with pytest.raises(ValueError, match="Credential presence"):
        jobs.require_extraction_lab(True)


def test_offline_partial_rows_remain_in_denominators_and_claim_is_single_use(root, monkeypatch):
    from malpdf.experiments import cic_static_benchmark

    state = prepare(root)
    monkeypatch.setattr(jobs, "require_extraction_lab", lambda attested, **kwargs: {"fixture": True})
    monkeypatch.setattr(cic_static_benchmark, "clean_code", lambda root: None)
    monkeypatch.setattr(jobs, "_worker_count", lambda *args: 1)
    calls = []
    def extract(*args, **kwargs):
        calls.append((args, kwargs))
        return {"status": "timeout" if len(calls) == 1 else "observed"}
    monkeypatch.setattr(jobs, "extract_pdf", extract)
    outcome = jobs.run_job(root, state["run_id"], lab_attested=True)
    summary = json.loads((root / outcome["report_path"]).with_name("coverage_summary.json").read_text())
    assert summary["completed"] == summary["planned"] == 64 and summary["not_completed"] == 0
    assert summary["statuses"] == {"timeout": 1, "observed": 63}
    assert all(kwargs["expected_sha256"] for _, kwargs in calls)
    with pytest.raises(FileExistsError):
        jobs.run_job(root, state["run_id"], lab_attested=True)
    assert len(calls) == 64


def test_launcher_rechecks_isolation_after_confirmation_before_real_runner_claim(root, monkeypatch):
    from types import SimpleNamespace
    from malpdf.experiments import cic_static_benchmark
    from malpdf.extraction import launcher

    prepared = prepare(root)
    state = {"uid": 1000, "ssh_session": False, "connected_interfaces": [],
             "unknown_interfaces": [], "shared_mounts": []}
    monkeypatch.setattr(jobs, "lab_state", lambda: dict(state))
    monkeypatch.setattr(Path, "home", lambda: root)
    monkeypatch.setattr(jobs.os, "environ", {})
    monkeypatch.setattr(launcher, "clean_code", lambda root: None)
    monkeypatch.setattr(cic_static_benchmark, "clean_code", lambda root: None)
    monkeypatch.setattr(jobs, "_worker_count", lambda *a: 1)
    monkeypatch.setattr(jobs, "extract_pdf", lambda *a, **k: pytest.fail("No PDF before second LAB check"))
    terminal = SimpleNamespace(isatty=lambda: True)
    monkeypatch.setattr(launcher, "sys", SimpleNamespace(version_info=(3, 11), stdin=terminal, stdout=terminal))
    def confirm(*a):
        state["connected_interfaces"] = ["synthetic_reconnected"]
        return launcher.CONFIRMATION
    monkeypatch.setattr("builtins.input", confirm)
    assert launcher.main(["--prepared-run", prepared["run_id"]], root=root) == 1
    assert not (root / "data/processed/pdf_extraction").exists()
    report = next((root / "reports/experiments/pdf_extraction_refused").glob("*/run_summary.json"))
    assert json.loads(report.read_text())["status"] == "refused"

from __future__ import annotations

import hashlib
import importlib
from pathlib import Path

import pytest

LAB_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts" / "lab"
JOB_KIND = "pdf-tlsh-holdout"


def test_holdout_fingerprint_job_is_fixed_and_console_only(monkeypatch):
    monkeypatch.syspath_prepend(str(LAB_SCRIPTS))
    jobs = importlib.import_module("lab_jobs")
    identifiers = ("a" * 40, "b" * 64, "c" * 64)

    with pytest.raises(ValueError, match="job_mismatch"):
        jobs.make_job(*identifiers, mode="host-only", kind=JOB_KIND)

    job = jobs.make_job(*identifiers, mode="offline", kind=JOB_KIND)
    assert job["limits"]["samples"] == 21559
    assert job["limits"]["workers"] == 1


def test_pooled_fingerprint_kind_remains_console_only_and_keeps_the_byte_budget(monkeypatch):
    monkeypatch.syspath_prepend(str(LAB_SCRIPTS))
    jobs = importlib.import_module("lab_jobs")
    from malpdf.extraction.pooled_fingerprint_job import SAMPLES, TOTAL_BYTES

    identifiers = ("a" * 40, "b" * 64, "c" * 64)
    with pytest.raises(ValueError, match="job_mismatch"):
        jobs.make_job(*identifiers, mode="host-only", kind=jobs.POOLED_TLSH_KIND)
    job = jobs.make_job(*identifiers, mode="offline", kind=jobs.POOLED_TLSH_KIND)
    assert job["limits"]["samples"] == SAMPLES
    assert job["limits"]["file_max_bytes"] == job["limits"]["file_memory_bytes"] // 1024 * 50
    assert TOTAL_BYTES <= 20_000_000_000


def test_holdout_worker_requires_the_live_console_claim(monkeypatch, tmp_path):
    monkeypatch.syspath_prepend(str(LAB_SCRIPTS))
    runner = importlib.import_module("lab_runner")
    jobs = runner.jobs
    job = jobs.make_job("a" * 40, "b" * 64, "c" * 64, mode="offline", kind=JOB_KIND)
    claim = {"job_id": job["job_id"], "hypervisor_controls_attested": True,
             "parent_pid": 42, "start_ticks": 1}
    monkeypatch.setattr(runner.sys, "platform", "linux")
    monkeypatch.setattr(runner.os, "getppid", lambda: 42)
    monkeypatch.setattr(jobs, "load_job", lambda _: job)
    monkeypatch.setattr(jobs, "job_directory", lambda _: tmp_path)
    monkeypatch.setattr(jobs, "preflight", lambda mode, attested: None)
    monkeypatch.setattr(jobs, "process_identity", lambda pid: 2)
    monkeypatch.setattr(runner.side, "bounded_read", lambda path, limit: jobs.encoded(claim))
    monkeypatch.setattr(runner, "worker_limits", lambda **kwargs: pytest.fail("stale claim reached the worker"))

    with pytest.raises(ValueError, match="approval_required"):
        runner._pdf_worker(job["job_id"])


def test_fingerprint_never_passes_checksum_mismatch_to_the_native_tool(tmp_path, monkeypatch):
    from malpdf.extraction import holdout_fingerprint_job as worker

    input_path = tmp_path / "reviewed.txt"
    input_path.write_bytes(b"inert test bytes")
    entry = {"path": input_path.name, "sha256": "b" * 64, "bytes": input_path.stat().st_size,
             "group": "historical_v4"}
    monkeypatch.setattr(worker, "native", lambda *args, **kwargs: pytest.fail("unverified bytes reached TLSH"))

    result = worker.fingerprint_entry(tmp_path, entry, {}, 3)

    assert result["status"] == "sha256_mismatch"
    assert result["tlsh"] is None


def test_publisher_sha1_mismatch_is_neither_a_fingerprint_nor_a_label(tmp_path, monkeypatch):
    from malpdf.extraction import holdout_fingerprint_job as worker

    data = b"inert provenance check"
    input_path = tmp_path / "reviewed.txt"
    input_path.write_bytes(data)
    sha = hashlib.sha256(data).hexdigest()
    entry = {"path": input_path.name, "sha256": sha, "bytes": len(data), "group": "govdocs1_review"}
    monkeypatch.setattr(worker, "native", lambda *args, **kwargs: pytest.fail("source-mismatched bytes reached TLSH"))

    result = worker.fingerprint_entry(tmp_path, entry, {sha: "b" * 40}, 3)

    assert result == {"sha256": sha, "status": "publisher_sha1_mismatch", "tlsh": None}


def test_optional_sha1_records_only_sha256_verified_bytes(tmp_path, monkeypatch):
    from malpdf.extraction import holdout_fingerprint_job as worker

    data = b"inert provenance check"
    path = tmp_path / "reviewed.txt"
    path.write_bytes(data)
    entry = {"path": path.name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    monkeypatch.setattr(worker, "native", lambda *args, **kwargs: None)
    result = worker.fingerprint_entry(tmp_path, entry, {}, 3, include_sha1=True)
    assert result["status"] == "tlsh_unavailable"
    assert result["sha1"] == hashlib.sha1(data, usedforsecurity=False).hexdigest()

    assert "sha1" not in worker.fingerprint_entry(tmp_path, dict(entry, sha256="0" * 64), {}, 3, include_sha1=True)

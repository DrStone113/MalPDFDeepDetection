from __future__ import annotations

import importlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from malpdf.extraction.contracts import validate_bundle
from malpdf.extraction.normalize import normalize_profile


LAB_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts" / "lab"
REAL_JOB_ID = "4cec6c2794967311bc5c55a924933a0b0cbda0529ff31fe1f19de8b4cdcd7b75"


@pytest.fixture
def jobs(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.syspath_prepend(str(LAB_SCRIPTS))
    return importlib.import_module("lab_jobs")


@pytest.fixture
def extraction_job() -> dict:
    return {
        "schema_version": 1,
        "api": 1,
        "commit": "c6b920385d966eaba9f0e1eec0ac2dcb789a4664",
        "archive_sha256": "bffb3ef0a3f5ffa12776bba3fc5594ae62a20a86541f803b120ece9015e2b253",
        "manifest_sha256": "e4a9a1ce4f34f1aabc1dced5dcd027295ee6a73469f7f10c749079c7ff8f14fb",
        "mode": "offline",
        "kind": "pdf-static-cic-full",
        "limits": {
            "wall_seconds": 7200,
            "file_wall_seconds": 35,
            "file_cpu_seconds": 30,
            "file_memory_bytes": 1073741824,
            "file_max_bytes": 10485760,
            "samples": 1452,
            "workers": 10,
            "output_bytes": 2147483648,
        },
        "attempt": "6eee14df0a8246048fefc66843e83eb1",
        "job_id": REAL_JOB_ID,
    }


def _partial_summary() -> dict:
    return {
        "planned": 1452,
        "completed": 1380,
        "observed": 284,
        "bounded_complete": 283,
        "partial": 139,
        "failed": 957,
        "primary_available": 1309,
        "timeout": 587,
        "elapsed_ms": 3980880,
        "peak_rss_bytes": 412389376,
        "status_counts": {"bounded_complete": 283, "decode_error": 48, "observed": 1, "partial": 139, "timeout": 587, "unsupported": 322},
    }


def test_partial_real_job_count_is_reported_as_incomplete(jobs, extraction_job: dict) -> None:
    banner = jobs.pdf_completion_banner(extraction_job, _partial_summary(), elapsed_seconds=3980.88, workers=10)
    assert "1380" in banner
    assert "1452" in banner
    assert "72" in banner
    assert "INCOMPLETE" in banner.upper()
    assert "COMPLETED SUCCESSFULLY" not in banner.upper()


def test_processed_count_does_not_certify_partial_extractions(jobs, extraction_job: dict) -> None:
    summary = _partial_summary()
    summary.update(completed=1452, observed=0, bounded_complete=0, partial=1452, failed=0, primary_available=1452, timeout=0, status_counts={"partial": 1452})
    banner = jobs.pdf_completion_banner(extraction_job, summary, elapsed_seconds=1.0, workers=10)
    assert "PARTIAL" in banner.upper()
    assert "COMPLETED SUCCESSFULLY" not in banner.upper()


def test_complete_validated_extraction_can_report_success(jobs, extraction_job: dict) -> None:
    summary = _partial_summary()
    summary.update(completed=1452, observed=1452, bounded_complete=1452, partial=0, failed=0, primary_available=1452, timeout=0, status_counts={"bounded_complete": 1452})
    banner = jobs.pdf_completion_banner(extraction_job, summary, elapsed_seconds=1.0, workers=10)
    assert "1452" in banner
    assert "COMPLETED SUCCESSFULLY" in banner.upper()


def test_halted_shard_prevents_success_even_when_all_counts_look_complete(jobs, extraction_job: dict) -> None:
    summary = _partial_summary()
    summary.update(completed=1452, observed=1452, bounded_complete=1452, partial=0, failed=0, primary_available=1452, timeout=0, status_counts={"bounded_complete": 1452})
    banner = jobs.pdf_completion_banner(extraction_job, summary, elapsed_seconds=1.0, workers=10, halted_shards=1)
    assert "PARTIAL" in banner.upper()
    assert "SUCCESSFULLY" not in banner.upper()


def test_persisted_job_result_respects_halt_markers(jobs, extraction_job: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(jobs, "JOBS", tmp_path / "jobs")
    directory = jobs.save_job(extraction_job)
    jobs.write_pdf_halt(extraction_job, directory, shard=4, index=724, reason="worker_cleanup_incomplete")
    summary = _partial_summary()
    summary.update(completed=1452, observed=1452, bounded_complete=1452, partial=0, failed=0, primary_available=1452, timeout=0, status_counts={"bounded_complete": 1452})
    environment = {"mode": "offline", "guest_network_checked": True, "stdlib_dependencies_checked": True, "hypervisor_controls_attested": True}
    monkeypatch.setattr(jobs, "config", lambda: {"data_root": str(tmp_path)})
    monkeypatch.setattr(jobs, "check_credentials", lambda root: None)
    monkeypatch.setattr(jobs, "preflight", lambda *args, **kwargs: environment)
    monkeypatch.setattr(jobs.side, "verify_release", lambda *args: {})
    monkeypatch.setattr(jobs, "verify_helpers", lambda metadata: None)
    monkeypatch.setattr(jobs, "pdf_task", lambda job, directory: summary)
    result = jobs.execute(extraction_job, attested=True)
    assert result["status"] == "partial"
    assert json.loads((directory / "result.json").read_bytes())["status"] == "partial"


@pytest.mark.parametrize("corruption", ["count_mismatch", "over_planned", "missing_summary"])
def test_unvalidated_summaries_cannot_reach_a_completion_banner(jobs, extraction_job: dict, corruption: str) -> None:
    summary = _partial_summary()
    if corruption == "count_mismatch":
        summary["status_counts"] = {"partial": 1}
    elif corruption == "over_planned":
        summary.update(completed=1453, observed=0, bounded_complete=0, partial=1453, failed=0, primary_available=1453, timeout=0, status_counts={"partial": 1453})
    else:
        summary = None
    with pytest.raises(ValueError):
        jobs.pdf_completion_banner(extraction_job, summary, elapsed_seconds=1.0, workers=10)


@pytest.mark.parametrize("reason", ["wall_limit", "output_limit", "bundle_size_limit", "worker_cleanup_incomplete"])
def test_worker_halt_exports_only_bounded_structured_metadata(jobs, extraction_job: dict, tmp_path: Path, reason: str) -> None:
    jobs.write_pdf_halt(extraction_job, tmp_path, shard=4, index=724, reason=reason)
    path = tmp_path / "pdf_halt.4.json"
    payload = path.read_bytes()
    record = json.loads(payload)
    assert len(payload) <= 4096
    assert record == {"schema_version": 1, "job_id": REAL_JOB_ID, "shard": 4, "index": 724, "reason": reason}


def test_worker_halt_is_immutable_but_identical_replay_is_safe(jobs, extraction_job: dict, tmp_path: Path) -> None:
    jobs.write_pdf_halt(extraction_job, tmp_path, shard=4, index=724, reason="worker_cleanup_incomplete")
    path = tmp_path / "pdf_halt.4.json"
    original_bytes = path.read_bytes()
    jobs.write_pdf_halt(extraction_job, tmp_path, shard=4, index=724, reason="worker_cleanup_incomplete")
    assert path.read_bytes() == original_bytes
    with pytest.raises(ValueError):
        jobs.write_pdf_halt(extraction_job, tmp_path, shard=4, index=734, reason="worker_cleanup_incomplete")
    assert path.read_bytes() == original_bytes


@pytest.mark.parametrize(
    "shard,index,reason",
    [
        (4, 724, "cleanup failed: /private/raw/sample.pdf"),
        (-1, 724, "worker_cleanup_incomplete"),
        (10, 724, "worker_cleanup_incomplete"),
        (4, -1, "worker_cleanup_incomplete"),
        (4, 1452, "worker_cleanup_incomplete"),
    ],
)
def test_worker_halt_rejects_unbounded_or_invalid_metadata(jobs, extraction_job: dict, tmp_path: Path, shard: int, index: int, reason: str) -> None:
    with pytest.raises(ValueError):
        jobs.write_pdf_halt(extraction_job, tmp_path, shard=shard, index=index, reason=reason)
    assert not list(tmp_path.glob("pdf_halt.*.json"))


@pytest.mark.parametrize(
    "payload,expected",
    [
        (b"not JSON", "unreadable"),
        (b"{}", "unknown"),
        (b'{"status":"complete"}', "unknown"),
        (b'{"status":[]}', "unknown"),
        (b'{"status":{}}', "unknown"),
        (b'{"status":"bounded_complete"}', "bounded_complete"),
        (b'{"status":"timeout"}', "timeout"),
    ],
)
def test_progress_does_not_turn_invalid_or_unknown_bundles_into_observed(jobs, tmp_path: Path, payload: bytes, expected: str) -> None:
    path = tmp_path / "0724.json"
    path.write_bytes(payload)
    assert jobs.pdf_bundle_progress_status(path) == expected


def test_unclean_worker_checkpoint_stops_before_next_shard_index(jobs, extraction_job: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runner = importlib.import_module("lab_runner")
    monkeypatch.setattr(jobs, "JOBS", tmp_path / "jobs")
    directory = jobs.save_job(extraction_job)
    root = tmp_path / "reviewed_metadata"
    (root / "configs").mkdir(parents=True)
    (root / "configs" / "arlington.lock.json").write_text("{}", encoding="utf-8")
    rows = [{"pdf_relative_path": f"unused-{index}.pdf", "pdf_sha256": f"{index:064x}"} for index in range(1452)]
    selection = {"job_id": REAL_JOB_ID, "rows": rows, "selection_sha256": jobs.sha(jobs.encoded(rows))}
    jobs.immutable(directory / "selection.json", selection)
    jobs.immutable(directory / "claim.json", {"job_id": REAL_JOB_ID, "parent_pid": os.getppid(), "hypervisor_controls_attested": True})
    outputs = directory / "private_bundles"
    outputs.mkdir()
    for index in range(4, 724, 10):
        jobs.immutable(outputs / f"{index:04d}.json", _validated_cached_bundle(f"{index:064x}"))
    extracted_names = []

    def extract(path: Path, **kwargs) -> dict:
        extracted_names.append(path.name)
        bundle = _validated_cached_bundle(kwargs["expected_sha256"])
        bundle["status"] = "partial"
        bundle["coverage_report"]["worker"].update(peak_rss_bytes=1024, worker_cleanup_complete=False)
        return validate_bundle(bundle)

    replacements = {
        "malpdf.extraction.orchestrator": SimpleNamespace(extract_pdf=extract),
        "malpdf.extraction.arlington_model": SimpleNamespace(load_model=lambda path: None),
        "malpdf.extraction.jobs": SimpleNamespace(require_extraction_lab=lambda *args, **kwargs: None),
        "malpdf.static.code_inspector": SimpleNamespace(CodeInspectionLimits=lambda **kwargs: kwargs, _worker_count=lambda *args: None),
    }
    for name, replacement in replacements.items():
        monkeypatch.setitem(sys.modules, name, replacement)
    monkeypatch.setattr(runner, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(jobs, "preflight", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner, "worker_limits", lambda **kwargs: None)
    monkeypatch.setattr(runner, "pdf_metadata", lambda job: (root, root, rows))
    monkeypatch.setenv("MALPDF_LAB_ISOLATED", "0")
    runner.pdf_worker(REAL_JOB_ID, shard=4, count=10)
    assert extracted_names == ["unused-724.pdf"]
    assert (outputs / "0724.json").is_file()
    assert not (outputs / "0734.json").exists()
    checkpoint = json.loads((outputs / "0724.json").read_bytes())
    assert checkpoint["coverage_report"]["worker"]["worker_cleanup_complete"] is False
    halted = json.loads((directory / "pdf_halt.4.json").read_bytes())
    assert halted["reason"] == "worker_cleanup_incomplete"
    assert halted["index"] == 724
    summary = json.loads((directory / "pdf_summary.4.json").read_bytes())
    assert summary["completed"] == 73


def _validated_cached_bundle(digest: str = "a" * 64) -> dict:
    return normalize_profile({"status": "complete", "errors": [], "worker_cleanup_complete": True}, digest, "fast-static")


def test_matching_validated_bundle_with_completed_cleanup_can_be_reused(jobs) -> None:
    runner = importlib.import_module("lab_runner")
    bundle = _validated_cached_bundle()
    before = json.dumps(bundle, sort_keys=True)
    assert runner.reusable_pdf_bundle(bundle, "a" * 64) is True
    assert json.dumps(bundle, sort_keys=True) == before


@pytest.mark.parametrize("cleanup", [False, None, 1, "true"])
def test_cached_bundle_without_verified_cleanup_cannot_be_reused(jobs, cleanup) -> None:
    runner = importlib.import_module("lab_runner")
    bundle = _validated_cached_bundle()
    bundle["coverage_report"]["worker"]["worker_cleanup_complete"] = cleanup
    assert runner.reusable_pdf_bundle(bundle, "a" * 64) is False


def test_cached_bundle_with_missing_cleanup_cannot_be_reused(jobs) -> None:
    runner = importlib.import_module("lab_runner")
    bundle = _validated_cached_bundle()
    del bundle["coverage_report"]["worker"]["worker_cleanup_complete"]
    assert runner.reusable_pdf_bundle(bundle, "a" * 64) is False


def test_cached_bundle_identity_must_match_selection(jobs) -> None:
    runner = importlib.import_module("lab_runner")
    assert runner.reusable_pdf_bundle(_validated_cached_bundle(), "b" * 64) is False


@pytest.mark.parametrize("status", [None, [], {}, 42, "complete", "invented_status"])
def test_cached_bundle_malformed_status_is_rejected_without_type_errors(jobs, status) -> None:
    runner = importlib.import_module("lab_runner")
    bundle = _validated_cached_bundle()
    bundle["status"] = status
    assert runner.reusable_pdf_bundle(bundle, "a" * 64) is False


@pytest.mark.parametrize("corruption", ["missing_evidence_store", "mismatched_store_identity", "invalid_digest"])
def test_cached_bundle_requires_full_schema_validation_before_reuse(jobs, corruption: str) -> None:
    runner = importlib.import_module("lab_runner")
    bundle = _validated_cached_bundle()
    if corruption == "missing_evidence_store":
        del bundle["evidence_store"]
    elif corruption == "mismatched_store_identity":
        bundle["feature_store"]["sample_sha256"] = "b" * 64
    else:
        bundle["sample_sha256"] = "not-a-valid-sha256"
    assert runner.reusable_pdf_bundle(bundle, "a" * 64) is False


def test_immutable_replay_accepts_identical_large_structured_metadata(jobs, tmp_path: Path) -> None:
    value = {"metadata": "x" * (600 * 1024)}
    path = tmp_path / "selection.json"
    jobs.immutable(path, value)
    original = path.read_bytes()
    assert len(original) > 512 * 1024
    jobs.immutable(path, value)
    assert path.read_bytes() == original


def test_immutable_replay_rejects_changed_large_metadata_without_overwrite(jobs, tmp_path: Path) -> None:
    value = {"metadata": "x" * (600 * 1024)}
    path = tmp_path / "selection.json"
    jobs.immutable(path, value)
    original = path.read_bytes()
    changed = {"metadata": "y" * (600 * 1024)}
    with pytest.raises(ValueError):
        jobs.immutable(path, changed)
    assert path.read_bytes() == original

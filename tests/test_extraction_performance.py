"""Snapshot parity, eager scheduling and verified extraction resume."""

from copy import deepcopy
import csv
import hashlib
import io
import json
from pathlib import Path
import threading

import pytest
import yaml
from pypdf import PdfWriter

from malpdf.extraction import batch
from malpdf.extraction.checkpointing import CheckpointScheduler
from malpdf.extraction.contracts import validate_bundle
from malpdf.extraction.normalize import normalize_profile
from malpdf.extraction.parser_views import inspect_parser_views
from malpdf.extraction.raw import inspect_raw_layout
from malpdf.extraction.raw_forensic import inspect_raw_forensic
from malpdf.extraction.resume import verify_blobs
from malpdf.extraction.vm_jobs import run_vm_job
from malpdf.static.code_inspector import CodeInspectionLimits, VMInspectionLimits
from malpdf.static.execution import UNLIMITED
from test_arlington import pdf
from test_extraction_jobs import root
from test_extraction_vm import fast_bundle, vm_configuration


def test_vm_snapshot_scheduler_accounts_for_snapshot_cost_and_flushes_boundaries() -> None:
    now = [0.0]
    schedule = CheckpointScheduler(VMInspectionLimits(), clock=lambda: now[0])
    assert schedule.due()
    now[0] = 0.2
    schedule.completed()
    now[0] = 0.6
    assert not schedule.due()
    now[0] = 2.21
    assert schedule.due()
    schedule.completed()
    assert not schedule.due()
    assert schedule.due(force=True)
    assert schedule.snapshots == 2


def test_bounded_snapshot_cadence_is_preserved() -> None:
    schedule = CheckpointScheduler(CodeInspectionLimits(), clock=lambda: 0.0)
    for _ in range(5):
        assert schedule.due()
        schedule.completed()
    assert schedule.snapshots == 5


@pytest.mark.parametrize("kind", ["native", "raw"])
def test_coalesced_final_evidence_matches_every_snapshot_reference(monkeypatch, kind) -> None:
    data = pdf(b"<< /Type /Catalog /Pages 2 0 R >>", others=[
        (2, b"<< /Type /Pages /Count 0 /Kids [] >>"),
        *[(index, f"<< /Value {index} >>".encode()) for index in range(3, 35)]])
    def inspect(checkpoint):
        if kind == "native":
            return inspect_parser_views(data, VMInspectionLimits(), checkpoint=checkpoint)
        return inspect_raw_forensic(data, VMInspectionLimits(), remaining=UNLIMITED, checkpoint=checkpoint)
    snapshots = []
    result = inspect(lambda value: snapshots.append(value))
    reference_snapshots = [0]
    with monkeypatch.context() as patch:
        patch.setattr(CheckpointScheduler, "due", lambda self, **kwargs: True)
        def checkpoint(value):
            reference_snapshots[0] += 1
        reference = inspect(checkpoint)
    assert result == reference
    assert snapshots[-1] == result
    assert reference_snapshots[0] > len(snapshots) * 5


def test_stream_and_artifact_stages_force_a_complete_final_snapshot() -> None:
    from malpdf.extraction.carving import RecursiveCarver
    from malpdf.extraction.streams import StreamCollector
    for collector in (StreamCollector("a" * 64, VMInspectionLimits()), RecursiveCarver("a" * 64, VMInspectionLimits())):
        snapshots = []
        collector.checkpoint = lambda value: snapshots.append(deepcopy(value))
        result = collector.finish(UNLIMITED)
        assert snapshots[-1] == result and result["complete"]


def test_batch_refills_before_the_consumer_requests_another_result(monkeypatch, tmp_path) -> None:
    second_started = threading.Event()
    def extract(path, **kwargs):
        if path.name == "second.pdf":
            second_started.set()
        return fast_bundle()
    monkeypatch.setattr(batch, "extract_pdf", extract)
    results = batch.extract_pdfs([Path("first.pdf"), Path("second.pdf")], boundary=tmp_path, workers=1)
    assert next(results)[0] == 0
    assert second_started.wait(timeout=5)
    assert next(results)[0] == 1
    results.close()


def test_batch_keeps_global_indices_for_resumed_subsets(monkeypatch, tmp_path) -> None:
    seen = []
    def extract(path, **kwargs):
        seen.append(kwargs["raw_artifact_dir"].name)
        return fast_bundle()
    monkeypatch.setattr(batch, "extract_pdf", extract)
    events = []
    results = dict(batch.extract_pdfs([Path("one.pdf"), Path("two.pdf")], input_indices=[3, 17],
        boundary=tmp_path, raw_artifact_root=tmp_path / "streams", workers=1, progress=events.append))
    assert set(results) == {3, 17}
    assert seen == ["sample_00000003", "sample_00000017"]
    assert {event["input_index"] for event in events if event["event"] == "sample_started"} == {3, 17}


def test_later_submission_error_keeps_the_already_completed_sample(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(batch, "extract_pdf", lambda *args, **kwargs: fast_bundle())
    results = batch.extract_pdfs([Path("one.pdf"), Path("two.pdf")], boundary=tmp_path,
        workers=1, expected_hashes={0: "a" * 64})
    assert next(results)[0] == 0
    with pytest.raises(ValueError, match="Missing expected hash"):
        next(results)


@pytest.fixture
def resumable(root, monkeypatch):
    config = vm_configuration(root)
    cohort_path = root / "configs/cic_synthetic.yaml"
    cohort = yaml.safe_load(cohort_path.read_text())
    identities = {"train_0_0", "train_1_0", "validation_0_0", "test_1_0"}
    digests = {}
    for identity in identities:
        writer = PdfWriter()
        writer.add_blank_page(72, 72)
        writer.add_metadata({"/Title": identity})
        buffer = io.BytesIO()
        writer.write(buffer)
        data = buffer.getvalue()
        digests[identity] = hashlib.sha256(data).hexdigest()
        path = root / f"data/raw/cic_pdf/{identity}.pdf"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    for name in ("split_manifest", "source_manifest", "normalization_manifest"):
        path = root / cohort[name]["path"]
        with path.open(newline="") as handle:
            rows = list(csv.DictReader(handle))
        selected = []
        for row in rows:
            identity = row.get("sample_id", Path(row.get("pdf_relative_path", "")).stem)
            if identity in identities:
                if "pdf_sha256" in row:
                    row["pdf_sha256"] = digests[identity]
                selected.append(row)
        with path.open("w", newline="") as handle:
            output = csv.DictWriter(handle, fieldnames=list(rows[0]))
            output.writeheader()
            output.writerows(selected)
        cohort[name]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    cohort_path.write_text(yaml.safe_dump(cohort))
    calls = []
    def extract(paths, **kwargs):
        for index, path in zip(kwargs["input_indices"], paths, strict=True):
            calls.append(index)
            data = path.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            layout = inspect_raw_layout(data, full_scan=True)
            profile = {"status": "complete", "raw_layout": layout, "errors": [],
                "worker_result_received": True, "worker_cleanup_complete": True, "worker_seconds": 1.0}
            if digest != kwargs["expected_hashes"][index]:
                profile.update(status="input_error", worker_result_received=False, errors=["input_checksum_mismatch"])
            yield index, normalize_profile(profile, digest, "fast-static", provenance={"seed": 42})
    monkeypatch.setattr("malpdf.extraction.vm_jobs.extract_pdfs", extract)
    return root, config, calls


def test_resume_reuses_verified_outputs_and_can_resume_again(resumable) -> None:
    root, config, calls = resumable
    first = run_vm_job(root, config)
    assert sorted(calls) == [0, 1, 2]
    calls.clear()
    second = run_vm_job(root, config, resume_from=first["run_id"])
    assert calls == [] and second["rows"] == second["reused"] == 3
    third = run_vm_job(root, config, resume_from=second["run_id"])
    assert calls == [] and third["reused"] == 3
    records = sorted((root / third["output_path"]).glob("sample_*.json"))
    assert len(records) == 3
    for path in records:
        bundle = json.loads(path.read_text())["bundle"]
        validate_bundle(bundle)
        assert bundle["coverage_report"]["provenance"]["reused_from"]["run_id"] == second["run_id"]
    summary = json.loads((root / third["report_path"]).with_name("coverage_summary.json").read_text())
    assert summary["newly_extracted"] == summary["timed_rows"] == 0
    assert summary["worker_seconds_median"] is None


@pytest.mark.parametrize("change", ["record", "input", "unfinished", "duplicate_journal", "torn_journal"])
def test_resume_recomputes_changed_or_unfinished_occurrences(resumable, change) -> None:
    root, config, calls = resumable
    first = run_vm_job(root, config)
    directory = root / first["output_path"]
    journal_path = directory / "completed_samples.jsonl"
    lines = journal_path.read_text().splitlines()
    entry = json.loads(lines[0])
    path = directory / entry["path"]
    if change == "record":
        path.write_text(path.read_text() + "\n")
    elif change == "input":
        saved = json.loads(path.read_text())
        raw = root / f"data/raw/cic_pdf/{saved['sample_id']}.pdf"
        raw.write_bytes(raw.read_bytes() + b" benign suffix")
    elif change == "unfinished":
        saved = json.loads(path.read_text())
        saved["bundle"]["coverage_report"]["worker"]["worker_result_received"] = False
        path.write_text(json.dumps(saved))
        entry["record_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        lines[0] = json.dumps(entry)
        journal_path.write_text("\n".join(lines) + "\n")
    elif change == "duplicate_journal":
        journal_path.write_text("\n".join([*lines, lines[0]]) + "\n")
    else:
        journal_path.write_text("\n".join(lines) + '\n{"input_')
    calls.clear()
    second = run_vm_job(root, config, resume_from=first["run_id"])
    if change == "torn_journal":
        assert calls == [] and second["reused"] == 3
    else:
        assert calls == [entry["input_index"]] and second["reused"] == 2
    assert second["rows"] == 3


def test_code_change_does_not_block_a_fresh_run_but_invalidates_resume(resumable) -> None:
    root, config, calls = resumable
    first = run_vm_job(root, config)
    path = root / "src/malpdf/example.py"
    path.parent.mkdir(parents=True)
    path.write_text("value = 2\n")
    calls.clear()
    second = run_vm_job(root, config, resume_from=first["run_id"])
    assert sorted(calls) == [0, 1, 2] and second["reused"] == 0
    summary = json.loads((root / second["report_path"]).with_name("coverage_summary.json").read_text())
    assert summary["resume"]["status"] == "incompatible"


def test_interrupted_run_retains_a_reusable_completed_prefix(resumable, monkeypatch) -> None:
    root, config, calls = resumable
    from malpdf.extraction import vm_jobs
    original = vm_jobs.extract_pdfs
    def interrupted(*args, **kwargs):
        for result in original(*args, **kwargs):
            yield result
            raise KeyboardInterrupt()
    monkeypatch.setattr(vm_jobs, "extract_pdfs", interrupted)
    with pytest.raises(KeyboardInterrupt):
        run_vm_job(root, config)
    path = next((root / "reports/experiments/pdf_extraction_vm").glob("*/run_summary.json"))
    state = json.loads(path.read_text())
    assert state["status"] == "interrupted" and state["rows"] == 1
    monkeypatch.setattr(vm_jobs, "extract_pdfs", original)
    calls.clear()
    result = run_vm_job(root, config, resume_from=state["run_id"])
    assert len(calls) == 2 and result["reused"] == 1 and result["rows"] == 3


@pytest.mark.parametrize("change", ["content", "missing", "symlink", "outside", "unfinished"])
def test_resume_verifies_retained_blobs_and_never_follows_external_paths(tmp_path, change) -> None:
    output = tmp_path / "data/processed/pdf_extraction"
    directory = output / "run_first"
    storage = directory / "streams/sample_00000000"
    storage.mkdir(parents=True)
    content = b"benign synthetic blob"
    digest = hashlib.sha256(content).hexdigest()
    path = storage / (digest + ".bin")
    path.write_bytes(content)
    bundle = {"extraction_profile": "deep-static", "coverage_report": {
        "provenance": {"raw_artifact_directory": str(storage)}}, "evidence_store": {"records": [
        {"kind": "stream_analysis", "details": {"storage": {"unfinished_stream": False,
            "records": [{"sha256": digest, "size_bytes": len(content), "status": "verified"}]}}}]}}
    verify_blobs(tmp_path, directory, 0, bundle)
    verify_blobs(tmp_path, output / "run_second", 0, bundle)
    if change == "content":
        path.write_bytes(b"changed")
    elif change == "missing":
        path.unlink()
    elif change == "symlink":
        path.unlink()
        path.symlink_to(tmp_path / "outside.bin")
    elif change == "outside":
        bundle["coverage_report"]["provenance"]["raw_artifact_directory"] = str(tmp_path / "outside")
    else:
        bundle["evidence_store"]["records"][0]["details"]["storage"]["unfinished_stream"] = True
    with pytest.raises((OSError, ValueError)):
        verify_blobs(tmp_path, directory, 0, bundle)

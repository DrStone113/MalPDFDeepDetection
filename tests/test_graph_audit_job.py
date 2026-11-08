from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from malpdf.extraction.normalize import normalize_profile


PRIVATE_SENTINEL = "PRIVATE_SAVED_BUNDLE_TEXT_MUST_NOT_LEAVE_LAB"


@pytest.fixture
def tool(monkeypatch):
    path = Path(__file__).resolve().parents[1] / "scripts/lab/audit_graph_extraction.py"
    monkeypatch.syspath_prepend(str(path.parent))
    spec = importlib.util.spec_from_file_location("graph_audit_job_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "sys", SimpleNamespace(**{**vars(module.sys), "platform": "linux"}))
    return module


def _write_json(path, value, jobs):
    payload = jobs.encoded(value) + b"\n"
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _source(tmp_path):
    jobs = importlib.import_module("lab_jobs")
    job = jobs.make_job("a" * 40, "b" * 64, "c" * 64, mode="offline", kind="pdf-static-cve", attempt="3" * 32)
    job_root = tmp_path / "jobs"
    folder = job_root / job["job_id"]
    bundles = folder / "private_bundles"
    bundles.mkdir(parents=True)
    rows = [{"pdf_sha256": char * 64, "split": split, "Label": str(label)}
            for char, split, label in (("a", "train", 0), ("b", "train", 1), ("c", "validation", 0), ("d", "validation", 1), ("e", "test", 1))]
    _write_json(folder / "job.json", job, jobs)
    _write_json(folder / "selection.json", {"job_id": job["job_id"], "rows": rows,
        "selection_sha256": jobs.sha(jobs.encoded(rows))}, jobs)
    summary = {"planned": 5, "completed": 5, "observed": 5, "bounded_complete": 0, "partial": 0, "failed": 0,
               "primary_available": 0, "timeout": 0, "elapsed_ms": 1234, "peak_rss_bytes": 1024, "status_counts": {"observed": 5}}
    environment = {"mode": "offline", "guest_network_checked": True, "stdlib_dependencies_checked": True, "hypervisor_controls_attested": True}
    _write_json(folder / "result.json", jobs.result(job, "partial", summary=summary, environment=environment), jobs)
    expected = []
    for index, row in enumerate(rows):
        bundle = normalize_profile({"status": "complete", "errors": [], "worker_cleanup_complete": True}, row["pdf_sha256"], "fast-static")
        bundle["coverage_report"]["provenance"]["source_path"] = PRIVATE_SENTINEL
        bundle["coverage_report"]["worker"]["raw_exception"] = PRIVATE_SENTINEL
        digest = _write_json(bundles / f"{index:04d}.json", bundle, jobs)
        expected.append({"index": index, "sha256": row["pdf_sha256"], "split": row["split"], "label": int(row["Label"]),
                         "source_bundle_sha256": digest, "availability": "present"})
    expected_path = tmp_path / "expected_index.json"
    _write_json(expected_path, expected, jobs)
    return job, job_root, folder, expected_path, expected


def _run(tool, job, job_root, expected, output_root):
    receipt = tool.audit_job(job["job_id"], expected, job_root=job_root, output_root=output_root)
    folder = Path(receipt["output"])
    rows = [json.loads(line) for line in (folder / "cases.jsonl").read_text(encoding="utf-8").splitlines()]
    return receipt, folder, rows


def test_saved_bundle_audit_keeps_all_samples_private_content_and_originals(tool, tmp_path):
    job, job_root, source, expected_path, expected = _source(tmp_path)
    before = {path.relative_to(source).as_posix(): path.read_bytes() for path in source.rglob("*") if path.is_file()}
    receipt, output, rows = _run(tool, job, job_root, expected_path, tmp_path / "outputs")
    assert receipt["records"] == len(rows) == 5
    assert receipt["model_input_ready"] is False
    assert receipt["raw_pdf_processing"] is False
    assert [row["availability"] for row in rows] == ["present"] * 5
    for row, pinned in zip(rows, expected):
        assert set(row) == {"index", "sha256", "split", "label", "expected_bundle_sha256", "source_bundle_sha256",
                            "availability", "bundle_schema_valid", "focus_missing_graph", "audit"}
        assert all(row[key] == pinned[key] for key in ("index", "sha256", "split", "label"))
        assert row["source_bundle_sha256"] == row["expected_bundle_sha256"] == pinned["source_bundle_sha256"]
        assert row["bundle_schema_valid"] is True
        assert row["audit"]["graph"]["feature_dim"] is None
    assert before == {path.relative_to(source).as_posix(): path.read_bytes() for path in source.rglob("*") if path.is_file()}
    for name in ("locked_methodology.json", "cases.jsonl", "metrics.json", "audit_report.md"):
        assert (output / name).is_file()
        assert PRIVATE_SENTINEL not in (output / name).read_text(encoding="utf-8")


def test_same_source_audit_creates_new_immutable_run_instead_of_overwriting(tool, tmp_path):
    job, job_root, _, expected_path, _ = _source(tmp_path)
    _, first, _ = _run(tool, job, job_root, expected_path, tmp_path / "outputs")
    before = {path.name: path.read_bytes() for path in first.iterdir() if path.is_file()}
    _, second, _ = _run(tool, job, job_root, expected_path, tmp_path / "outputs")
    assert second != first
    assert before == {path.name: path.read_bytes() for path in first.iterdir() if path.is_file()}


def test_missing_and_changed_bundles_keep_selection_denominator_without_analysis(tool, tmp_path):
    job, job_root, source, expected_path, _ = _source(tmp_path)
    (source / "private_bundles/0001.json").unlink()
    path = source / "private_bundles/0003.json"
    payload = json.loads(path.read_bytes())
    payload["coverage_report"]["worker"]["worker_seconds"] = 999
    path.write_text(json.dumps(payload), encoding="utf-8")
    receipt, _, rows = _run(tool, job, job_root, expected_path, tmp_path / "outputs")
    assert receipt["records"] == len(rows) == 5
    assert [row["availability"] for row in rows] == ["present", "missing", "present", "checksum_mismatch", "present"]
    assert rows[1]["audit"] is None
    assert rows[3]["audit"] is None


@pytest.mark.parametrize("corruption", ["invalid_json", "invalid_schema"])
def test_pinned_invalid_bundle_is_accounted_for_without_losing_samples(tool, tmp_path, corruption):
    jobs = importlib.import_module("lab_jobs")
    job, job_root, source, expected_path, expected = _source(tmp_path)
    path = source / "private_bundles/0002.json"
    if corruption == "invalid_json":
        path.write_bytes(b"{malformed-json")
    else:
        value = json.loads(path.read_bytes())
        del value["coverage_report"]["groups"]
        _write_json(path, value, jobs)
    expected[2]["source_bundle_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    _write_json(expected_path, expected, jobs)
    receipt, _, rows = _run(tool, job, job_root, expected_path, tmp_path / "outputs")
    assert receipt["records"] == len(rows) == 5
    assert rows[2]["availability"] == corruption
    assert rows[2]["bundle_schema_valid"] is False
    if corruption == "invalid_json":
        assert rows[2]["audit"] is None
    else:
        assert rows[2]["audit"] is not None


@pytest.mark.parametrize("corruption", ["selection_hash", "job_identity"])
def test_tampered_job_or_selection_is_refused_before_output_creation(tool, tmp_path, corruption):
    job, job_root, source, expected_path, _ = _source(tmp_path)
    if corruption == "selection_hash":
        path = source / "selection.json"
        value = json.loads(path.read_bytes())
        value["rows"][0]["split"] = "test"
    else:
        path = source / "job.json"
        value = json.loads(path.read_bytes())
        value["attempt"] = "f" * 32
    path.write_text(json.dumps(value), encoding="utf-8")
    output = tmp_path / "outputs"
    with pytest.raises(ValueError):
        tool.audit_job(job["job_id"], expected_path, job_root=job_root, output_root=output)
    assert not output.exists()


@pytest.mark.parametrize("field,value", [("split", "test"), ("label", 1), ("label", False), ("index", True)])
def test_expected_index_must_match_pinned_selection_with_strict_metadata_types(tool, tmp_path, field, value):
    jobs = importlib.import_module("lab_jobs")
    job, job_root, _, expected_path, expected = _source(tmp_path)
    expected[0][field] = value
    _write_json(expected_path, expected, jobs)
    output = tmp_path / "outputs"
    with pytest.raises(ValueError):
        tool.audit_job(job["job_id"], expected_path, job_root=job_root, output_root=output)
    assert not output.exists()


@pytest.mark.parametrize("corruption", ["present_without_audit", "present_without_hash", "present_changed_hash", "present_invalid_schema", "missing_with_data"])
def test_received_row_cannot_claim_present_without_matching_verified_measurements(tool, tmp_path, corruption):
    job, job_root, _, expected_path, _ = _source(tmp_path)
    _, _, rows = _run(tool, job, job_root, expected_path, tmp_path / "outputs")
    row = rows[0]
    if corruption == "present_without_audit":
        row["audit"] = None
        row["focus_missing_graph"] = None
    elif corruption == "present_without_hash":
        row["source_bundle_sha256"] = None
    elif corruption == "present_changed_hash":
        row["source_bundle_sha256"] = "f" * 64
    elif corruption == "present_invalid_schema":
        row["bundle_schema_valid"] = False
    else:
        row["availability"] = "missing"
    with pytest.raises(ValueError):
        tool.validate_row(row)


def test_symlink_bundle_is_refused_without_following_target(tool, tmp_path):
    job, job_root, source, expected_path, _ = _source(tmp_path)
    path = source / "private_bundles/0001.json"
    outside = tmp_path / "outside.json"
    path.rename(outside)
    try:
        path.symlink_to(outside)
    except OSError:
        pytest.skip("Symlink creation unavailable for this account")
    receipt, _, rows = _run(tool, job, job_root, expected_path, tmp_path / "outputs")
    assert receipt["records"] == 5
    assert rows[1]["availability"] == "unsafe_or_oversize"
    assert rows[1]["audit"] is None

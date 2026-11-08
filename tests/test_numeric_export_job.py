from __future__ import annotations

import gzip
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from malpdf.extraction.normalize import normalize_profile
from malpdf.extraction.numeric_export import validate_numeric_projection


@pytest.fixture
def exporter(monkeypatch):
    path = Path(__file__).resolve().parents[1] / "scripts/lab/export_numeric_postrun.py"
    monkeypatch.syspath_prepend(str(path.parent))
    spec = importlib.util.spec_from_file_location("numeric_export_job", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.sys = SimpleNamespace(platform="win32")
    return module


def prepare_job(exporter, tmp_path):
    jobs = importlib.import_module("lab_jobs")
    job = jobs.make_job("a" * 40, "b" * 64, "c" * 64, mode="offline", kind="pdf-static-cve", attempt="2" * 32)
    job_id = job["job_id"]
    folder = tmp_path / "jobs" / job_id
    (folder / "private_bundles").mkdir(parents=True)
    rows = [{"pdf_sha256": char * 64, "split": split, "Label": label}
            for char, split, label in (("a", "train", 0), ("b", "validation", 1), ("c", "test", 0), ("d", "train", 1), ("e", "validation", 0))]
    (folder / "job.json").write_bytes(exporter.encoded(job))
    (folder / "selection.json").write_bytes(exporter.encoded({"job_id": job_id, "rows": rows,
        "selection_sha256": exporter.digest(exporter.encoded(rows))}))
    summary = {"planned": 5, "completed": 2, "observed": 2, "bounded_complete": 0, "partial": 0, "failed": 0,
               "primary_available": 0, "timeout": 0, "elapsed_ms": 0, "peak_rss_bytes": 0, "status_counts": {"observed": 2}}
    environment = {"mode": "offline", "guest_network_checked": True, "stdlib_dependencies_checked": True, "hypervisor_controls_attested": True}
    (folder / "result.json").write_bytes(exporter.encoded(jobs.result(job, "partial", summary=summary, environment=environment)))
    bundle = normalize_profile({"status": "complete", "errors": [], "worker_cleanup_complete": True}, "a" * 64, "fast-static")
    (folder / "private_bundles/0000.json").write_bytes(exporter.encoded(bundle))
    bundle["sample_sha256"] = "d" * 64
    (folder / "private_bundles/0002.json").write_bytes(exporter.encoded(bundle))
    return job_id, folder


def test_export_keeps_denominator_and_rejects_invalid_identity_without_placeholder_graphs(exporter, tmp_path, monkeypatch):
    monkeypatch.setattr(exporter.sys, "platform", "linux")
    job_id, source = prepare_job(exporter, tmp_path)
    before = {path.name: path.read_bytes() for path in source.iterdir() if path.is_file()}
    receipt = exporter.export_job(job_id, job_root=tmp_path / "jobs", export_root=tmp_path / "exports")
    output = Path(receipt["output"])
    with gzip.open(output / "numeric.jsonl.gz", "rt") as stream:
        records = [json.loads(line) for line in stream]
    assert len(records) == 5
    assert [row["availability"] for row in records] == ["present", "missing", "invalid", "missing", "missing"]
    assert records[1]["numeric"] is None
    assert records[2]["numeric"] is None
    validate_numeric_projection(records[0]["numeric"], "a" * 64)
    assert records[0]["numeric"]["graph"]["model_input_ready"] is False
    coverage = json.loads((output / "coverage.json").read_bytes())
    assert coverage["planned"] == 5
    assert coverage["missing_indices"] == [1, 3, 4]
    assert coverage["invalid_indices"] == [2]
    assert coverage["raw_pdf_processing"] is False
    assert before == {path.name: path.read_bytes() for path in source.iterdir() if path.is_file()}
    manifest = json.loads((output / "manifest.json").read_bytes())
    for item in manifest["files"]:
        assert item["sha256"] == exporter.digest((output / item["name"]).read_bytes())
    with pytest.raises(FileExistsError):
        exporter.export_job(job_id, job_root=tmp_path / "jobs", export_root=tmp_path / "exports")


def test_tampered_selection_is_refused_before_export_creation(exporter, tmp_path, monkeypatch):
    monkeypatch.setattr(exporter.sys, "platform", "linux")
    job_id, folder = prepare_job(exporter, tmp_path)
    selection = json.loads((folder / "selection.json").read_bytes())
    selection["rows"][0]["split"] = "test"
    (folder / "selection.json").write_bytes(exporter.encoded(selection))
    with pytest.raises(ValueError, match="selection_identity"):
        exporter.export_job(job_id, job_root=tmp_path / "jobs", export_root=tmp_path / "exports")
    assert not (tmp_path / "exports").exists()

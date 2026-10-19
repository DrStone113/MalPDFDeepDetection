"""VM scheduling, uncapped static work and preserved partition provenance."""

import hashlib
import io
import json
import os
from pathlib import Path
import csv
import random
import resource
import threading
import zlib

import pytest
from pypdf import PdfWriter
from pypdf.generic import DictionaryObject, NameObject, NumberObject
import yaml

from malpdf.extraction import batch
from malpdf.extraction.contracts import validate_bundle
from malpdf.extraction.filters import decode_filters
from malpdf.extraction.normalize import normalize_profile
from malpdf.extraction.orchestrator import extract_pdf
from malpdf.extraction.parser_views import inspect_parser_views
from malpdf.extraction.raw import inspect_raw_layout, MAX_MARKERS, MAX_WINDOWS, WINDOW_BYTES
from malpdf.extraction.raw_forensic import inspect_raw_forensic
from malpdf.extraction.streams import StreamCollector
from malpdf.extraction.vm_jobs import load_vm_configuration, run_vm_job, select_manifest_rows
from malpdf.static.code_inspector import CodeInspectionLimits, VMInspectionLimits, _worker_count
from malpdf.static.execution import UNLIMITED
from malpdf.static.profile_worker import profile_pdf
from test_extraction_jobs import root


def benign_bytes() -> bytes:
    writer = PdfWriter()
    writer.add_blank_page(72, 72)
    output = io.BytesIO()
    writer.write(output)
    return output.getvalue()


def fast_bundle() -> dict:
    layout = inspect_raw_layout(b"%PDF-1.7\n%%EOF")
    return normalize_profile({"status": "complete", "errors": [], "raw_layout": layout},
        layout["sha256"], "fast-static")


def vm_configuration(root: Path) -> Path:
    cfg = {"execution_mode": "vm", "cohort_config": "configs/cic_synthetic.yaml", "cohort": "cic",
        "raw_boundary": "data/raw/cic_pdf", "output_root": "data/processed/pdf_extraction",
        "profile": "fast-static", "seed": 42, "workers": "auto", "partitions": ["train", "validation"],
        "limits": {}}
    path = root / "configs/extraction_vm.yaml"
    path.write_text(yaml.safe_dump(cfg))
    return path


def test_vm_limits_preserve_explicit_legacy_profile_and_reject_quotas() -> None:
    limits = VMInspectionLimits()
    assert limits.max_file_bytes == limits.max_decoded_bytes == UNLIMITED
    assert limits.wall_seconds is limits.cpu_seconds is limits.memory_bytes is None
    assert CodeInspectionLimits().cpu_seconds == 4
    with pytest.raises(ValueError, match="does not impose"):
        VMInspectionLimits(cpu_seconds=12)


def test_vm_worker_count_has_no_sixteen_process_ceiling(monkeypatch) -> None:
    monkeypatch.setattr("malpdf.static.execution.available_cpus", lambda: 64)
    assert _worker_count(64, VMInspectionLimits()) == 64


def test_vm_raw_scan_covers_tail_windows_names_and_markers() -> None:
    data = b"%PDF-1.7\n" + b"%%EOF\n" * (MAX_MARKERS + 5) + b"x" * (WINDOW_BYTES * MAX_WINDOWS)
    data += b" /J#53 " * 4100
    result = inspect_raw_layout(data, full_scan=True)
    assert result["markers"]["eof"]["complete"]
    assert len(result["markers"]["eof"]["offsets"]) == MAX_MARKERS + 5
    assert result["entropy_windows_complete"] and len(result["entropy_windows"]) > MAX_WINDOWS
    assert result["name_scan_complete"] and result["escaped_name_candidates"] == 4100


def test_vm_filters_decode_past_previous_stage_and_total_byte_caps() -> None:
    limits = VMInspectionLimits()
    collector = StreamCollector("a" * 64, limits)
    data = random.Random(42).randbytes(9 * 1024**2)
    result = decode_filters(zlib.compress(data), ["/FlateDecode"], limits=collector.limits)
    assert result.data == data and result.metadata["status"] == "observed"
    assert result.metadata["decoded_byte_debit"] == len(data)


def test_vm_native_inventory_keeps_all_dictionary_keys() -> None:
    writer = PdfWriter()
    writer.add_blank_page(72, 72)
    writer._root_object[NameObject("/Wide")] = DictionaryObject({
        NameObject(f"/Key{index}"): NumberObject(index) for index in range(1100)})
    output = io.BytesIO()
    writer.write(output)
    result = inspect_parser_views(output.getvalue(), VMInspectionLimits())
    assert len(result["views"]) == 3
    assert result["comparisons_complete"]
    assert all(view["enumeration_complete"] for view in result["views"])
    assert all(all(record["projection"]["projection_complete"] for record in view["records"])
               for view in result["views"])


def test_vm_raw_forensic_keeps_ir_beyond_previous_node_cap() -> None:
    data = b"%PDF-1.7\n1 0 obj\n[" + b"0 " * 8300 + b"]\nendobj\n%%EOF"
    result = inspect_raw_forensic(data, VMInspectionLimits(), remaining=UNLIMITED)
    assert len(result["syntax_nodes"]) > 8192
    assert "forensic_ir_node_limit" not in result["reason_codes"]


def test_vm_subpasses_respect_explicit_smaller_traversal_allowances() -> None:
    from malpdf.extraction.script_semantics import ScriptSemantics
    limits = VMInspectionLimits(max_objects=1, max_ast_nodes=20)
    assert ScriptSemantics("a" * 64, limits).limits.max_nodes == 20
    data = b"%PDF-1.7\n1 0 obj\n0\nendobj\n2 0 obj\n0\nendobj\n%%EOF"
    result = inspect_raw_forensic(data, limits, remaining=UNLIMITED)
    assert "forensic_object_limit" in result["reason_codes"]


def test_vm_cancellation_reaps_the_spawned_parser(tmp_path) -> None:
    cancellation = threading.Event()
    cancellation.set()
    result = profile_pdf(tmp_path / "unused.pdf", boundary=tmp_path, digest="a" * 64,
        limits=VMInspectionLimits(), analysis_version="v9", extraction_profile="fast-static",
        cancellation_event=cancellation)
    assert result["worker_cleanup_complete"]
    assert "extraction_cancelled" in result["errors"]


def test_vm_worker_reads_input_above_ten_megabytes_without_thread_or_os_quotas(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("OPENBLAS_NUM_THREADS", "3")
    monkeypatch.setenv("OMP_NUM_THREADS", "2")
    data = benign_bytes() + b" " * (11 * 1024**2)
    path = tmp_path / "benign.pdf"
    path.write_bytes(data)
    cpu_before = resource.getrlimit(resource.RLIMIT_CPU)
    memory_before = resource.getrlimit(resource.RLIMIT_AS)
    bundle = extract_pdf(path, boundary=tmp_path, profile="fast-static", limits=VMInspectionLimits())
    validate_bundle(bundle)
    assert bundle["sample_sha256"] == hashlib.sha256(data).hexdigest()
    applied = bundle["coverage_report"]["worker"]["resource_limits"]
    assert applied["cpu_seconds"] == list(cpu_before)
    assert applied["address_space_bytes"] == list(memory_before)
    assert applied["wall_seconds"] is None
    assert os.environ["OPENBLAS_NUM_THREADS"] == "3" and os.environ["OMP_NUM_THREADS"] == "2"
    assert bundle["coverage_report"]["provenance"]["environment"]["hardware"]["available_cpus"] > 0
    assert bundle["coverage_report"]["provenance"]["generating_commit"]
    assert bundle["coverage_report"]["provenance"]["worktree"]["status"] in {"dirty", "clean"}
    assert path.read_bytes() == data


def test_batch_runs_concurrently_and_retains_failed_occurrence(monkeypatch, tmp_path) -> None:
    barrier = threading.Barrier(2)
    options = []
    def extract(path, **kwargs):
        options.append(kwargs)
        barrier.wait(timeout=10)
        if path.name == "failure.pdf":
            raise ValueError("synthetic failure")
        return fast_bundle()
    monkeypatch.setattr(batch, "extract_pdf", extract)
    monkeypatch.setattr(batch, "available_cpus", lambda: 2)
    outcomes = dict(batch.extract_pdfs([Path("benign.pdf"), Path("failure.pdf")],
        boundary=tmp_path, workers=2, limits=VMInspectionLimits()))
    assert set(outcomes) == {0, 1}
    assert outcomes[1]["sample_sha256"] is None
    assert outcomes[1]["status"] != "observed"
    assert len(options) == 2 and all(item["limits"].execution_mode == "vm" for item in options)
    validate_bundle(outcomes[1])


def test_batch_close_cancels_running_coordinators(monkeypatch, tmp_path) -> None:
    started = threading.Event()
    stopped = threading.Event()
    def extract(path, **kwargs):
        if path.name == "first.pdf":
            assert started.wait(10)
            return fast_bundle()
        started.set()
        assert kwargs["cancellation_event"].wait(10)
        stopped.set()
        return fast_bundle()
    monkeypatch.setattr(batch, "extract_pdf", extract)
    monkeypatch.setattr(batch, "available_cpus", lambda: 2)
    results = batch.extract_pdfs([Path("first.pdf"), Path("second.pdf")], boundary=tmp_path, workers=2)
    assert next(results)[0] == 0
    results.close()
    assert stopped.is_set()


def test_batch_verifies_arlington_once_and_reuses_the_catalog(monkeypatch, tmp_path) -> None:
    from malpdf.extraction import arlington_model
    calls = []
    catalog = arlington_model.Catalog({}, {"status": "available"})
    def load(*args):
        calls.append(args)
        return catalog
    def extract(path, **kwargs):
        assert kwargs["arlington_catalog"] is catalog
        assert "arlington_lock" not in kwargs
        return fast_bundle()
    monkeypatch.setattr(arlington_model, "load_model", load)
    monkeypatch.setattr(batch, "extract_pdf", extract)
    results = list(batch.extract_pdfs([Path("one.pdf"), Path("two.pdf")], boundary=tmp_path,
        repository_root=tmp_path, arlington_lock="configs/arlington.lock.json"))
    assert len(results) == 2 and len(calls) == 1


def test_vm_arlington_reads_cached_ir_with_expanded_rule_ledger() -> None:
    from test_arlington import catalog, pdf, row
    captured = []
    inspect_raw_forensic(pdf(b"<< /Type /Catalog /N 3 >>"), VMInspectionLimits(), remaining=UNLIMITED,
        arlington_catalog=catalog([row("N")]), arlington_checkpoint=captured.append)
    assert captured[-1]["limits"]["max_checks"] == UNLIMITED
    assert captured[-1]["checks"] and captured[-1]["complete"]


@pytest.mark.parametrize("workers", [0, -1, True, "auto"])
def test_batch_rejects_invalid_explicit_worker_counts(workers, tmp_path) -> None:
    with pytest.raises(ValueError, match="workers"):
        list(batch.extract_pdfs([], boundary=tmp_path, workers=workers))


def test_batch_requires_every_expected_identity(tmp_path) -> None:
    with pytest.raises(ValueError, match="Missing expected hash"):
        list(batch.extract_pdfs([tmp_path / "missing.pdf"], boundary=tmp_path, expected_hashes={}))


def test_real_batch_isolates_native_workers_and_preserves_duplicate_inputs(tmp_path) -> None:
    path = tmp_path / "benign.pdf"
    path.write_bytes(benign_bytes())
    results = dict(batch.extract_pdfs([path, path, tmp_path / "missing.pdf"],
        boundary=tmp_path, profile="fast-static", workers=2))
    assert set(results) == {0, 1, 2}
    assert results[0]["sample_sha256"] == results[1]["sample_sha256"]
    assert results[2]["sample_sha256"] is None
    assert all(results[index]["coverage_report"]["worker"]["worker_cleanup_complete"] for index in (0, 1))


def test_vm_configuration_uses_all_saved_rows_without_pdf_access(root) -> None:
    cfg, cohort, rows, limits = load_vm_configuration(root, vm_configuration(root))
    assert len(rows) == 64 and {row["split"] for row in rows} == {"train", "validation"}
    assert cfg["workers"] == "auto" and limits.cpu_seconds is None
    assert not (root / "data/raw").exists()
    assert all(row["label_source"] for row in rows)


def test_vm_selection_retains_unbalanced_strata_and_checks_excluded_partitions() -> None:
    manifest = [{"sample_id": str(index), "Label": str(index % 2), "split": split,
        "cohort": "cic", "duplicate_group_id": str(index)}
        for index, split in enumerate(("train", "train", "train", "test"))]
    sources = [{"sample_id": row["sample_id"], "Label": row["Label"],
        "pdf_sha256": hashlib.sha256(row["sample_id"].encode()).hexdigest(),
        "related_group_id": row["sample_id"], "pdf_relative_path": f"data/raw/cic_pdf/{row['sample_id']}.pdf"}
        for row in manifest]
    chosen = select_manifest_rows(manifest, sources, partitions=["train"], cohort="cic", boundary=Path("data/raw/cic_pdf"))
    assert [row["sample_id"] for row in chosen] == ["0", "1", "2"]
    sources[-1]["related_group_id"] = sources[0]["related_group_id"]
    with pytest.raises(ValueError, match="crosses partitions"):
        select_manifest_rows(manifest, sources, partitions=["train"], cohort="cic", boundary=Path("data/raw/cic_pdf"))


def test_vm_job_runs_from_dirty_worktree_with_fresh_outputs_and_failure_denominators(root, monkeypatch) -> None:
    config = vm_configuration(root)
    def extract(paths, **kwargs):
        assert len(list(paths)) == 64
        assert kwargs["limits"].execution_mode == "vm"
        for index in range(64):
            result = fast_bundle()
            if index == 3:
                result = normalize_profile({"status": "worker_error", "errors": ["synthetic_failure"]}, None, "fast-static")
            yield index, result
    monkeypatch.setattr("malpdf.extraction.vm_jobs.extract_pdfs", extract)
    first = run_vm_job(root, config)
    second = run_vm_job(root, config)
    assert first["code_worktree"]["status"] == "dirty" and first["rows"] == 64
    assert first["output_path"] != second["output_path"]
    directory = root / Path(first["report_path"]).parent
    summary = json.loads((directory / "coverage_summary.json").read_text())
    assert summary["planned"] == summary["completed"] == 64
    assert sum(summary["statuses"].values()) == 64 and not summary["model_evaluation"]
    assert (directory / "locked_methodology.json").is_file() and (directory / "model_comparison.csv").is_file()
    assert (directory / "runtime_environment.json").is_file()
    assert len(list((root / first["output_path"]).glob("sample_*.json"))) == 64
    assert not (root / "data/raw").exists()


def test_vm_job_end_to_end_uses_saved_rows_and_writes_verified_bundles(root) -> None:
    config = vm_configuration(root)
    cohort_path = root / "configs/cic_synthetic.yaml"
    cohort = yaml.safe_load(cohort_path.read_text())
    identities = {"train_0_0", "train_1_0", "validation_0_0", "test_1_0"}
    digests = {}
    for identity in identities:
        writer = PdfWriter()
        writer.add_blank_page(72, 72)
        writer.add_metadata({"/Title": identity})
        output = io.BytesIO()
        writer.write(output)
        data = output.getvalue()
        digests[identity] = hashlib.sha256(data).hexdigest()
        if not identity.startswith("test_"):
            path = root / f"data/raw/cic_pdf/{identity}.pdf"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    for key in ("split_manifest", "source_manifest", "normalization_manifest"):
        path = root / cohort[key]["path"]
        with path.open(newline="") as handle:
            rows = list(csv.DictReader(handle))
        selected = []
        for row in rows:
            identity = row.get("sample_id", Path(row.get("pdf_relative_path", "")).stem)
            if identity not in identities:
                continue
            if "pdf_sha256" in row:
                row["pdf_sha256"] = digests[identity]
            selected.append(row)
        with path.open("w", newline="") as handle:
            output_table = csv.DictWriter(handle, fieldnames=list(rows[0]))
            output_table.writeheader()
            output_table.writerows(selected)
        cohort[key]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    cohort_path.write_text(yaml.safe_dump(cohort))
    state = run_vm_job(root, config)
    assert state["status"] == "completed" and state["rows"] == state["planned"] == 3
    records = [json.loads(path.read_text()) for path in (root / state["output_path"]).glob("sample_*.json")]
    assert {row["sample_id"] for row in records} == identities - {"test_1_0"}
    for record in records:
        validate_bundle(record["bundle"])
        assert record["bundle"]["sample_sha256"] == digests[record["sample_id"]]
        assert record["bundle"]["coverage_report"]["provenance"]["worktree"]["status"] == "dirty"
        assert record["bundle"]["coverage_report"]["worker"]["worker_cleanup_complete"]


@pytest.mark.parametrize("field,value", [("seed", 7), ("workers", 0), ("partitions", []),
    ("raw_boundary", "../outside"), ("limits", {"wall_seconds": 20}), ("profile", "full-hybrid")])
def test_vm_configuration_rejects_split_and_execution_drift(root, field, value) -> None:
    path = vm_configuration(root)
    cfg = yaml.safe_load(path.read_text())
    cfg[field] = value
    path.write_text(yaml.safe_dump(cfg))
    with pytest.raises(ValueError):
        load_vm_configuration(root, path)

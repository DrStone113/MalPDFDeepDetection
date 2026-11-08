from __future__ import annotations

import gzip
import hashlib
import importlib
import importlib.util
import json
import math
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from malpdf.extraction.contracts import validate_bundle
from malpdf.extraction.normalize import normalize_profile


SAMPLE_SHA256 = "a" * 64
PRIVATE_SENTINEL = "PRIVATE_RAW_CONTENT_NEVER_EXPORT_V2"


def _load_script(rel_path: str, mod_name: str, monkeypatch: pytest.MonkeyPatch):
    path = Path(__file__).resolve().parents[1] / rel_path
    monkeypatch.syspath_prepend(str(path.parent))
    spec = importlib.util.spec_from_file_location(mod_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "sys", SimpleNamespace(**{**vars(module.sys), "platform": "linux"}))
    return module


def _node(
    identifier: str,
    kind: str = "pdf_object",
    status: str = "observed",
    *,
    backend: str = "pypdf",
    number: int | None = None,
    generation: int | None = None,
    offset_start: int | None = None,
    raw_bytes: int | None = None,
    repaired: bool = False,
    value_type: str = "dict",
) -> dict:
    details: dict = {
        "secret": PRIVATE_SENTINEL,
        "projection": {"value_type": value_type, "projection_complete": True},
    }
    if raw_bytes is not None:
        details["raw_bytes"] = raw_bytes
    return {
        "evidence_id": identifier,
        "kind": kind,
        "backend": backend,
        "observation_status": status,
        "object_number": number,
        "generation": generation,
        "revision": None,
        "byte_offset_start": offset_start,
        "byte_offset_end": None,
        "filter_chain": None,
        "is_synthetic_repaired": repaired,
        "details": details,
    }


def _forensic_decl(identifier: str, number: int, generation: int, start: int, end: int) -> dict:
    return {
        "evidence_id": identifier,
        "kind": "forensic_object_declaration",
        "backend": "raw_forensic",
        "observation_status": "observed",
        "object_number": number,
        "generation": generation,
        "revision": 0,
        "byte_offset_start": start,
        "byte_offset_end": end,
        "filter_chain": None,
        "is_synthetic_repaired": False,
        "details": {
            "source_space": "original",
            "top_level_confirmed": True,
            "object_number": number,
            "generation": generation,
            "byte_start": start,
            "byte_end": end,
        },
    }


def _edge(identifier: str, source: str, target: str, kind: str = "indirect_reference", status: str = "verified") -> dict:
    return {"id": identifier, "source": source, "target": target, "kind": kind, "status": status}


def _bundle(
    records: list[dict],
    edges: list[dict],
    *,
    sha256: str = SAMPLE_SHA256,
    status: str = "bounded_complete",
    extraction_status: str = "bounded_complete",
    worker_status: str = "complete",
    cleanup: bool = True,
    limitations: list[str] | None = None,
) -> dict:
    base = normalize_profile(
        {
            "status": worker_status if worker_status in {"complete", "timeout", "worker_error"} else "complete",
            "errors": list(limitations or []),
            "worker_cleanup_complete": cleanup,
            "worker_exit_code": 0,
            "last_stage": "parse_pdf",
        },
        sha256,
        "deep-static",
        provenance={"private_note": PRIVATE_SENTINEL},
    )
    base["status"] = status
    base["extraction_status"] = extraction_status
    base["coverage_report"]["extraction_status"] = extraction_status
    base["coverage_report"]["limitations"] = list(limitations or [])
    base["coverage_report"]["worker"]["status"] = worker_status
    base["coverage_report"]["worker"]["worker_cleanup_complete"] = cleanup
    base["evidence_store"]["records"] = list(records)
    base["evidence_store"]["edges"] = list(edges)
    return base


def _write_json(path: Path, value: object, jobs) -> str:
    payload = jobs.encoded(value) + b"\n"
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def test_v2_priority_selection_prevents_inline_pdf_object_saturation_and_retains_security_nodes():
    gp2 = importlib.import_module("malpdf.extraction.graph_projection_v2")
    records = [
        _node("cat", "catalog", number=1, generation=0, offset_start=16),
        _node("pages", "pages", number=2, generation=0, offset_start=80),
        _node("page_1", "page", number=3, generation=0, offset_start=160),
        *[_node(f"inline_scalar_{i}", "pdf_object", value_type="int") for i in range(250)],
        _node("ind_font", "pdf_object", number=4, generation=0, offset_start=260),
        _node("annot_1", "annotation", number=5, generation=0, offset_start=340),
        _node("act_js", "action", number=6, generation=0, offset_start=420),
        _node("scr_js", "script"),
        _node("fspec_1", "filespec", number=7, generation=0, offset_start=500),
        _node("stm_1", "stream", number=8, generation=0, offset_start=580, raw_bytes=128),
        _forensic_decl("decl_1", 1, 0, 16, 76),
        _forensic_decl("decl_8", 8, 0, 580, 760),
    ]
    edges = [
        _edge("e1", "cat", "pages"),
        _edge("e2", "pages", "page_1"),
        _edge("e3", "cat", "act_js"),
        _edge("e4", "act_js", "scr_js", kind="action_JS"),
        _edge("e5", "page_1", "stm_1"),
    ]
    projected = gp2.project_graph_bundle_v2(_bundle(records, edges), SAMPLE_SHA256)
    gp2.validate_graph_projection_v2(projected, SAMPLE_SHA256)

    assert PRIVATE_SENTINEL not in json.dumps(projected)
    g = projected["graph"]
    assert g["excluded_inline_pdf_objects"] == 250
    assert g["dropped_nodes_cap"] == 0
    assert g["security_sensitive_dropped_cap"] == 0
    assert g["num_nodes"] == 9
    assert g["node_types"] == [0, 1, 2, 8, 4, 3, 5, 7, 6]


def test_v2_container_transparent_edge_contraction_reconnects_pages_streams_and_actions():
    gp2 = importlib.import_module("malpdf.extraction.graph_projection_v2")
    records = [
        _node("cat", "catalog", number=1, generation=0, offset_start=10),
        _node("pages", "pages", number=2, generation=0, offset_start=50),
        _node("kids_arr", "array"),
        _node("page_1", "page", number=3, generation=0, offset_start=90),
        _node("res_dict", "pdf_object"),
        _node("xobj_dict", "pdf_object"),
        _node("stm_img", "stream", number=4, generation=0, offset_start=150, raw_bytes=512),
        _node("acroform", "form"),
        _node("fields_arr", "array"),
        _node("field_0", "field"),
        _node("act_open", "action"),
        _node("scr_0", "script"),
        _node("unres_stream", "stream", number=9, generation=0, raw_bytes=64),
    ]
    edges = [
        _edge("e_cat_pages", "cat", "pages"),
        _edge("e_pages_kids", "pages", "kids_arr", kind="contains"),
        _edge("e_kids_page", "kids_arr", "page_1"),
        _edge("e_page_res", "page_1", "res_dict", kind="contains"),
        _edge("e_res_xobj", "res_dict", "xobj_dict", kind="contains"),
        _edge("e_xobj_stm", "xobj_dict", "stm_img"),
        _edge("e_cat_form", "cat", "acroform", kind="document_acroform"),
        _edge("e_form_fields", "acroform", "fields_arr", kind="contains"),
        _edge("e_fields_f0", "fields_arr", "field_0"),
        _edge("e_f0_act", "field_0", "act_open", kind="field_action"),
        _edge("e_act_scr", "act_open", "scr_0", kind="action_JS"),
        _edge("e_bad_unres", "xobj_dict", "unres_stream", status="unresolved"),
    ]
    projected = gp2.project_graph_bundle_v2(_bundle(records, edges), SAMPLE_SHA256)
    g = projected["graph"]
    assert g["node_types"] == [0, 1, 2, 6, 3, 5, 6]
    pairs = list(zip(g["edge_src"], g["edge_dst"], g["edge_rel"]))
    assert (0, 1, 0) in pairs
    assert (1, 2, 1) in pairs
    assert (2, 3, 6) in pairs
    assert (0, 4, 2) in pairs
    assert (4, 5, 4) in pairs
    assert (1, 3, 7) not in pairs
    assert all(dst != 6 for _, dst, _ in pairs)
    assert g["direct_kept_edges"] == 2
    assert g["contracted_container_edges"] == 3
    feats = g["node_features"]
    assert feats[2][6] == 0.0
    assert feats[3][6] == 0.0
    assert feats[6][6] == 1.0


def test_v2_provenance_sizes_preserve_null_in_json_and_injective_masks_in_23d_features():
    gp2 = importlib.import_module("malpdf.extraction.graph_projection_v2")
    graph_contract = importlib.import_module("malpdf.data.graph_contract")

    records = [
        _node("cat", "catalog", number=1, generation=0, offset_start=20),
        _node("empty_stm", "stream", number=2, generation=0, offset_start=100, raw_bytes=0),
        _node("mupdf_page", "page", backend="MuPDF", number=3, generation=0, repaired=True),
        _forensic_decl("decl_cat", 1, 0, 20, 95),
    ]
    edges = [_edge("e1", "cat", "empty_stm"), _edge("e2", "cat", "mupdf_page")]
    projected = gp2.project_graph_bundle_v2(_bundle(records, edges), SAMPLE_SHA256)
    g = projected["graph"]

    assert g["verified_physical_span_bytes"] == [75, None, None]
    assert g["verified_physical_span_reasons"] == [
        "measured",
        "no_matching_confirmed_original_declaration",
        "synthetic_repaired_backend",
    ]
    assert g["stream_raw_payload_bytes"] == [None, 0, None]
    assert g["node_feature_dim"] == 23

    nf = g["node_features"]
    assert math.isclose(nf[0][0], math.log1p(75), rel_tol=1e-5)
    assert nf[0][1] == 1.0
    assert nf[0][2:4] == [0.0, 0.0]

    assert nf[1][0:2] == [0.0, 0.0]
    assert nf[1][2:4] == [0.0, 1.0]
    assert nf[0][2:4] != nf[1][2:4]

    assert nf[2][4] == 1.0
    assert nf[2][5] == 1.0

    measured_record = gp2.to_measured_graph_record_v2(projected)
    indexed = graph_contract.index_measured_graphs_v2([measured_record], {SAMPLE_SHA256})
    assert SAMPLE_SHA256 in indexed


def test_v2_measured_graph_runs_pdf_transgraph_23d_forward():
    torch = pytest.importorskip("torch")
    from malpdf.models.pdf_transgraph import PDFTransGraph

    gp2 = importlib.import_module("malpdf.extraction.graph_projection_v2")
    records = [
        _node("cat", "catalog", number=1, generation=0, offset_start=20),
        _node("empty_stm", "stream", number=2, generation=0, offset_start=100, raw_bytes=0),
        _node("mupdf_page", "page", backend="MuPDF", number=3, generation=0, repaired=True),
        _forensic_decl("decl_cat", 1, 0, 20, 95),
    ]
    edges = [_edge("e1", "cat", "empty_stm"), _edge("e2", "cat", "mupdf_page")]
    projected = gp2.project_graph_bundle_v2(_bundle(records, edges), SAMPLE_SHA256)
    measured_record = gp2.to_measured_graph_record_v2(projected)

    model = PDFTransGraph(node_in_dim=23, num_node_types=9, num_relations=8, tabular_in_features=8, hidden_dim=32)
    model.eval()
    with torch.no_grad():
        logits, attn = model(
            torch.tensor(measured_record["node_features"], dtype=torch.float32),
            torch.tensor(measured_record["node_types"], dtype=torch.long),
            torch.tensor([measured_record["edge_src"], measured_record["edge_dst"]], dtype=torch.long),
            torch.tensor(measured_record["edge_rel"], dtype=torch.long),
            torch.zeros((measured_record["num_nodes"],), dtype=torch.long),
            torch.zeros((1, 32), dtype=torch.long),
            torch.zeros((1, 8), dtype=torch.float32),
        )
    assert logits.shape == (1,) and torch.isfinite(logits).all()
    assert torch.isfinite(attn).all()


def test_quality_gate_v2_reaches_ready_for_locked_export_and_export_tool_gates_fail_closed(tmp_path, monkeypatch):
    gate_tool = _load_script("scripts/lab/evaluate_extraction_quality_gate.py", "gate_tool_v2_test", monkeypatch)
    export_tool = _load_script("scripts/lab/export_graphs_v2.py", "export_tool_v2_test", monkeypatch)
    jobs = importlib.import_module("lab_jobs")

    base_job = jobs.make_job("a" * 40, "b" * 64, "c" * 64, mode="offline", kind="pdf-static-cve", attempt="5" * 32)
    job_root = tmp_path / "jobs"
    base_dir = job_root / base_job["job_id"]
    (base_dir / "private_bundles").mkdir(parents=True)

    rows = [
        {"pdf_sha256": "1" * 64, "split": "train", "Label": "1"},
        {"pdf_sha256": "2" * 64, "split": "validation", "Label": "0"},
        {"pdf_sha256": "3" * 64, "split": "train", "Label": "0"},
        {"pdf_sha256": "4" * 64, "split": "test", "Label": "1"},
        {"pdf_sha256": "5" * 64, "split": "train", "Label": "0"},
    ]
    _write_json(base_dir / "job.json", base_job, jobs)
    _write_json(
        base_dir / "selection.json",
        {"job_id": base_job["job_id"], "rows": rows, "selection_sha256": jobs.sha(jobs.encoded(rows))},
        jobs,
    )
    summary = {
        "planned": 5, "completed": 5, "observed": 2, "bounded_complete": 0, "partial": 2, "failed": 1,
        "primary_available": 2, "timeout": 1, "elapsed_ms": 100, "peak_rss_bytes": 1024,
        "status_counts": {"observed": 2, "partial": 2, "timeout": 1},
    }
    env = {"mode": "offline", "guest_network_checked": True, "stdlib_dependencies_checked": True, "hypervisor_controls_attested": True}
    _write_json(base_dir / "result.json", jobs.result(base_job, "partial", summary=summary, environment=env), jobs)

    b0 = _bundle(
        [
            _node("cat_0", "catalog", number=1, generation=0, offset_start=12),
            *[_node(f"in_{i}", "pdf_object") for i in range(210)],
            _node("late_act", "action", number=2, generation=0, offset_start=120),
            _node("late_stm", "stream", number=3, generation=0, offset_start=200, raw_bytes=256),
            _forensic_decl("d0_1", 1, 0, 12, 92),
        ],
        [_edge("e0_1", "cat_0", "late_act"), _edge("e0_2", "cat_0", "late_stm")],
        sha256=rows[0]["pdf_sha256"],
    )
    b1 = _bundle(
        [_node("cat_1", "catalog", number=1, generation=0, offset_start=16), _forensic_decl("d1_1", 1, 0, 16, 80)],
        [],
        sha256=rows[1]["pdf_sha256"],
    )
    b2 = _bundle(
        [{
            "evidence_id": "po_filter", "kind": "parser_object", "backend": "MuPDF", "observation_status": "observed",
            "object_number": 1, "generation": 0, "revision": None, "byte_offset_start": None, "byte_offset_end": None,
            "filter_chain": None, "is_synthetic_repaired": True, "details": {"projection": {"type": "dict"}},
        }],
        [],
        sha256=rows[2]["pdf_sha256"],
        status="partial",
    )
    b3 = _bundle([], [], sha256=rows[3]["pdf_sha256"], status="partial", extraction_status="failed", worker_status="worker_error", limitations=["worker_admission_failed"])
    b4 = _bundle([], [], sha256=rows[4]["pdf_sha256"], status="timeout", extraction_status="timeout_partial", worker_status="timeout", limitations=["wall_timeout"])

    expected = []
    for idx, (row, b_obj) in enumerate(zip(rows, (b0, b1, b2, b3, b4))):
        digest = _write_json(base_dir / "private_bundles" / f"{idx:04d}.json", b_obj, jobs)
        expected.append({
            "index": idx, "sha256": row["pdf_sha256"], "split": row["split"],
            "label": int(row["Label"]), "source_bundle_sha256": digest, "availability": "present",
        })
    expected_path = tmp_path / "expected_index.json"
    _write_json(expected_path, expected, jobs)

    orig_policy = jobs.policy
    monkeypatch.setattr(jobs, "policy", lambda k: {**orig_policy("pdf-static-cic-full"), "samples": 2} if k == "pdf-diagnostic-replay" else orig_policy(k))
    replay_job = jobs.make_job("d" * 40, "e" * 64, "f" * 64, mode="offline", kind="pdf-diagnostic-replay", attempt="6" * 32)
    replay_dir = job_root / replay_job["job_id"]
    (replay_dir / "private_bundles").mkdir(parents=True)
    _write_json(replay_dir / "job.json", replay_job, jobs)
    r_summary = {
        "planned": 2, "completed": 2, "observed": 1, "bounded_complete": 1, "partial": 0, "failed": 1,
        "primary_available": 2, "timeout": 1, "elapsed_ms": 50, "peak_rss_bytes": 512,
        "status_counts": {"bounded_complete": 1, "timeout": 1},
    }
    _write_json(replay_dir / "result.json", jobs.result(replay_job, "partial", summary=r_summary, environment=env), jobs)

    rb0 = _bundle(
        [_node("cat_restored", "catalog", number=1, generation=0, offset_start=24), _forensic_decl("dr0", 1, 0, 24, 104)],
        [],
        sha256=rows[3]["pdf_sha256"],
    )
    rb1 = _bundle([], [], sha256=rows[4]["pdf_sha256"], status="timeout", extraction_status="timeout_partial", worker_status="timeout", limitations=["wall_timeout"])
    _write_json(replay_dir / "private_bundles/0000.json", rb0, jobs)
    _write_json(replay_dir / "private_bundles/0001.json", rb1, jobs)
    _write_json(
        replay_dir / "locked_methodology.json",
        {
            "schema_version": 1, "stage": "BUG-007B1", "job_id": replay_job["job_id"], "baseline_job_id": base_job["job_id"],
            "records": [
                {"baseline_index": 3, "sha256": rows[3]["pdf_sha256"], "split": rows[3]["split"], "label": int(rows[3]["Label"])},
                {"baseline_index": 4, "sha256": rows[4]["pdf_sha256"], "split": rows[4]["split"], "label": int(rows[4]["Label"])},
            ],
        },
        jobs,
    )

    gate_receipt = gate_tool.evaluate_quality_gate_job(
        base_job["job_id"],
        expected_path,
        replay_job_id=replay_job["job_id"],
        projection_version="v2",
        job_root=job_root,
        output_root=tmp_path / "gate_v2_runs",
    )
    assert gate_receipt["baseline_verdict"] == "blocked_unresolved_extraction_failures"
    assert gate_receipt["virtual_post_b1_verdict"] == "ready_for_locked_export"

    with pytest.raises(ValueError, match="quality_gate_not_ready_for_export"):
        export_tool.export_graphs_v2_job(
            base_job["job_id"],
            expected_path,
            job_root=job_root,
            output_root=tmp_path / "blocked_export",
        )

    export_receipt = export_tool.export_graphs_v2_job(
        base_job["job_id"],
        expected_path,
        replay_job_id=replay_job["job_id"],
        allow_virtual_overlay=True,
        job_root=job_root,
        output_root=tmp_path / "ok_export",
    )
    exp_dir = Path(export_receipt["output"])
    assert export_receipt["cohort_gate_verdict"] == "ready_for_locked_export"
    assert export_receipt["gnn_exported_graphs"] == 3
    assert export_receipt["unavailable_empty_graphs"] == 2
    assert export_receipt["export_scope"] == "virtual_post_b1_dry_run"

    with gzip.open(exp_dir / "hetero_graphs_v2.jsonl.gz", "rt", encoding="utf-8") as gs:
        exported_graphs = [json.loads(line) for line in gs if line.strip()]
    assert len(exported_graphs) == 3
    assert all(len(g["node_features"][0]) == 23 for g in exported_graphs)

    for item in exp_dir.iterdir():
        raw_txt = gzip.decompress(item.read_bytes()).decode("utf-8") if item.name.endswith(".gz") else item.read_text(encoding="utf-8")
        assert PRIVATE_SENTINEL not in raw_txt
        assert str(job_root) not in raw_txt


def test_lab_runner_prespawn_memory_headroom_and_bounded_retry_without_false_cleanup_halt(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts/lab"))
    jobs = importlib.import_module("lab_jobs")
    runner = importlib.import_module("lab_runner")

    job = jobs.make_job("a" * 40, "b" * 64, "c" * 64, mode="offline", kind="pdf-static-cve", attempt="7" * 32)
    monkeypatch.setattr(jobs, "JOBS", tmp_path / "jobs")
    directory = jobs.save_job(job)
    root = tmp_path / "reviewed_metadata"
    (root / "configs").mkdir(parents=True)
    (root / "configs" / "arlington.lock.json").write_text("{}", encoding="utf-8")
    rows = [{"pdf_relative_path": f"sample-{i}.pdf", "pdf_sha256": f"{i + 1:064x}"} for i in range(5)]
    jobs.immutable(directory / "selection.json", {"job_id": job["job_id"], "rows": rows, "selection_sha256": jobs.sha(jobs.encoded(rows))})
    jobs.immutable(directory / "claim.json", {"job_id": job["job_id"], "parent_pid": os.getppid(), "hypervisor_controls_attested": True})

    mem_samples = iter([500 * 1024**2, 1100 * 1024**2, 1200 * 1024**2, 1200 * 1024**2, 1200 * 1024**2, 1200 * 1024**2, 1200 * 1024**2])
    sleeps = []
    monkeypatch.setattr(runner, "_available_memory_bytes", lambda: next(mem_samples, 1500 * 1024**2))
    monkeypatch.setattr(runner.time, "sleep", lambda sec: sleeps.append(sec))

    attempts_by_sha = {}

    def fake_extract(path: Path, **kwargs) -> dict:
        sha = kwargs["expected_sha256"]
        attempts_by_sha[sha] = attempts_by_sha.get(sha, 0) + 1
        if sha == rows[0]["pdf_sha256"] and attempts_by_sha[sha] == 1:
            b_fail = normalize_profile(
                {
                    "status": "worker_error",
                    "errors": ["worker_admission_failed"],
                    "worker_cleanup_complete": None,
                    "diagnostic": {
                        "last_phase": "worker_start",
                        "worker_exit_code": None,
                        "cleanup_exit_code": None,
                        "cleanup_complete": None,
                    },
                },
                sha,
                "deep-static",
            )
            return validate_bundle(b_fail)
        b_ok = normalize_profile({"status": "complete", "errors": [], "worker_cleanup_complete": True}, sha, "deep-static")
        return validate_bundle(b_ok)

    replacements = {
        "malpdf.extraction.orchestrator": SimpleNamespace(extract_pdf=fake_extract),
        "malpdf.extraction.arlington_model": SimpleNamespace(load_model=lambda path: None),
        "malpdf.extraction.jobs": SimpleNamespace(require_extraction_lab=lambda *args, **kwargs: None),
        "malpdf.static.code_inspector": SimpleNamespace(CodeInspectionLimits=lambda **kwargs: kwargs, _worker_count=lambda *args: None),
    }
    for name, replacement in replacements.items():
        monkeypatch.setitem(sys.modules, name, replacement)
    monkeypatch.setattr(runner, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(jobs, "preflight", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner, "worker_limits", lambda **kwargs: None)
    monkeypatch.setattr(runner, "pdf_metadata", lambda _job: (root, root, rows))

    runner.pdf_worker(job["job_id"], shard=0, count=1)
    assert attempts_by_sha[rows[0]["pdf_sha256"]] == 2
    assert any(s == 0.25 for s in sleeps)
    assert any(s == 1.0 for s in sleeps)
    assert not list(directory.glob("pdf_halt.*.json"))
    saved_0 = json.loads((directory / "private_bundles/0000.json").read_bytes())
    assert saved_0["coverage_report"]["worker"]["worker_cleanup_complete"] is True
    summary = json.loads((directory / "pdf_summary.0.json").read_bytes())
    assert summary["completed"] == 5

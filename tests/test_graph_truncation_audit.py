from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from malpdf.extraction.normalize import normalize_profile


SAMPLE_SHA256 = "a" * 64
PRIVATE_SENTINEL = "PRIVATE_DOCUMENT_TEXT_NEVER_EXPORT_B2"


@pytest.fixture
def trunc():
    return importlib.import_module("malpdf.extraction.graph_truncation_audit")


@pytest.fixture
def job_tool(monkeypatch):
    path = Path(__file__).resolve().parents[1] / "scripts/lab/audit_graph_truncation.py"
    monkeypatch.syspath_prepend(str(path.parent))
    spec = importlib.util.spec_from_file_location("audit_graph_truncation_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "sys", SimpleNamespace(**{**vars(module.sys), "platform": "linux"}))
    return module


def _node(
    identifier,
    kind="pdf_object",
    status="observed",
    *,
    backend="pypdf",
    number=None,
    generation=None,
    offset_start=None,
    offset_end=None,
    repaired=False,
    details=None,
):
    return {
        "evidence_id": identifier,
        "kind": kind,
        "backend": backend,
        "observation_status": status,
        "object_number": number,
        "generation": generation,
        "revision": None,
        "byte_offset_start": offset_start,
        "byte_offset_end": offset_end,
        "filter_chain": None,
        "is_synthetic_repaired": repaired,
        "details": {"secret": PRIVATE_SENTINEL, **(details or {})},
    }


def _forensic_decl(identifier, number, generation, start, end, *, space="original", confirmed=True, status="observed"):
    return {
        "evidence_id": identifier,
        "kind": "forensic_object_declaration",
        "backend": "raw_forensic",
        "observation_status": status,
        "object_number": number,
        "generation": generation,
        "revision": None,
        "byte_offset_start": start,
        "byte_offset_end": end,
        "filter_chain": None,
        "is_synthetic_repaired": False,
        "details": {
            "byte_start": start,
            "byte_end": end,
            "object_number": number,
            "generation": generation,
            "source_space": space,
            "top_level_confirmed": confirmed,
            "secret": PRIVATE_SENTINEL,
        },
    }


def _edge(identifier, source, target, kind="indirect_reference"):
    return {"id": identifier, "source": source, "target": target, "kind": kind, "status": "verified"}


def _bundle(records, edges, *, status="bounded_complete", extraction_status="bounded_complete", worker_status="complete"):
    return {
        "schema_version": "pdf-extraction-bundle-v1",
        "sample_sha256": SAMPLE_SHA256,
        "extraction_profile": "deep-static",
        "status": status,
        "extraction_status": extraction_status,
        "evidence_store": {"records": records, "edges": edges},
        "feature_store": {"records": []},
        "coverage_report": {
            "whole_document_complete": False,
            "extraction_status": extraction_status,
            "limitations": [],
            "backends": {},
            "groups": {},
            "worker": {
                "status": worker_status,
                "worker_cleanup_complete": True,
                "worker_exit_code": 0,
                "last_stage": "parse_pdf",
            },
            "provenance": {"private_note": PRIVATE_SENTINEL},
        },
    }


def _write_json(path, value, jobs):
    payload = jobs.encoded(value) + b"\n"
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def test_truncation_audit_separates_kind_status_and_cap_for_nodes_and_edges(trunc):
    nodes = [
        _node("cat", "catalog", number=1, generation=0, offset_start=10),
        _node("p1", "page", number=2, generation=0, offset_start=50),
        _node("arr", "array"),
        _node("bad_page", "page", status="unsupported", number=3, generation=0),
        _node("act", "action", number=4, generation=0, offset_start=120),
        _node("scr", "script"),
    ]
    edges = [
        _edge("e_cat_p1", "cat", "p1"),
        _edge("e_cat_arr", "cat", "arr"),
        _edge("e_arr_bad", "arr", "bad_page"),
        _edge("e_p1_act", "p1", "act"),
        _edge("e_act_scr", "act", "scr"),
    ]
    src = _bundle(nodes, edges)
    snap = deepcopy(src)
    res = trunc.audit_truncation_bundle(src, SAMPLE_SHA256, node_cap=2)
    assert src == snap
    assert PRIVATE_SENTINEL not in json.dumps(res)
    na = res["node_accounting"]
    assert na["evidence_nodes"] == 6
    assert na["excluded_nodes_kind"] == 1
    assert na["excluded_nodes_status"] == 1
    assert na["eligible_nodes_before_cap"] == 4
    assert na["kept_nodes_after_cap"] == 2
    assert na["dropped_nodes_cap"] == 2
    assert na["is_capped"] is True
    assert na["node_drop_ratio"] == pytest.approx(0.5)
    assert na["by_kind"]["action"] == {"eligible": 1, "kept": 0, "dropped_cap": 1}
    assert na["by_kind"]["script"] == {"eligible": 1, "kept": 0, "dropped_cap": 1}
    assert na["security_sensitive_dropped_cap"] == 2

    ea = res["edge_accounting"]
    assert ea["evidence_edges"] == 5
    assert ea["excluded_edges_non_eligible_endpoint"] == 2
    assert ea["eligible_edges_before_cap"] == 3
    assert ea["kept_edges_after_cap"] == 1
    assert ea["dropped_edges_cap"] == 2
    assert ea["dropped_edges_one_endpoint_capped"] == 1
    assert ea["dropped_edges_both_endpoints_capped"] == 1
    assert ea["edge_drop_ratio"] == pytest.approx(2.0 / 3.0)


def test_structural_distortion_separates_kept_fragmentation_from_dropped_components(trunc):
    nodes = [
        _node("cat", "catalog", number=1, generation=0, offset_start=10),
        _node("leaf_via_late_bridge", "stream", number=2, generation=0, offset_start=40, details={"raw_bytes": 512}),
        _node("late_bridge", "action", number=3, generation=0, offset_start=90),
        _node("extra_island_a", "pdf_object"),
        _node("extra_island_b", "pdf_object"),
    ]
    edges = [
        _edge("e1", "cat", "late_bridge"),
        _edge("e2", "late_bridge", "leaf_via_late_bridge"),
    ]
    res = trunc.audit_truncation_bundle(_bundle(nodes, edges), SAMPLE_SHA256, node_cap=2)
    st = res["structural_impact"]
    assert st["isolates_before_cap"] == 2
    assert st["isolates_after_cap"] == 2
    assert st["newly_isolated_kept_nodes"] == 2
    assert st["orphans_before_cap"] == 2
    assert st["orphans_after_cap"] == 1
    assert st["newly_orphaned_kept_nodes"] == 1
    assert st["wcc_before_cap"] == 3
    assert st["wcc_after_cap"] == 2
    assert st["wcc_delta"] == -1
    assert st["kept_precap_wcc_count"] == 1
    assert st["kept_fragmentation_wcc_gain"] == 1
    assert st["catalog_reachable_before_cap"] == 3
    assert st["catalog_reachable_after_cap"] == 1
    assert st["kept_disconnected_from_catalog_by_cap"] == 1


def test_node_size_provenance_keeps_four_definitions_distinct_and_null_when_unverified(trunc):
    nodes = [
        _node("cat_verified", "catalog", backend="pypdf", number=1, generation=0, offset_start=100),
        _node("inline_dict", "pdf_object", backend="pypdf", number=None, generation=None, offset_start=None),
        _node("mupdf_repaired", "page", backend="MuPDF", number=2, generation=0, offset_start=200, repaired=True),
        _node("mupdf_direct", "pdf_object", backend="MuPDF", number=None, generation=None, repaired=True),
        _node("number_only_no_offset", "page", backend="pypdf", number=3, generation=0, offset_start=None),
        _node("objstm_member", "pdf_object", backend="pypdf", number=4, generation=0, offset_start=400),
        _node("stream_obj", "stream", backend="pypdf", number=5, generation=0, offset_start=500, details={"raw_bytes": 128}),
        _node("ambig_obj", "page", backend="pypdf", number=6, generation=0, offset_start=600),
        _node("script_node", "script", backend="pypdf", number=None, generation=None),
        _forensic_decl("decl1", 1, 0, 100, 180),
        _forensic_decl("decl2", 2, 0, 200, 290),
        _forensic_decl("decl3", 3, 0, 300, 390),
        _forensic_decl("decl4_objstm", 4, 0, 400, 460, space="decoded_stream"),
        _forensic_decl("decl5", 5, 0, 500, 700),
        _forensic_decl("decl6a", 6, 0, 600, 650),
        _forensic_decl("decl6b", 6, 0, 600, 680),
    ]
    res = trunc.audit_truncation_bundle(_bundle(nodes, []), SAMPLE_SHA256, node_cap=200)
    origins = res["node_accounting"]["by_origin"]
    assert origins["indirect_pypdf"]["kept"] == 5
    assert origins["direct_pypdf"]["kept"] == 2
    assert origins["indirect_mupdf"]["kept"] == 1
    assert origins["direct_mupdf"]["kept"] == 1

    sp = res["size_provenance"]
    assert sp["legacy_semantic_size_bytes"]["known_count"] == 0
    assert sp["legacy_semantic_size_bytes"]["null_count"] == 9
    assert sp["verified_physical_declaration_span_bytes"]["known_count"] == 2
    assert sp["verified_physical_declaration_span_bytes"]["null_count"] == 7
    assert sp["verified_physical_declaration_span_bytes"]["total"] == 280
    reasons = sp["verified_physical_declaration_span_reasons"]
    assert reasons["measured"] == 2
    assert reasons["direct_inline_object"] == 1
    assert reasons["synthetic_repaired_backend"] == 2
    assert reasons["missing_verified_header_offset"] == 1
    assert reasons["no_matching_confirmed_original_declaration"] == 1
    assert reasons["ambiguous_declaration_match"] == 1
    assert reasons["script_derived_node"] == 1
    assert sp["stream_raw_payload_bytes"]["known_count"] == 1
    assert sp["stream_raw_payload_bytes"]["null_count"] == 8
    assert sp["stream_raw_payload_bytes"]["total"] == 128
    assert sp["projected_json_storage_bytes"]["is_model_feature_producer"] is False
    assert sp["projected_json_storage_bytes"]["known_count"] == 9


def test_edge_cap_is_counted_separately_from_node_cap_drops(trunc, monkeypatch):
    monkeypatch.setattr(trunc, "MAX_EDGES", 2)
    nodes = [_node("n0", "catalog"), _node("n1", "page"), _node("n2", "action")]
    edges = [
        _edge("e0", "n0", "n1"),
        _edge("e1", "n1", "n0"),
        _edge("e2", "n0", "n0"),
        _edge("e3", "n1", "n2"),
    ]
    res = trunc.audit_truncation_bundle(_bundle(nodes, edges), SAMPLE_SHA256, node_cap=2)
    ea = res["edge_accounting"]
    assert ea["eligible_edges_before_cap"] == 4
    assert ea["kept_edges_after_cap"] == 2
    assert ea["excluded_edges_edge_cap"] == 1
    assert ea["dropped_edges_cap"] == 1


def test_empty_projection_keeps_null_ratios_and_separates_projection_filter_from_failures(trunc):
    parser_obj = {
        "evidence_id": "po1",
        "kind": "parser_object",
        "backend": "MuPDF",
        "observation_status": "observed",
        "object_number": 1,
        "generation": 0,
        "revision": None,
        "byte_offset_start": None,
        "byte_offset_end": None,
        "filter_chain": None,
        "is_synthetic_repaired": True,
        "details": {"projection": {"type": "dict"}},
    }
    res = trunc.audit_truncation_bundle(_bundle([parser_obj], [], status="partial", extraction_status="bounded_complete"), SAMPLE_SHA256)
    assert res["node_accounting"]["eligible_nodes_before_cap"] == 0
    assert res["node_accounting"]["node_drop_ratio"] is None
    assert res["edge_accounting"]["edge_drop_ratio"] is None
    assert res["quality_gate_view"]["graph_state"] == "empty_projection_filtered"


def _make_baseline_cve_job(tmp_path):
    jobs = importlib.import_module("lab_jobs")
    base_job = jobs.make_job("a" * 40, "b" * 64, "c" * 64, mode="offline", kind="pdf-static-cve", attempt="1" * 32)
    job_root = tmp_path / "jobs"
    base_dir = job_root / base_job["job_id"]
    (base_dir / "private_bundles").mkdir(parents=True)

    rows = [
        {"pdf_sha256": "1" * 64, "split": "train", "Label": "1"},
        {"pdf_sha256": "2" * 64, "split": "validation", "Label": "0"},
        {"pdf_sha256": "3" * 64, "split": "validation", "Label": "0"},
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
        "planned": 5,
        "completed": 5,
        "observed": 2,
        "bounded_complete": 0,
        "partial": 2,
        "failed": 1,
        "primary_available": 2,
        "timeout": 1,
        "elapsed_ms": 100,
        "peak_rss_bytes": 1024,
        "status_counts": {"observed": 2, "partial": 2, "timeout": 1},
    }
    env = {"mode": "offline", "guest_network_checked": True, "stdlib_dependencies_checked": True, "hypervisor_controls_attested": True}
    _write_json(base_dir / "result.json", jobs.result(base_job, "partial", summary=summary, environment=env), jobs)

    b0 = normalize_profile({"status": "complete", "errors": [], "worker_cleanup_complete": True}, rows[0]["pdf_sha256"], "deep-static")
    b0["evidence_store"]["records"].extend(_node(f"n_{i}", "pdf_object") for i in range(205))

    b1 = normalize_profile({"status": "complete", "errors": [], "worker_cleanup_complete": True}, rows[1]["pdf_sha256"], "deep-static")
    b1["evidence_store"]["records"].append(_node("cat_1", "catalog", number=1, generation=0, offset_start=12))

    b2 = normalize_profile({"status": "partial", "errors": [], "worker_cleanup_complete": True}, rows[2]["pdf_sha256"], "deep-static")
    b2["evidence_store"]["records"].append({
        "evidence_id": "po_filter",
        "kind": "parser_object",
        "backend": "MuPDF",
        "observation_status": "observed",
        "object_number": 1,
        "generation": 0,
        "revision": None,
        "byte_offset_start": None,
        "byte_offset_end": None,
        "filter_chain": None,
        "is_synthetic_repaired": True,
        "details": {"projection": {"type": "dict"}},
    })

    b3 = normalize_profile({"status": "worker_error", "errors": ["worker_admission_failed"], "worker_cleanup_complete": True}, rows[3]["pdf_sha256"], "deep-static")
    b4 = normalize_profile({"status": "timeout", "errors": ["wall_timeout"], "worker_cleanup_complete": True}, rows[4]["pdf_sha256"], "deep-static")

    expected = []
    for idx, (row, bundle) in enumerate(zip(rows, (b0, b1, b2, b3, b4))):
        bundle["coverage_report"]["provenance"]["secret"] = PRIVATE_SENTINEL
        digest = _write_json(base_dir / "private_bundles" / f"{idx:04d}.json", bundle, jobs)
        expected.append({
            "index": idx,
            "sha256": row["pdf_sha256"],
            "split": row["split"],
            "label": int(row["Label"]),
            "source_bundle_sha256": digest,
            "availability": "present",
        })
    expected_path = tmp_path / "expected_index.json"
    _write_json(expected_path, expected, jobs)
    return jobs, base_job, job_root, base_dir, expected_path, rows


def test_truncation_audit_job_stratifies_by_split_and_label_with_virtual_replay_overlay(job_tool, tmp_path, monkeypatch):
    jobs, base_job, job_root, base_dir, expected_path, rows = _make_baseline_cve_job(tmp_path)
    orig_policy = jobs.policy

    def custom_policy(kind):
        if kind == "pdf-diagnostic-replay":
            return {**orig_policy("pdf-static-cic-full"), "samples": 2}
        return orig_policy(kind)

    monkeypatch.setattr(jobs, "policy", custom_policy)
    replay_job = jobs.make_job("d" * 40, "e" * 64, "f" * 64, mode="offline", kind="pdf-diagnostic-replay", attempt="2" * 32)
    replay_dir = job_root / replay_job["job_id"]
    (replay_dir / "private_bundles").mkdir(parents=True)
    _write_json(replay_dir / "job.json", replay_job, jobs)
    r_summary = {
        "planned": 2,
        "completed": 2,
        "observed": 1,
        "bounded_complete": 1,
        "partial": 0,
        "failed": 1,
        "primary_available": 2,
        "timeout": 1,
        "elapsed_ms": 50,
        "peak_rss_bytes": 512,
        "status_counts": {"bounded_complete": 1, "timeout": 1},
    }
    env = {"mode": "offline", "guest_network_checked": True, "stdlib_dependencies_checked": True, "hypervisor_controls_attested": True}
    _write_json(replay_dir / "result.json", jobs.result(replay_job, "partial", summary=r_summary, environment=env), jobs)

    rb0 = normalize_profile({"status": "complete", "errors": [], "worker_cleanup_complete": True}, rows[3]["pdf_sha256"], "deep-static")
    rb0["evidence_store"]["records"].extend(_node(f"rn_{i}", "pdf_object") for i in range(210))
    rb1 = normalize_profile({"status": "timeout", "errors": ["wall_timeout"], "worker_cleanup_complete": True}, rows[4]["pdf_sha256"], "deep-static")
    _write_json(replay_dir / "private_bundles/0000.json", rb0, jobs)
    _write_json(replay_dir / "private_bundles/0001.json", rb1, jobs)
    _write_json(
        replay_dir / "locked_methodology.json",
        {
            "schema_version": 1,
            "stage": "BUG-007B1",
            "job_id": replay_job["job_id"],
            "baseline_job_id": base_job["job_id"],
            "records": [
                {"baseline_index": 3, "sha256": rows[3]["pdf_sha256"], "split": rows[3]["split"], "label": int(rows[3]["Label"])},
                {"baseline_index": 4, "sha256": rows[4]["pdf_sha256"], "split": rows[4]["split"], "label": int(rows[4]["Label"])},
            ],
        },
        jobs,
    )

    before_base = {p.relative_to(base_dir).as_posix(): p.read_bytes() for p in base_dir.rglob("*") if p.is_file()}
    before_replay = {p.relative_to(replay_dir).as_posix(): p.read_bytes() for p in replay_dir.rglob("*") if p.is_file()}

    out_root = tmp_path / "trunc_audits"
    receipt = job_tool.audit_truncation_job(
        base_job["job_id"],
        expected_path,
        replay_job_id=replay_job["job_id"],
        job_root=job_root,
        output_root=out_root,
    )
    out_dir = Path(receipt["output"])
    assert receipt["records"] == 5
    assert receipt["capped_graphs"] == 1
    assert receipt["raw_pdf_processing"] is False
    assert receipt["model_input_ready"] is False
    assert before_base == {p.relative_to(base_dir).as_posix(): p.read_bytes() for p in base_dir.rglob("*") if p.is_file()}
    assert before_replay == {p.relative_to(replay_dir).as_posix(): p.read_bytes() for p in replay_dir.rglob("*") if p.is_file()}

    metrics = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    assert metrics["cohort"]["nonempty_graphs"] == 2
    assert metrics["cohort"]["empty_graphs"] == 3
    assert metrics["capped_cohort"]["count"] == 1
    assert metrics["empty_projection_separation"]["projection_filter_confirmed_indices"] == [2]
    assert metrics["empty_projection_separation"]["other_empty_projection_indices"] == [3, 4]

    overlay = metrics["b1_replay_overlay"]
    assert overlay["virtual_post_b1_cohort"]["nonempty_graphs"] == 3
    assert overlay["virtual_post_b1_cohort"]["capped_graphs"] == 2
    assert overlay["virtual_post_b1_cohort"]["empty_graphs"] == 2
    assert overlay["virtual_post_b1_empty_projection_separation"]["projection_filter_confirmed_indices"] == [2]
    assert overlay["virtual_post_b1_empty_projection_separation"]["other_empty_projection_indices"] == [4]

    manifest = json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))
    for name in ("locked_methodology.json", "cases.jsonl", "replay_overlay_cases.jsonl", "summary.json", "report.md"):
        assert (out_dir / name).is_file()
        assert hashlib.sha256((out_dir / name).read_bytes()).hexdigest() == manifest["files"][name]
        assert PRIVATE_SENTINEL not in (out_dir / name).read_text(encoding="utf-8")


def test_truncation_audit_job_handles_corrupted_or_missing_bundles_and_rejects_output_inside_job_root(job_tool, tmp_path):
    _, base_job, job_root, base_dir, expected_path, _ = _make_baseline_cve_job(tmp_path)
    with pytest.raises(ValueError, match="output_inside_input"):
        job_tool.audit_truncation_job(base_job["job_id"], expected_path, job_root=job_root, output_root=job_root / "sub")

    (base_dir / "private_bundles/0001.json").unlink()
    tampered = json.loads((base_dir / "private_bundles/0003.json").read_text(encoding="utf-8"))
    tampered["status"] = "complete"
    (base_dir / "private_bundles/0003.json").write_text(json.dumps(tampered), encoding="utf-8")

    receipt = job_tool.audit_truncation_job(base_job["job_id"], expected_path, job_root=job_root, output_root=tmp_path / "out")
    out_dir = Path(receipt["output"])
    rows = [json.loads(line) for line in (out_dir / "cases.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 5
    assert [r["availability"] for r in rows] == ["present", "missing", "present", "checksum_mismatch", "present"]
    assert rows[1]["truncation"] is None
    assert rows[3]["truncation"] is None

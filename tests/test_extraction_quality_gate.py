from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from malpdf.extraction.contracts import feature
from malpdf.extraction.normalize import normalize_profile


SAMPLE_SHA256 = "a" * 64
PRIVATE_SENTINEL = "PRIVATE_DOCUMENT_TEXT_NEVER_EXPORT_B3"


@pytest.fixture
def qgate():
    return importlib.import_module("malpdf.extraction.quality_gate")


@pytest.fixture
def gate_tool(monkeypatch):
    path = Path(__file__).resolve().parents[1] / "scripts/lab/evaluate_extraction_quality_gate.py"
    monkeypatch.syspath_prepend(str(path.parent))
    spec = importlib.util.spec_from_file_location("evaluate_extraction_quality_gate_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "sys", SimpleNamespace(**{**vars(module.sys), "platform": "linux"}))
    return module


def _node(identifier, kind="pdf_object", status="observed", *, backend="pypdf", number=None, generation=None, offset_start=None, size_bytes=None, raw_bytes=None):
    details = {"secret": PRIVATE_SENTINEL}
    if size_bytes is not None:
        details["size_bytes"] = size_bytes
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
        "is_synthetic_repaired": False,
        "details": details,
    }


def _edge(identifier, source, target, kind="indirect_reference"):
    return {"id": identifier, "source": source, "target": target, "kind": kind, "status": "verified"}


def _bundle(records, edges, *, sha256=SAMPLE_SHA256, status="bounded_complete", extraction_status="bounded_complete",
            worker_status="complete", cleanup=True, limitations=None, extra_features=None):
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
    if extra_features is not None:
        base["feature_store"]["records"].extend(extra_features)
        base["coverage_report"]["observation_status_counts"] = dict(
            Counter(item["observation_status"] for item in base["feature_store"]["records"])
        )
    return base


def _write_json(path, value, jobs):
    payload = jobs.encoded(value) + b"\n"
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def test_sample_gate_blocks_legacy_19d_when_semantic_size_missing_and_never_leaks_private_text(qgate):
    src = _bundle([_node("cat", "catalog", number=1, generation=0, offset_start=10)], [])
    snap = deepcopy(src)
    missing_size = qgate.evaluate_sample_quality(src, SAMPLE_SHA256)
    assert src == snap
    assert PRIVATE_SENTINEL not in json.dumps(missing_size)
    assert missing_size["sample_disposition"] == "usable_complete_projection"
    assert missing_size["gnn_message_passing_eligible"] is True
    assert missing_size["tabular_features_valid"] is True
    assert missing_size["evaluation_denominator_included"] is True
    assert missing_size["placeholder_nodes_inserted"] is False
    assert missing_size["legacy_19d_ready"] is False
    assert "legacy_semantic_node_size_missing" in missing_size["warnings"]

    with_size = qgate.evaluate_sample_quality(
        _bundle([_node("cat", "catalog", number=1, generation=0, offset_start=10, size_bytes=64)], []),
        SAMPLE_SHA256,
    )
    assert with_size["legacy_19d_ready"] is True
    assert "legacy_semantic_node_size_missing" not in with_size["warnings"]


def test_sample_gate_distinguishes_security_sensitive_cap_loss_from_benign_cap_loss(qgate):
    benign_nodes = [_node("cat", "catalog"), _node("p1", "page"), _node("inline_extra", "pdf_object")]
    benign_res = qgate.evaluate_sample_quality(_bundle(benign_nodes, []), SAMPLE_SHA256, node_cap=2)
    assert benign_res["sample_disposition"] == "usable_degraded_capped_benign_loss"
    assert "capped_non_sensitive_node_loss" in benign_res["warnings"]
    assert "capped_security_sensitive_node_loss" not in benign_res["warnings"]

    sec_nodes = [_node("cat", "catalog"), _node("inline_1", "pdf_object"), _node("late_act", "action")]
    sec_res = qgate.evaluate_sample_quality(_bundle(sec_nodes, []), SAMPLE_SHA256, node_cap=2)
    assert sec_res["sample_disposition"] == "usable_degraded_capped_security_loss"
    assert "capped_security_sensitive_node_loss" in sec_res["warnings"]


def test_unavailable_empty_projections_preserve_denominator_without_placeholder_nodes(qgate):
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
    proj_filtered = qgate.evaluate_sample_quality(
        _bundle([parser_obj], [], status="partial", extraction_status="bounded_complete"),
        SAMPLE_SHA256,
    )
    assert proj_filtered["sample_disposition"] == "unavailable_projection_filtered"
    assert proj_filtered["gnn_message_passing_eligible"] is False
    assert proj_filtered["placeholder_nodes_inserted"] is False
    assert proj_filtered["evaluation_denominator_included"] is True
    assert proj_filtered["evaluation_handling"] == "abstention_or_tabular_only_no_placeholder_graph"

    timeout_empty = qgate.evaluate_sample_quality(
        _bundle([], [], status="timeout", extraction_status="timeout_partial", worker_status="timeout", limitations=["wall_timeout"]),
        SAMPLE_SHA256,
    )
    assert timeout_empty["sample_disposition"] == "unavailable_timeout_no_graph"
    assert timeout_empty["gnn_message_passing_eligible"] is False

    worker_err = qgate.evaluate_sample_quality(
        _bundle([], [], status="partial", extraction_status="failed", worker_status="worker_error", limitations=["worker_admission_failed"]),
        SAMPLE_SHA256,
    )
    assert worker_err["sample_disposition"] == "unavailable_worker_failure"
    assert worker_err["gnn_message_passing_eligible"] is False


def test_sample_gate_rejects_unverified_cleanup_dangling_edges_and_invalid_feature_contracts(qgate):
    uncleaned = qgate.evaluate_sample_quality(
        _bundle([_node("cat", "catalog")], [], cleanup=False),
        SAMPLE_SHA256,
    )
    assert uncleaned["sample_disposition"] == "rejected_unverified_cleanup"
    assert uncleaned["gnn_message_passing_eligible"] is False
    assert uncleaned["tabular_features_valid"] is False
    assert uncleaned["evaluation_handling"] == "fail_closed_abort_evaluation"

    dangling = qgate.evaluate_sample_quality(
        _bundle([_node("cat", "catalog")], [_edge("e_bad", "cat", "nonexistent_target")]),
        SAMPLE_SHA256,
    )
    assert dangling["sample_disposition"] == "rejected_missing_or_corrupt"

    bad_feat_bundle = _bundle([_node("cat", "catalog")], [])
    bad_feat_bundle["feature_store"]["records"][0] = feature(
        "canonical_pdfsize", "raw_layout", 99, "not_run", [], "corrupt_status_value", complete=False
    )
    bad_feat = qgate.evaluate_sample_quality(bad_feat_bundle, SAMPLE_SHA256)
    assert bad_feat["sample_disposition"] == "rejected_missing_or_corrupt"
    assert bad_feat["tabular_features_valid"] is False


def test_cohort_gate_progresses_from_blocked_worker_failures_to_hold_and_to_ready(qgate):
    def make_row(idx, split, label, b_obj):
        sha = f"{idx + 1:064x}"
        b_obj = deepcopy(b_obj)
        b_obj["sample_sha256"] = sha
        for store_name in ("evidence_store", "feature_store", "coverage_report"):
            b_obj[store_name]["sample_sha256"] = sha
        return {
            "index": idx,
            "sha256": sha,
            "split": split,
            "label": label,
            "expected_bundle_sha256": "b" * 64,
            "source_bundle_sha256": "b" * 64,
            "availability": "present",
            "bundle_schema_valid": True,
            "gate": qgate.evaluate_sample_quality(b_obj, sha),
        }

    ok_missing_size = _bundle([_node("cat", "catalog")], [])
    worker_fail = _bundle([], [], status="partial", extraction_status="failed", worker_status="worker_error", limitations=["worker_admission_failed"])
    baseline_rows = [
        make_row(0, "train", 1, ok_missing_size),
        make_row(1, "validation", 0, ok_missing_size),
        make_row(2, "test", 1, worker_fail),
    ]
    s_blocked = qgate.evaluate_cohort_quality_gate(baseline_rows)
    assert s_blocked["cohort_gate_verdict"] == "blocked_unresolved_extraction_failures"
    assert s_blocked["checks"]["unresolved_worker_failures_cleared"]["passed"] is False
    assert s_blocked["legacy_19d_model_input_ready"] is False
    assert s_blocked["training_unlocked"] is False

    post_b1_rows = [
        make_row(0, "train", 1, ok_missing_size),
        make_row(1, "validation", 0, ok_missing_size),
        make_row(2, "test", 1, ok_missing_size),
    ]
    s_hold = qgate.evaluate_cohort_quality_gate(post_b1_rows)
    assert s_hold["cohort_gate_verdict"] == "hold_pending_v2_projection_and_size_contract"
    assert s_hold["checks"]["unresolved_worker_failures_cleared"]["passed"] is True
    assert s_hold["checks"]["evaluation_partition_coverage"]["passed"] is True
    assert s_hold["checks"]["legacy_19d_semantic_size_populated"]["passed"] is False
    assert s_hold["legacy_19d_model_input_ready"] is False
    assert s_hold["training_unlocked"] is False

    ok_with_size = _bundle([_node("cat", "catalog", size_bytes=120)], [])
    ready_rows = [
        make_row(0, "train", 1, ok_with_size),
        make_row(1, "validation", 0, ok_with_size),
        make_row(2, "test", 1, ok_with_size),
    ]
    s_ready = qgate.evaluate_cohort_quality_gate(ready_rows)
    assert s_ready["cohort_gate_verdict"] == "ready_for_locked_export"
    assert all(item["passed"] for item in s_ready["checks"].values())
    assert s_ready["legacy_19d_model_input_ready"] is True


def test_cohort_gate_enforces_eval_1pct_unavailable_bound_and_integrity_rejection(qgate):
    ok_gate = qgate.evaluate_sample_quality(_bundle([_node("cat", "catalog", size_bytes=32)], []), SAMPLE_SHA256)
    parser_obj = {
        "evidence_id": "po1", "kind": "parser_object", "backend": "MuPDF", "observation_status": "observed",
        "object_number": 1, "generation": 0, "revision": None, "byte_offset_start": None,
        "byte_offset_end": None, "filter_chain": None, "is_synthetic_repaired": True,
        "details": {"projection": {"type": "dict"}},
    }
    proj_filtered_gate = qgate.evaluate_sample_quality(
        _bundle([parser_obj], [], status="partial", extraction_status="bounded_complete"),
        SAMPLE_SHA256,
    )

    def clone_gate(gate_template, idx, split, label, *, availability="present"):
        sha = f"{idx + 1:064x}"
        g = None
        if availability == "present":
            g = deepcopy(gate_template)
            g["sample_sha256"] = sha
        return {
            "index": idx,
            "sha256": sha,
            "split": split,
            "label": label,
            "expected_bundle_sha256": "b" * 64,
            "source_bundle_sha256": "b" * 64 if availability == "present" else None,
            "availability": availability,
            "bundle_schema_valid": availability == "present",
            "gate": g,
        }

    val_rows_pass = [
        clone_gate(proj_filtered_gate if i == 141 else ok_gate, i, "validation", 0)
        for i in range(291)
    ]
    res_pass = qgate.evaluate_cohort_quality_gate(val_rows_pass)
    assert res_pass["checks"]["evaluation_partition_coverage"]["passed"] is True
    assert res_pass["unavailable_document_ledger"]["by_disposition_indices"]["unavailable_projection_filtered"] == [141]
    assert res_pass["unavailable_document_ledger"]["eval_abstention_or_tabular_fallback_indices"]["validation"] == [141]
    assert res_pass["cohort"]["planned_denominator"] == 291
    assert res_pass["cohort"]["evaluation_denominator_preserved"] == 291
    assert res_pass["cohort_gate_verdict"] == "ready_for_locked_export"

    val_rows_exceed = deepcopy(val_rows_pass)
    for extra_idx in (10, 20, 30):
        val_rows_exceed[extra_idx] = clone_gate(proj_filtered_gate, extra_idx, "validation", 0)
    res_exceed = qgate.evaluate_cohort_quality_gate(val_rows_exceed)
    assert res_exceed["checks"]["evaluation_partition_coverage"]["passed"] is False
    assert res_exceed["cohort_gate_verdict"] == "blocked_unresolved_extraction_failures"

    missing_rows = deepcopy(val_rows_pass)
    missing_rows[0] = clone_gate(ok_gate, 0, "validation", 0, availability="missing")
    res_missing = qgate.evaluate_cohort_quality_gate(missing_rows)
    assert res_missing["checks"]["cohort_denominator_complete"]["passed"] is False
    assert res_missing["cohort_gate_verdict"] == "rejected_integrity_failure"


def test_quality_gate_job_evaluates_baseline_and_virtual_b1_overlay_without_modifying_inputs(gate_tool, tmp_path, monkeypatch):
    jobs = importlib.import_module("lab_jobs")
    base_job = jobs.make_job("a" * 40, "b" * 64, "c" * 64, mode="offline", kind="pdf-static-cve", attempt="1" * 32)
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

    b0 = normalize_profile({"status": "complete", "errors": [], "worker_cleanup_complete": True}, rows[0]["pdf_sha256"], "deep-static")
    b0["evidence_store"]["records"].extend([_node("cat_0", "catalog"), *(_node(f"in_{i}", "pdf_object") for i in range(200)), _node("late_act", "action")])
    b1 = normalize_profile({"status": "complete", "errors": [], "worker_cleanup_complete": True}, rows[1]["pdf_sha256"], "deep-static")
    b1["evidence_store"]["records"].append(_node("cat_1", "catalog"))
    b2 = normalize_profile({"status": "partial", "errors": [], "worker_cleanup_complete": True}, rows[2]["pdf_sha256"], "deep-static")
    b2["evidence_store"]["records"].append({
        "evidence_id": "po_filter", "kind": "parser_object", "backend": "MuPDF", "observation_status": "observed",
        "object_number": 1, "generation": 0, "revision": None, "byte_offset_start": None, "byte_offset_end": None,
        "filter_chain": None, "is_synthetic_repaired": True, "details": {"projection": {"type": "dict"}},
    })
    b3 = normalize_profile({"status": "worker_error", "errors": ["worker_admission_failed"], "worker_cleanup_complete": True}, rows[3]["pdf_sha256"], "deep-static")
    b4 = normalize_profile({"status": "timeout", "errors": ["wall_timeout"], "worker_cleanup_complete": True}, rows[4]["pdf_sha256"], "deep-static")

    expected = []
    for idx, (row, b_obj) in enumerate(zip(rows, (b0, b1, b2, b3, b4))):
        b_obj["coverage_report"]["provenance"]["secret"] = PRIVATE_SENTINEL
        digest = _write_json(base_dir / "private_bundles" / f"{idx:04d}.json", b_obj, jobs)
        expected.append({
            "index": idx, "sha256": row["pdf_sha256"], "split": row["split"],
            "label": int(row["Label"]), "source_bundle_sha256": digest, "availability": "present",
        })
    expected_path = tmp_path / "expected_index.json"
    _write_json(expected_path, expected, jobs)

    orig_policy = jobs.policy
    monkeypatch.setattr(jobs, "policy", lambda k: {**orig_policy("pdf-static-cic-full"), "samples": 2} if k == "pdf-diagnostic-replay" else orig_policy(k))
    replay_job = jobs.make_job("d" * 40, "e" * 64, "f" * 64, mode="offline", kind="pdf-diagnostic-replay", attempt="2" * 32)
    replay_dir = job_root / replay_job["job_id"]
    (replay_dir / "private_bundles").mkdir(parents=True)
    _write_json(replay_dir / "job.json", replay_job, jobs)
    r_summary = {
        "planned": 2, "completed": 2, "observed": 1, "bounded_complete": 1, "partial": 0, "failed": 1,
        "primary_available": 2, "timeout": 1, "elapsed_ms": 50, "peak_rss_bytes": 512,
        "status_counts": {"bounded_complete": 1, "timeout": 1},
    }
    _write_json(replay_dir / "result.json", jobs.result(replay_job, "partial", summary=r_summary, environment=env), jobs)

    rb0 = normalize_profile({"status": "complete", "errors": [], "worker_cleanup_complete": True}, rows[3]["pdf_sha256"], "deep-static")
    rb0["evidence_store"]["records"].append(_node("cat_restored", "catalog"))
    rb1 = normalize_profile({"status": "timeout", "errors": ["wall_timeout"], "worker_cleanup_complete": True}, rows[4]["pdf_sha256"], "deep-static")
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

    with pytest.raises(ValueError, match="quality_gate_output_inside_input"):
        gate_tool.evaluate_quality_gate_job(base_job["job_id"], expected_path, job_root=job_root, output_root=base_dir / "inside")

    before_base = {p.relative_to(base_dir).as_posix(): p.read_bytes() for p in base_dir.rglob("*") if p.is_file()}
    before_replay = {p.relative_to(replay_dir).as_posix(): p.read_bytes() for p in replay_dir.rglob("*") if p.is_file()}
    out_root = tmp_path / "gate_runs"
    receipt = gate_tool.evaluate_quality_gate_job(
        base_job["job_id"],
        expected_path,
        replay_job_id=replay_job["job_id"],
        job_root=job_root,
        output_root=out_root,
    )
    out_dir = Path(receipt["output"])
    assert receipt["baseline_verdict"] == "blocked_unresolved_extraction_failures"
    assert receipt["virtual_post_b1_verdict"] == "hold_pending_v2_projection_and_size_contract"
    assert receipt["raw_pdf_processing"] is False
    assert receipt["training_executed"] is False
    assert before_base == {p.relative_to(base_dir).as_posix(): p.read_bytes() for p in base_dir.rglob("*") if p.is_file()}
    assert before_replay == {p.relative_to(replay_dir).as_posix(): p.read_bytes() for p in replay_dir.rglob("*") if p.is_file()}

    for name in ("locked_methodology.json", "cases.jsonl", "replay_overlay_cases.jsonl", "summary.json", "report.md", "manifest.json"):
        assert (out_dir / name).is_file()
        assert PRIVATE_SENTINEL not in (out_dir / name).read_text(encoding="utf-8")

    saved_summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    trans = saved_summary["b1_replay_overlay"]["verdict_transition"]
    assert trans["checks_cleared_by_b1"] == ["unresolved_worker_failures_cleared", "evaluation_partition_coverage"]
    assert trans["remaining_failed_checks"] == ["legacy_19d_semantic_size_populated", "security_sensitive_truncation_bounded"]


def test_quality_gate_job_flags_checksum_mismatch_and_refuses_index_141_replay(gate_tool, tmp_path):
    jobs = importlib.import_module("lab_jobs")
    base_job = jobs.make_job("a" * 40, "b" * 64, "c" * 64, mode="offline", kind="pdf-static-cve", attempt="3" * 32)
    job_root = tmp_path / "jobs"
    base_dir = job_root / base_job["job_id"]
    (base_dir / "private_bundles").mkdir(parents=True)

    rows = [
        {"pdf_sha256": f"{i + 1:064x}", "split": "train", "Label": "0"}
        for i in range(5)
    ]
    _write_json(base_dir / "job.json", base_job, jobs)
    _write_json(
        base_dir / "selection.json",
        {"job_id": base_job["job_id"], "rows": rows, "selection_sha256": jobs.sha(jobs.encoded(rows))},
        jobs,
    )
    summary = {
        "planned": 5, "completed": 5, "observed": 5, "bounded_complete": 0, "partial": 0, "failed": 0,
        "primary_available": 5, "timeout": 0, "elapsed_ms": 20, "peak_rss_bytes": 512,
        "status_counts": {"observed": 5},
    }
    env = {"mode": "offline", "guest_network_checked": True, "stdlib_dependencies_checked": True, "hypervisor_controls_attested": True}
    _write_json(base_dir / "result.json", jobs.result(base_job, "passed", summary=summary, environment=env), jobs)

    expected = []
    for idx, row in enumerate(rows):
        b_obj = normalize_profile({"status": "complete", "errors": [], "worker_cleanup_complete": True}, row["pdf_sha256"], "deep-static")
        b_obj["evidence_store"]["records"].append(_node(f"cat_{idx}", "catalog", size_bytes=32))
        digest = _write_json(base_dir / "private_bundles" / f"{idx:04d}.json", b_obj, jobs)
        expected.append({
            "index": idx, "sha256": row["pdf_sha256"], "split": row["split"],
            "label": 0, "source_bundle_sha256": "f" * 64 if idx == 4 else digest, "availability": "present",
        })
    expected_path = tmp_path / "expected_bad.json"
    _write_json(expected_path, expected, jobs)

    receipt = gate_tool.evaluate_quality_gate_job(base_job["job_id"], expected_path, job_root=job_root, output_root=tmp_path / "out")
    assert receipt["baseline_verdict"] == "rejected_integrity_failure"
    saved = json.loads((Path(receipt["output"]) / "summary.json").read_text(encoding="utf-8"))
    assert saved["availability_counts"] == {"checksum_mismatch": 1, "present": 4}
    assert saved["checks"]["cohort_denominator_complete"]["passed"] is False

    replay_job = jobs.make_job("d" * 40, "e" * 64, "f" * 64, mode="offline", kind="pdf-diagnostic-replay", attempt="4" * 32)
    replay_dir = job_root / replay_job["job_id"]
    (replay_dir / "private_bundles").mkdir(parents=True)
    _write_json(replay_dir / "job.json", replay_job, jobs)
    r_sum = {
        "planned": 74, "completed": 74, "observed": 74, "bounded_complete": 0, "partial": 0, "failed": 0,
        "primary_available": 74, "timeout": 0, "elapsed_ms": 20, "peak_rss_bytes": 512,
        "status_counts": {"observed": 74},
    }
    _write_json(replay_dir / "result.json", jobs.result(replay_job, "passed", summary=r_sum, environment=env), jobs)
    _write_json(
        replay_dir / "locked_methodology.json",
        {
            "schema_version": 1, "stage": "BUG-007B1", "job_id": replay_job["job_id"], "baseline_job_id": base_job["job_id"],
            "records": [{"baseline_index": 141, "sha256": "a" * 64, "split": "validation", "label": 0}] * 74,
        },
        jobs,
    )
    with pytest.raises(ValueError, match="quality_gate_replay_index_invalid"):
        gate_tool._evaluate_replay_overlay(replay_job["job_id"], base_job["job_id"], {141: {"sha256": "a" * 64, "split": "validation", "label": 0}}, job_root=job_root)


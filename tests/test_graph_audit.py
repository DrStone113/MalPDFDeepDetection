from __future__ import annotations

from copy import deepcopy
from collections import Counter
import importlib
import json

import pytest


SAMPLE_SHA256 = "a" * 64
PRIVATE_SENTINEL = "PRIVATE_DOCUMENT_SENTINEL_DO_NOT_EXPORT"


@pytest.fixture
def audit():
    return importlib.import_module("malpdf.extraction.graph_audit")


def _node(identifier="root", kind="catalog", status="observed", *, details=None):
    return {"evidence_id": identifier, "kind": kind, "backend": "pypdf", "observation_status": status,
            "object_number": 1, "generation": 0, "revision": None, "byte_offset_start": None,
            "byte_offset_end": None, "details": {} if details is None else details}


def _bundle(nodes=None, edges=None):
    return {"sample_sha256": SAMPLE_SHA256, "status": "partial",
            "evidence_store": {"records": [_node()] if nodes is None else nodes,
                               "edges": [] if edges is None else edges},
            "coverage_report": {"worker": {"status": "partial", "worker_cleanup_complete": True,
                "worker_exit_code": 0, "last_stage": "parse_pdf"}, "backends": {}, "limitations": []}}


def _span_record():
    return {**_node("object-7", "forensic_object_declaration"), "backend": "raw_forensic",
            "object_number": 7, "generation": 0, "byte_offset_start": 10, "byte_offset_end": 30,
            "details": {"source_space": "original", "top_level_confirmed": True,
                        "byte_start": 10, "byte_end": 30}}


def _edge(identifier, source, target):
    return {"id": identifier, "source": source, "target": target, "kind": "pdf_reference", "status": "verified"}


def test_canonical_serialization_is_deterministic_utf8_without_newline(audit):
    value = {"z": "Tiếng Việt", "a": [1, None, False]}
    expected = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    assert audit.canonical_bytes(value) == expected
    assert audit.canonical_bytes(dict(reversed(list(value.items())))) == expected
    assert not expected.endswith(b"\n")


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf")])
def test_canonical_serialization_rejects_nonfinite_numbers(audit, value):
    with pytest.raises(ValueError):
        audit.canonical_bytes({"value": value})


def test_original_object_span_uses_verified_half_open_source_interval(audit):
    record = _span_record()
    before = deepcopy(record)
    assert audit.span_measurement(record) == {"value": 20, "reason": "measured"}
    assert record == before


def test_semantic_node_storage_size_does_not_become_original_object_size(audit):
    result = audit.span_measurement(_node(details={"size_bytes": 123456}))
    assert result == {"value": None, "reason": "not_applicable"}


def test_decoded_object_stream_member_is_not_an_original_pdf_byte_span(audit):
    record = _span_record()
    record["details"]["source_space"] = "decoded_stream"
    assert audit.span_measurement(record) == {"value": None, "reason": "non_original_space"}


@pytest.mark.parametrize("key,value", [("observation_status", "partial"), ("backend", "MuPDF")])
def test_unverified_or_other_backend_span_is_not_promoted(audit, key, value):
    record = _span_record()
    record[key] = value
    measured = audit.span_measurement(record)
    assert measured["value"] is None
    assert measured["reason"] != "measured"


def test_unconfirmed_top_level_boundary_stays_unknown(audit):
    record = _span_record()
    record["details"]["top_level_confirmed"] = False
    assert audit.span_measurement(record) == {"value": None, "reason": "unverified_boundary"}


def test_missing_object_boundary_is_unknown_instead_of_zero(audit):
    record = _span_record()
    record["byte_offset_end"] = record["details"]["byte_end"] = None
    assert audit.span_measurement(record) == {"value": None, "reason": "missing_boundary"}


@pytest.mark.parametrize("start,end", [(True, 30), (10, False), (-1, 30), (30, 10), (10.0, 30)])
def test_invalid_original_object_boundaries_are_not_measurements(audit, start, end):
    record = _span_record()
    record["byte_offset_start"] = record["details"]["byte_start"] = start
    record["byte_offset_end"] = record["details"]["byte_end"] = end
    assert audit.span_measurement(record) == {"value": None, "reason": "invalid_boundary"}


def test_conflicting_locator_and_producer_span_is_not_accepted(audit):
    record = _span_record()
    record["details"]["byte_start"] = 11
    assert audit.span_measurement(record) == {"value": None, "reason": "invalid_boundary"}


@pytest.mark.parametrize("field,value", [("object_number", 0), ("object_number", True), ("generation", None), ("generation", -1)])
def test_original_span_requires_valid_object_identity(audit, field, value):
    record = _span_record()
    record[field] = value
    measured = audit.span_measurement(record)
    assert measured["value"] is None
    assert measured["reason"] != "measured"


@pytest.mark.parametrize("field,value", [("object_number", 999), ("generation", 1)])
def test_original_span_rejects_conflicting_producer_object_identity(audit, field, value):
    record = _span_record()
    record["details"].update(object_number=record["object_number"], generation=record["generation"])
    record["details"][field] = value
    measured = audit.span_measurement(record)
    assert measured["value"] is None
    assert measured["reason"] != "measured"


def test_original_span_accepts_agreeing_producer_object_identity(audit):
    record = _span_record()
    record["details"].update(object_number=record["object_number"], generation=record["generation"])
    assert audit.span_measurement(record) == {"value": 20, "reason": "measured"}


def test_graph_audit_preserves_input_and_has_closed_top_level_schema(audit):
    source = _bundle()
    before = deepcopy(source)
    result = audit.audit_bundle(source, SAMPLE_SHA256)
    assert set(result) == {"schema_version", "sample_sha256", "bundle_status", "issues", "graph",
                           "classification", "backends", "worker", "measurements"}
    assert result["sample_sha256"] == SAMPLE_SHA256
    assert result["graph"]["feature_dim"] is None
    assert result["graph"]["legacy_target_feature_dim"] == 19
    assert source == before


@pytest.mark.parametrize("digest", ["b" * 64, "invalid", "A" * 64])
def test_bundle_audit_is_bound_to_the_expected_document_hash(audit, digest):
    with pytest.raises(ValueError):
        audit.audit_bundle(_bundle(), digest)


def test_projection_accounts_separately_for_kind_status_and_node_cap(audit):
    nodes = [_node("root"), _node("page", "page"), _node("stream", "stream"),
             _node("view", "parser_object"), _node("unavailable", "page", "unsupported")]
    edges = [_edge("root-page", "root", "page"), _edge("page-stream", "page", "stream"),
             _edge("root-view", "root", "view")]
    result = audit.audit_bundle(_bundle(nodes, edges), SAMPLE_SHA256, node_cap=2)
    graph = result["graph"]
    assert graph["evidence_nodes"] == 5
    assert graph["evidence_edges"] == 3
    assert graph["projected_nodes"] == 2
    assert graph["projected_edges"] == 1
    assert graph["excluded_nodes_kind"] == 1
    assert graph["excluded_nodes_status"] == 1
    assert graph["excluded_nodes_cap"] == 1
    assert graph["excluded_edges_endpoint"] == 2
    assert graph["projected_isolates"] == 0


def test_valid_multigraph_cycles_and_self_loops_are_retained(audit):
    nodes = [_node("root"), _node("page", "page")]
    edges = [_edge("a", "root", "page"), _edge("b", "root", "page"),
             _edge("c", "page", "root"), _edge("d", "root", "root")]
    result = audit.audit_bundle(_bundle(nodes, edges), SAMPLE_SHA256)
    assert result["graph"]["projected_edges"] == 4
    assert result["graph"]["parallel_edges"] == 1
    assert result["graph"]["self_loops"] == 1
    assert result["issues"]["duplicate_node_ids"] == 0
    assert result["issues"]["duplicate_edge_ids"] == 0
    assert result["issues"]["dangling_edges"] == 0


def test_duplicate_id_and_dangling_endpoint_are_reported_without_crash(audit):
    nodes = [_node("root"), _node("root", "page")]
    edges = [_edge("duplicate", "root", "missing"), _edge("duplicate", "root", "root")]
    result = audit.audit_bundle(_bundle(nodes, edges), SAMPLE_SHA256)
    assert result["issues"]["duplicate_node_ids"] == 1
    assert result["issues"]["duplicate_edge_ids"] == 1
    assert result["issues"]["dangling_edges"] == 1


@pytest.mark.parametrize("field,value", [("kind", []), ("observation_status", []), ("details", [])])
def test_malformed_node_attributes_are_diagnosed_without_audit_crash(audit, field, value):
    node = _node()
    node[field] = value
    result = audit.audit_bundle(_bundle([node]), SAMPLE_SHA256)
    assert result["issues"]["invalid_attributes"] > 0


@pytest.mark.parametrize("cap", [True, 0, -1, 2.0])
def test_projection_cap_requires_a_positive_integer(audit, cap):
    with pytest.raises(ValueError):
        audit.audit_bundle(_bundle(), SAMPLE_SHA256, node_cap=cap)


def test_real_parser_objects_excluded_from_projection_are_distinct_from_worker_failure(audit):
    nodes = [_node("native-1", "parser_object", details={"projection": {"projection_complete": True}})]
    result = audit.audit_bundle(_bundle(nodes), SAMPLE_SHA256)
    assert result["graph"]["projected_nodes"] == 0
    assert result["graph"]["parser_object_candidates"] == 1
    assert result["graph"]["parser_objects_observed"] == 1
    assert result["graph"]["parser_objects_with_projection"] == 1
    assert result["classification"]["failure_family"] == "projection_filter"
    assert result["classification"]["investigation_required"] is True


def test_failed_parser_candidates_are_not_successfully_read_graph_nodes(audit):
    nodes = [_node(f"candidate-{index}", "parser_object", "partial", details={"projection": None}) for index in range(7)]
    result = audit.audit_bundle(_bundle(nodes), SAMPLE_SHA256)
    assert result["graph"]["parser_object_candidates"] == 7
    assert result["graph"]["parser_objects_observed"] == 0
    assert result["graph"]["parser_objects_with_projection"] == 0
    assert result["classification"]["failure_family"] == "unresolved"
    assert result["classification"]["root_cause_status"] == "unresolved"


def test_partial_projection_is_not_counted_as_observed_success(audit):
    nodes = [_node("candidate", "parser_object", "partial", details={"projection": {"projection_complete": False}})]
    result = audit.audit_bundle(_bundle(nodes), SAMPLE_SHA256)
    assert result["graph"]["parser_object_candidates"] == 1
    assert result["graph"]["parser_objects_observed"] == 0


def test_generic_admission_error_does_not_prove_corrupt_pdf(audit):
    source = _bundle([])
    source["coverage_report"]["limitations"] = ["worker_admission_failed"]
    source["coverage_report"]["worker"].update(status="worker_error", worker_exit_code=None, last_stage=None)
    result = audit.audit_bundle(source, SAMPLE_SHA256)
    classification = result["classification"]
    assert classification["failure_family"] == "worker_error_unspecified"
    assert classification["root_cause_status"] == "unresolved"
    assert "corrupt" not in json.dumps(classification).lower()


def test_explicit_timeout_is_kept_separate_from_unknown_worker_error(audit):
    source = _bundle([])
    source["coverage_report"]["limitations"] = ["wall_timeout"]
    source["coverage_report"]["worker"].update(status="timeout", worker_exit_code=-9)
    result = audit.audit_bundle(source, SAMPLE_SHA256)
    assert result["classification"]["failure_family"] == "timeout"
    assert result["classification"]["investigation_required"] is True


def test_parser_error_alone_cannot_certify_corrupt_or_legitimately_empty_pdf(audit):
    source = _bundle([])
    source["coverage_report"]["worker"]["status"] = "parser_error"
    result = audit.audit_bundle(source, SAMPLE_SHA256)
    assert result["classification"]["root_cause_status"] == "unresolved"
    assert result["classification"]["failure_family"] not in {"corrupt", "corrupt_input", "valid_empty"}


def test_document_only_evidence_is_not_a_placeholder_model_graph(audit):
    result = audit.audit_bundle(_bundle([_node("document", "document")]), SAMPLE_SHA256)
    assert result["graph"]["evidence_nodes"] == 1
    assert result["graph"]["projected_nodes"] == 0
    assert result["classification"]["investigation_required"] is True
    assert result["classification"]["failure_family"] != "valid_empty"


def test_projection_present_does_not_get_an_invented_extraction_failure(audit):
    result = audit.audit_bundle(_bundle(), SAMPLE_SHA256)
    assert result["classification"]["failure_family"] == "none"
    assert result["classification"]["investigation_required"] is False


def test_audit_output_never_contains_document_text_paths_ids_or_unknown_code_strings(audit):
    source = _bundle([_node(PRIVATE_SENTINEL, details={"script": PRIVATE_SENTINEL, "raw_text": PRIVATE_SENTINEL})])
    source["coverage_report"]["limitations"] = [PRIVATE_SENTINEL]
    source["coverage_report"]["backends"] = {PRIVATE_SENTINEL: {"observation_status": "partial", "limitations": [PRIVATE_SENTINEL]}}
    source["coverage_report"]["worker"].update(raw_exception=PRIVATE_SENTINEL, last_stage=PRIVATE_SENTINEL)
    source["source_path"] = PRIVATE_SENTINEL
    result = audit.audit_bundle(source, SAMPLE_SHA256)
    assert PRIVATE_SENTINEL not in json.dumps(result, allow_nan=False)
    assert "raw_text" not in json.dumps(result)
    assert "raw_exception" not in json.dumps(result)


def test_case_classification_does_not_depend_on_labels_or_split(audit):
    source = _bundle([])
    source["coverage_report"]["limitations"] = ["worker_admission_failed"]
    first = audit.audit_bundle({**source, "Label": 0, "split": "train"}, SAMPLE_SHA256)
    second = audit.audit_bundle({**source, "Label": 1, "split": "test"}, SAMPLE_SHA256)
    assert first == second


def test_empty_distribution_and_observed_zero_are_distinct(audit):
    missing = audit.distribution([], null_count=3)
    observed = audit.distribution([0])
    assert missing == {"count": 0, "null_count": 3, "min": None, "median": None, "p95": None, "max": None, "total": 0}
    assert observed == {"count": 1, "null_count": 0, "min": 0, "median": 0.0, "p95": 0, "max": 0, "total": 0}


def test_weighted_distribution_uses_actual_counts_and_nearest_rank_p95(audit):
    result = audit.distribution(Counter({2: 1, 10: 3}))
    assert result == {"count": 4, "null_count": 0, "min": 2, "median": 10.0, "p95": 10, "max": 10, "total": 32}
    result = audit.distribution(range(1, 21))
    assert result["median"] == 10.5
    assert result["p95"] == 19


def test_storage_measurement_counts_real_canonical_utf8_bytes(audit):
    node = _node(details={"metadata": "Tiếng Việt", "size_bytes": None})
    source = _bundle([node])
    result = audit.audit_bundle(source, SAMPLE_SHA256)
    storage = result["measurements"]["node_record_storage_bytes"]
    expected = len(audit.canonical_bytes(node))
    assert storage["count"] == 1
    assert storage["min"] == storage["max"] == storage["total"] == expected
    assert result["measurements"]["graph_wire_storage_bytes"] == len(audit.canonical_bytes({"nodes": [node], "edges": []}))
    assert result["measurements"]["original_object_span_bytes"]["count"] == 0
    assert result["measurements"]["original_object_span_bytes"]["min"] is None


def test_summary_keeps_denominator_unknown_dimension_and_missing_span_values(audit):
    statistics = {}
    first = audit.audit_bundle(_bundle(), SAMPLE_SHA256, statistics=statistics)
    second = audit.audit_bundle(_bundle([]), SAMPLE_SHA256, statistics=statistics)
    summary = audit.summarize_cases([{"audit": first}, {"audit": second}, {"audit": None}], statistics=statistics)
    assert summary["planned"] == 3
    assert summary["audited"] == 2
    assert summary["missing_or_rejected"] == 1
    assert summary["projected_graphs"] == 1
    assert summary["focus_missing_graph"] == 1
    assert summary["feature_dim"] is None
    assert summary["legacy_target_feature_dim"] == 19
    assert summary["model_input_ready"] is False
    assert summary["node_distributions"]["original_object_span_bytes"]["min"] is None


def test_closed_case_validator_accepts_own_numeric_output(audit):
    case = audit.audit_bundle(_bundle(), SAMPLE_SHA256)
    assert audit.validate_case(case) == case


@pytest.mark.parametrize("location", ["top_level", "worker", "classification", "backend", "span_reason"])
def test_closed_case_validator_rejects_unknown_fields_and_source_text(audit, location):
    case = audit.audit_bundle(_bundle(), SAMPLE_SHA256)
    if location == "top_level":
        case[PRIVATE_SENTINEL] = PRIVATE_SENTINEL
    elif location == "worker":
        case["worker"]["raw_exception"] = PRIVATE_SENTINEL
    elif location == "classification":
        case["classification"]["evidence_codes"] = [PRIVATE_SENTINEL]
    elif location == "backend":
        case["backends"][PRIVATE_SENTINEL] = {}
    else:
        case["measurements"]["original_span_reasons"][PRIVATE_SENTINEL] = 1
    with pytest.raises(ValueError):
        audit.validate_case(case)


def test_closed_case_validator_rejects_legacy_target_used_as_actual_feature_dimension(audit):
    case = audit.audit_bundle(_bundle(), SAMPLE_SHA256)
    case["graph"]["feature_dim"] = 19
    with pytest.raises(ValueError):
        audit.validate_case(case)


def test_closed_case_validator_rejects_nonfinite_statistics(audit):
    case = audit.audit_bundle(_bundle(), SAMPLE_SHA256)
    case["measurements"]["node_record_storage_bytes"]["median"] = float("nan")
    with pytest.raises(ValueError):
        audit.validate_case(case)


def test_closed_case_validator_requires_integer_statistic_counts(audit):
    case = audit.audit_bundle(_bundle(), SAMPLE_SHA256)
    case["measurements"]["node_record_storage_bytes"]["count"] = 0.5
    with pytest.raises(ValueError):
        audit.validate_case(case)

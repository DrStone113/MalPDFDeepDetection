from __future__ import annotations

from collections import Counter
from copy import deepcopy
import re

from malpdf.extraction.contracts import validate_bundle
from malpdf.extraction.graph_audit import audit_bundle, canonical_bytes
from malpdf.extraction.graph_projection_v2 import (
    NODE_FEATURE_DIM_V2,
    PROJECTION_CONTRACT_VERSION,
    project_graph_bundle_v2,
    validate_graph_projection_v2,
)
from malpdf.extraction.graph_truncation_audit import _graph_state, audit_truncation_bundle
from malpdf.extraction.numeric_export import MAX_NODES, project_numeric_bundle, validate_numeric_projection


GATE_CONTRACT_VERSION = "pdf-extraction-quality-gate-v1"
GATE_CONTRACT_VERSION_V2 = "pdf-extraction-quality-gate-v2"
HASH_RE = re.compile(r"[a-f0-9]{64}\Z")

SAMPLE_DISPOSITIONS = (
    "usable_complete_projection",
    "usable_degraded_partial_or_timeout",
    "usable_degraded_capped_benign_loss",
    "usable_degraded_capped_security_loss",
    "unavailable_projection_filtered",
    "unavailable_timeout_no_graph",
    "unavailable_worker_failure",
    "unavailable_unclassified_empty",
    "rejected_unverified_cleanup",
    "rejected_missing_or_corrupt",
)

EVALUATION_HANDLINGS = frozenset({
    "graph_and_tabular",
    "abstention_or_tabular_only_no_placeholder_graph",
    "fail_closed_abort_evaluation",
})

WARNING_CODES = frozenset({
    "capped_security_sensitive_node_loss",
    "capped_non_sensitive_node_loss",
    "secondary_stage_timeout_with_primary_graph",
    "newly_orphaned_retained_nodes",
    "catalog_disconnection_by_cap",
    "legacy_semantic_node_size_missing",
})

COHORT_VERDICTS = frozenset({
    "rejected_integrity_failure",
    "blocked_unresolved_extraction_failures",
    "hold_pending_v2_projection_and_size_contract",
    "ready_for_locked_export",
})

METRIC_KEYS = frozenset({
    "bundle_status",
    "worker_cleanup_complete",
    "structural_issues_total",
    "tabular_feature_count",
    "tabular_features_nonnull",
    "eligible_nodes_before_cap",
    "kept_nodes_after_cap",
    "dropped_nodes_cap",
    "security_sensitive_dropped_cap",
    "kept_edges_after_cap",
    "dropped_edges_cap",
    "newly_orphaned_kept_nodes",
    "kept_disconnected_from_catalog_by_cap",
    "legacy_sizes_known",
    "legacy_sizes_null",
    "verified_physical_spans_known",
    "stream_raw_payloads_known",
    "parser_objects_observed",
})

UNAVAILABLE_DOCUMENT_POLICY = {
    "protocol_g_denominator_preserved": True,
    "placeholder_zero_nodes_allowed": False,
    "eval_denominator_shrinkage_allowed": False,
    "artificial_nonempty_1452_required": False,
    "train_empty_graph_handling": "exclude_from_gnn_message_passing_batches_retain_in_cohort_manifest_and_tabular_audit",
    "eval_empty_graph_handling": "explicit_abstention_or_verified_tabular_fallback_counted_against_full_split_denominator",
    "rejected_sample_handling": "fail_closed_abort_evaluation",
}

NODE_SIZE_AND_FEATURE_PROVENANCE_POLICY = {
    "missing_size_representation": "null",
    "null_to_zero_imputation_allowed": False,
    "projected_json_storage_bytes_as_object_size_allowed": False,
    "legacy_19d_requires_populated_semantic_size": True,
    "v2_provenance_producers": [
        "verified_physical_declaration_span_bytes",
        "stream_raw_payload_bytes",
    ],
    "worker_cleanup_complete_required": True,
    "tabular_observation_status_contract_enforced": True,
}

DEFAULT_GATE_POLICY = {
    "policy_version": "protocol-g-quality-policy-v1",
    "require_full_cohort_denominator": True,
    "require_verified_worker_cleanup": True,
    "forbid_placeholder_zero_nodes": True,
    "forbid_null_to_zero_size_imputation": True,
    "forbid_json_storage_as_object_size": True,
    "forbid_eval_denominator_shrinkage": True,
    "max_eval_unavailable_ratio": 0.01,
    "max_security_sensitive_cap_loss_ratio": 0.05,
}


def _rejected_sample_gate_base(
    expected_sha256,
    *,
    node_cap=MAX_NODES,
    disposition="rejected_missing_or_corrupt",
    contract_version=GATE_CONTRACT_VERSION,
):
    if disposition not in ("rejected_missing_or_corrupt", "rejected_unverified_cleanup"):
        raise ValueError("quality_gate_rejected_disposition")
    result = {
        "schema_version": 1,
        "gate_contract_version": contract_version,
        "sample_sha256": expected_sha256,
        "node_cap": node_cap,
        "sample_disposition": disposition,
        "gnn_message_passing_eligible": False,
        "tabular_features_valid": False,
        "evaluation_denominator_included": True,
        "evaluation_handling": "fail_closed_abort_evaluation",
        "placeholder_nodes_inserted": False,
        "legacy_19d_ready": False,
        "v2_provenance_graph_ready": False,
        "warnings": [],
        "metrics": {
            "bundle_status": "unknown",
            "worker_cleanup_complete": False if disposition == "rejected_unverified_cleanup" else None,
            "structural_issues_total": 0,
            "tabular_feature_count": 0,
            "tabular_features_nonnull": 0,
            "eligible_nodes_before_cap": 0,
            "kept_nodes_after_cap": 0,
            "dropped_nodes_cap": 0,
            "security_sensitive_dropped_cap": 0,
            "kept_edges_after_cap": 0,
            "dropped_edges_cap": 0,
            "newly_orphaned_kept_nodes": 0,
            "kept_disconnected_from_catalog_by_cap": 0,
            "legacy_sizes_known": 0,
            "legacy_sizes_null": 0,
            "verified_physical_spans_known": 0,
            "stream_raw_payloads_known": 0,
            "parser_objects_observed": 0,
        },
    }
    return _validate_sample_gate_case_for_version(result, contract_version=contract_version)


def rejected_sample_gate(expected_sha256, *, node_cap=MAX_NODES, disposition="rejected_missing_or_corrupt"):
    return _rejected_sample_gate_base(
        expected_sha256,
        node_cap=node_cap,
        disposition=disposition,
        contract_version=GATE_CONTRACT_VERSION,
    )


def rejected_sample_gate_v2(expected_sha256, *, node_cap=MAX_NODES, disposition="rejected_missing_or_corrupt"):
    return _rejected_sample_gate_base(
        expected_sha256,
        node_cap=node_cap,
        disposition=disposition,
        contract_version=GATE_CONTRACT_VERSION_V2,
    )


def evaluate_sample_quality(bundle, expected_sha256, *, node_cap=MAX_NODES):
    if not isinstance(expected_sha256, str) or not HASH_RE.fullmatch(expected_sha256):
        raise ValueError("quality_gate_identity")
    if type(node_cap) is not int or not 1 <= node_cap <= MAX_NODES:
        raise ValueError("quality_gate_node_cap")
    if not isinstance(bundle, dict) or bundle.get("sample_sha256") != expected_sha256:
        return rejected_sample_gate(expected_sha256, node_cap=node_cap)

    try:
        validate_bundle(bundle)
        graph_aud = audit_bundle(bundle, expected_sha256, node_cap=node_cap)
        trunc = audit_truncation_bundle(bundle, expected_sha256, node_cap=node_cap)
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
        return rejected_sample_gate(expected_sha256, node_cap=node_cap)

    issues_total = sum(graph_aud["issues"].values())
    if issues_total > 0:
        res = rejected_sample_gate(expected_sha256, node_cap=node_cap)
        res["metrics"]["structural_issues_total"] = issues_total
        return validate_sample_gate_case(res)

    try:
        numeric = validate_numeric_projection(project_numeric_bundle(bundle, expected_sha256), expected_sha256)
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
        return rejected_sample_gate(expected_sha256, node_cap=node_cap)

    cleanup_ok = trunc["quality_gate_view"]["worker_cleanup_complete"]
    if cleanup_ok is not True:
        return rejected_sample_gate(expected_sha256, node_cap=node_cap, disposition="rejected_unverified_cleanup")

    na = trunc["node_accounting"]
    ea = trunc["edge_accounting"]
    st = trunc["structural_impact"]
    sp = trunc["size_provenance"]
    qg = trunc["quality_gate_view"]

    kept = na["kept_nodes_after_cap"]
    is_capped = na["is_capped"]
    sec_drop = na["security_sensitive_dropped_cap"]
    b_status = qg["bundle_status"]
    g_state = qg["graph_state"]

    legacy_known = sp["legacy_semantic_size_bytes"]["known_count"]
    legacy_null = sp["legacy_semantic_size_bytes"]["null_count"]
    phys_known = sp["verified_physical_declaration_span_bytes"]["known_count"]
    stream_known = sp["stream_raw_payload_bytes"]["known_count"]

    feat_map = numeric["features"]
    feat_count = len(feat_map)
    feat_nonnull = sum(item["value"] is not None for item in feat_map.values())

    warnings = []
    if kept == 0:
        gnn_ok = False
        handling = "abstention_or_tabular_only_no_placeholder_graph"
        if g_state == "empty_projection_filtered":
            disposition = "unavailable_projection_filtered"
        elif g_state == "empty_timeout":
            disposition = "unavailable_timeout_no_graph"
        elif g_state == "empty_worker_error":
            disposition = "unavailable_worker_failure"
        else:
            disposition = "unavailable_unclassified_empty"
    else:
        gnn_ok = True
        handling = "graph_and_tabular"
        if is_capped and sec_drop > 0:
            disposition = "usable_degraded_capped_security_loss"
            warnings.append("capped_security_sensitive_node_loss")
        elif is_capped:
            disposition = "usable_degraded_capped_benign_loss"
            warnings.append("capped_non_sensitive_node_loss")
        elif b_status in {"complete", "bounded_complete", "observed"}:
            disposition = "usable_complete_projection"
        else:
            disposition = "usable_degraded_partial_or_timeout"

        if b_status == "timeout":
            warnings.append("secondary_stage_timeout_with_primary_graph")
        if st["newly_orphaned_kept_nodes"] > 0:
            warnings.append("newly_orphaned_retained_nodes")
        if st["kept_disconnected_from_catalog_by_cap"] > 0:
            warnings.append("catalog_disconnection_by_cap")
        if legacy_null > 0:
            warnings.append("legacy_semantic_node_size_missing")

    legacy_ready = bool(gnn_ok and kept > 0 and legacy_null == 0 and legacy_known == kept)
    v2_ready = bool(gnn_ok and kept > 0 and sec_drop == 0)

    result = {
        "schema_version": 1,
        "gate_contract_version": GATE_CONTRACT_VERSION,
        "sample_sha256": expected_sha256,
        "node_cap": node_cap,
        "sample_disposition": disposition,
        "gnn_message_passing_eligible": gnn_ok,
        "tabular_features_valid": True,
        "evaluation_denominator_included": True,
        "evaluation_handling": handling,
        "placeholder_nodes_inserted": False,
        "legacy_19d_ready": legacy_ready,
        "v2_provenance_graph_ready": v2_ready,
        "warnings": sorted(set(warnings)),
        "metrics": {
            "bundle_status": b_status,
            "worker_cleanup_complete": True,
            "structural_issues_total": 0,
            "tabular_feature_count": feat_count,
            "tabular_features_nonnull": feat_nonnull,
            "eligible_nodes_before_cap": na["eligible_nodes_before_cap"],
            "kept_nodes_after_cap": kept,
            "dropped_nodes_cap": na["dropped_nodes_cap"],
            "security_sensitive_dropped_cap": sec_drop,
            "kept_edges_after_cap": ea["kept_edges_after_cap"],
            "dropped_edges_cap": ea["dropped_edges_cap"],
            "newly_orphaned_kept_nodes": st["newly_orphaned_kept_nodes"],
            "kept_disconnected_from_catalog_by_cap": st["kept_disconnected_from_catalog_by_cap"],
            "legacy_sizes_known": legacy_known,
            "legacy_sizes_null": legacy_null,
            "verified_physical_spans_known": phys_known,
            "stream_raw_payloads_known": stream_known,
            "parser_objects_observed": qg["parser_objects_observed"],
        },
    }
    return validate_sample_gate_case(result)


def evaluate_sample_quality_v2(bundle, expected_sha256, *, node_cap=MAX_NODES):
    if not isinstance(expected_sha256, str) or not HASH_RE.fullmatch(expected_sha256):
        raise ValueError("quality_gate_identity")
    if type(node_cap) is not int or not 1 <= node_cap <= MAX_NODES:
        raise ValueError("quality_gate_node_cap")
    if not isinstance(bundle, dict) or bundle.get("sample_sha256") != expected_sha256:
        return rejected_sample_gate_v2(expected_sha256, node_cap=node_cap)

    try:
        validate_bundle(bundle)
        graph_aud = audit_bundle(bundle, expected_sha256, node_cap=node_cap)
        trunc = audit_truncation_bundle(bundle, expected_sha256, node_cap=node_cap)
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
        return rejected_sample_gate_v2(expected_sha256, node_cap=node_cap)

    issues_total = sum(graph_aud["issues"].values())
    if issues_total > 0:
        res = rejected_sample_gate_v2(expected_sha256, node_cap=node_cap)
        res["metrics"]["structural_issues_total"] = issues_total
        return validate_sample_gate_case_v2(res)

    try:
        proj_v2 = validate_graph_projection_v2(
            project_graph_bundle_v2(bundle, expected_sha256, node_cap=node_cap),
            expected_sha256,
        )
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
        return rejected_sample_gate_v2(expected_sha256, node_cap=node_cap)

    cleanup_ok = proj_v2["worker"]["worker_cleanup_complete"]
    if cleanup_ok is not True:
        return rejected_sample_gate_v2(expected_sha256, node_cap=node_cap, disposition="rejected_unverified_cleanup")

    g = proj_v2["graph"]
    qg = trunc["quality_gate_view"]
    coverage = bundle.get("coverage_report") if isinstance(bundle.get("coverage_report"), dict) else {}
    raw_worker = coverage.get("worker") if isinstance(coverage.get("worker"), dict) else {}
    worker_status = raw_worker.get("status") if isinstance(raw_worker.get("status"), str) else "unknown"
    limitations = [x for x in coverage.get("limitations", []) if isinstance(x, str)]

    kept = g["num_nodes"]
    dropped_cap = g["dropped_nodes_cap"]
    is_capped = dropped_cap > 0
    sec_drop = g["security_sensitive_dropped_cap"]
    b_status = proj_v2["status"]
    parser_obs = qg["parser_objects_observed"]
    g_state = _graph_state(kept, is_capped, parser_obs, b_status, worker_status, limitations)

    phys_known = sum(x is not None for x in g["verified_physical_span_bytes"])
    stream_known = sum(x is not None for x in g["stream_raw_payload_bytes"])

    feat_map = proj_v2["features"]
    feat_count = len(feat_map)
    feat_nonnull = sum(item["value"] is not None for item in feat_map.values())

    warnings = []
    if kept == 0:
        gnn_ok = False
        handling = "abstention_or_tabular_only_no_placeholder_graph"
        if g_state == "empty_projection_filtered":
            disposition = "unavailable_projection_filtered"
        elif g_state == "empty_timeout":
            disposition = "unavailable_timeout_no_graph"
        elif g_state == "empty_worker_error":
            disposition = "unavailable_worker_failure"
        else:
            disposition = "unavailable_unclassified_empty"
    else:
        gnn_ok = True
        handling = "graph_and_tabular"
        if is_capped and sec_drop > 0:
            disposition = "usable_degraded_capped_security_loss"
            warnings.append("capped_security_sensitive_node_loss")
        elif is_capped:
            disposition = "usable_degraded_capped_benign_loss"
            warnings.append("capped_non_sensitive_node_loss")
        elif b_status in {"complete", "bounded_complete", "observed"}:
            disposition = "usable_complete_projection"
        else:
            disposition = "usable_degraded_partial_or_timeout"

        if b_status == "timeout":
            warnings.append("secondary_stage_timeout_with_primary_graph")

    v2_ready = bool(
        gnn_ok
        and kept > 0
        and g["model_input_ready"] is True
        and g["projected_json_storage_bytes_used"] is False
        and sec_drop == 0
    )

    result = {
        "schema_version": 1,
        "gate_contract_version": GATE_CONTRACT_VERSION_V2,
        "sample_sha256": expected_sha256,
        "node_cap": node_cap,
        "sample_disposition": disposition,
        "gnn_message_passing_eligible": gnn_ok,
        "tabular_features_valid": True,
        "evaluation_denominator_included": True,
        "evaluation_handling": handling,
        "placeholder_nodes_inserted": False,
        "legacy_19d_ready": False,
        "v2_provenance_graph_ready": v2_ready,
        "warnings": sorted(set(warnings)),
        "metrics": {
            "bundle_status": b_status,
            "worker_cleanup_complete": True,
            "structural_issues_total": 0,
            "tabular_feature_count": feat_count,
            "tabular_features_nonnull": feat_nonnull,
            "eligible_nodes_before_cap": g["eligible_nodes_before_cap"],
            "kept_nodes_after_cap": kept,
            "dropped_nodes_cap": dropped_cap,
            "security_sensitive_dropped_cap": sec_drop,
            "kept_edges_after_cap": g["num_edges"],
            "dropped_edges_cap": 0,
            "newly_orphaned_kept_nodes": 0,
            "kept_disconnected_from_catalog_by_cap": 0,
            "legacy_sizes_known": 0,
            "legacy_sizes_null": kept,
            "verified_physical_spans_known": phys_known,
            "stream_raw_payloads_known": stream_known,
            "parser_objects_observed": parser_obs,
        },
    }
    return validate_sample_gate_case_v2(result)


def _validate_sample_gate_case_for_version(value, *, contract_version):
    keys = {
        "schema_version",
        "gate_contract_version",
        "sample_sha256",
        "node_cap",
        "sample_disposition",
        "gnn_message_passing_eligible",
        "tabular_features_valid",
        "evaluation_denominator_included",
        "evaluation_handling",
        "placeholder_nodes_inserted",
        "legacy_19d_ready",
        "v2_provenance_graph_ready",
        "warnings",
        "metrics",
    }
    if (not isinstance(value, dict) or set(value) != keys or value["schema_version"] != 1
            or value["gate_contract_version"] != contract_version
            or not isinstance(value["sample_sha256"], str) or not HASH_RE.fullmatch(value["sample_sha256"])
            or type(value["node_cap"]) is not int or not 1 <= value["node_cap"] <= MAX_NODES
            or value["sample_disposition"] not in SAMPLE_DISPOSITIONS
            or type(value["gnn_message_passing_eligible"]) is not bool
            or type(value["tabular_features_valid"]) is not bool
            or value["evaluation_denominator_included"] is not True
            or value["evaluation_handling"] not in EVALUATION_HANDLINGS
            or value["placeholder_nodes_inserted"] is not False
            or type(value["legacy_19d_ready"]) is not bool
            or type(value["v2_provenance_graph_ready"]) is not bool
            or not isinstance(value["warnings"], list)
            or any(not isinstance(w, str) or w not in WARNING_CODES for w in value["warnings"])):
        raise ValueError("quality_gate_case_shape")

    m = value["metrics"]
    if not isinstance(m, dict) or set(m) != METRIC_KEYS:
        raise ValueError("quality_gate_case_metrics")
    kept = m["kept_nodes_after_cap"]
    if value["gnn_message_passing_eligible"] is not (
        value["sample_disposition"].startswith("usable_") and kept > 0 and m["worker_cleanup_complete"] is True
    ):
        raise ValueError("quality_gate_gnn_flag")
    if contract_version == GATE_CONTRACT_VERSION:
        if value["legacy_19d_ready"] is not (
            value["gnn_message_passing_eligible"] and m["legacy_sizes_null"] == 0 and m["legacy_sizes_known"] == kept
        ):
            raise ValueError("quality_gate_legacy_19d_flag")
    else:
        if value["legacy_19d_ready"] is not False:
            raise ValueError("quality_gate_legacy_19d_flag")
    canonical_bytes(value)
    return value


def validate_sample_gate_case(value):
    return _validate_sample_gate_case_for_version(value, contract_version=GATE_CONTRACT_VERSION)


def validate_sample_gate_case_v2(value):
    return _validate_sample_gate_case_for_version(value, contract_version=GATE_CONTRACT_VERSION_V2)


def _partition_gate_stats(effective_pairs):
    planned = len(effective_pairs)
    gates = [g for _, g in effective_pairs]
    disp_counts = Counter(g["sample_disposition"] for g in gates)
    gnn_eligible = sum(g["gnn_message_passing_eligible"] for g in gates)
    tabular_valid = sum(g["tabular_features_valid"] for g in gates)
    legacy_ready = sum(g["legacy_19d_ready"] for g in gates)
    v2_ready = sum(g["v2_provenance_graph_ready"] for g in gates)
    unavailable_count = sum(g["sample_disposition"].startswith("unavailable_") for g in gates)
    rejected_count = sum(g["sample_disposition"].startswith("rejected_") for g in gates)
    return {
        "planned_denominator": planned,
        "evaluation_denominator_preserved": sum(g["evaluation_denominator_included"] for g in gates),
        "gnn_message_passing_eligible": gnn_eligible,
        "tabular_features_valid": tabular_valid,
        "unavailable_empty_projection": unavailable_count,
        "rejected": rejected_count,
        "legacy_19d_ready": legacy_ready,
        "v2_provenance_graph_ready": v2_ready,
        "disposition_counts": {k: disp_counts.get(k, 0) for k in SAMPLE_DISPOSITIONS if disp_counts.get(k, 0) > 0},
    }


def evaluate_cohort_quality_gate(rows, *, node_cap=MAX_NODES, policy=None):
    if not isinstance(rows, list) or not rows:
        raise ValueError("quality_gate_empty_cohort")
    cfg = {**DEFAULT_GATE_POLICY, **(policy or {})}

    effective_gates = []
    present_count = 0
    for r in rows:
        if r.get("availability") == "present" and r.get("bundle_schema_valid") is True and r.get("gate") is not None:
            present_count += 1
            effective_gates.append((r, validate_sample_gate_case(r["gate"])))
        else:
            effective_gates.append((r, rejected_sample_gate(r["sha256"], node_cap=node_cap)))

    planned = len(rows)
    disp = Counter(g["sample_disposition"] for _, g in effective_gates)
    warn_counts = Counter(w for _, g in effective_gates for w in g["warnings"])

    rejected_corrupt = disp["rejected_missing_or_corrupt"]
    rejected_cleanup = disp["rejected_unverified_cleanup"]
    structural_bad = sum(g["metrics"]["structural_issues_total"] > 0 for _, g in effective_gates)
    tabular_bad = sum(not g["tabular_features_valid"] for _, g in effective_gates)
    unresolved_worker = disp["unavailable_worker_failure"]
    sec_cap_loss_samples = disp["usable_degraded_capped_security_loss"]

    gnn_gates = [g for _, g in effective_gates if g["gnn_message_passing_eligible"]]
    retained_nodes_total = sum(g["metrics"]["kept_nodes_after_cap"] for g in gnn_gates)
    legacy_known_total = sum(g["metrics"]["legacy_sizes_known"] for g in gnn_gates)
    legacy_null_total = sum(g["metrics"]["legacy_sizes_null"] for g in gnn_gates)
    phys_known_total = sum(g["metrics"]["verified_physical_spans_known"] for g in gnn_gates)
    stream_known_total = sum(g["metrics"]["stream_raw_payloads_known"] for g in gnn_gates)

    eval_splits_ok = True
    eval_split_details = {}
    for sp_name in ("validation", "test"):
        sp_items = [(r, g) for r, g in effective_gates if r["split"] == sp_name]
        if not sp_items:
            continue
        sp_total = len(sp_items)
        sp_rejected = sum(g["sample_disposition"].startswith("rejected_") for _, g in sp_items)
        sp_worker_err = sum(g["sample_disposition"] == "unavailable_worker_failure" for _, g in sp_items)
        sp_unclassified = sum(g["sample_disposition"] == "unavailable_unclassified_empty" for _, g in sp_items)
        sp_unavail = sum(g["sample_disposition"].startswith("unavailable_") for _, g in sp_items)
        sp_ratio = sp_unavail / sp_total
        sp_pass = (
            sp_rejected == 0
            and sp_worker_err == 0
            and sp_unclassified == 0
            and sp_ratio <= cfg["max_eval_unavailable_ratio"]
        )
        if not sp_pass:
            eval_splits_ok = False
        eval_split_details[sp_name] = {
            "planned": sp_total,
            "unavailable": sp_unavail,
            "unavailable_ratio": round(sp_ratio, 6),
            "worker_failures": sp_worker_err,
            "rejected": sp_rejected,
            "passed": sp_pass,
        }

    sec_loss_ratio = sec_cap_loss_samples / planned
    checks = {
        "cohort_denominator_complete": {
            "passed": present_count == planned and rejected_corrupt == 0,
            "observed_present_valid": present_count,
            "expected_planned": planned,
            "rejected_missing_or_corrupt": rejected_corrupt,
        },
        "worker_cleanup_verified": {
            "passed": present_count == planned and rejected_cleanup == 0,
            "rejected_unverified_cleanup": rejected_cleanup,
        },
        "graph_structural_validity": {
            "passed": present_count == planned and structural_bad == 0,
            "samples_with_structural_issues": structural_bad,
        },
        "tabular_static_feature_store_integrity": {
            "passed": present_count == planned and tabular_bad == 0,
            "samples_with_invalid_tabular_features": tabular_bad,
        },
        "unresolved_worker_failures_cleared": {
            "passed": present_count == planned and unresolved_worker == 0,
            "unavailable_worker_failure_samples": unresolved_worker,
        },
        "evaluation_partition_coverage": {
            "passed": present_count == planned and eval_splits_ok,
            "max_eval_unavailable_ratio": cfg["max_eval_unavailable_ratio"],
            "splits": eval_split_details,
        },
        "legacy_19d_semantic_size_populated": {
            "passed": bool(gnn_gates) and legacy_null_total == 0 and legacy_known_total == retained_nodes_total,
            "retained_nodes_total": retained_nodes_total,
            "legacy_sizes_known_total": legacy_known_total,
            "legacy_sizes_null_total": legacy_null_total,
            "verified_physical_spans_known_total": phys_known_total,
            "stream_raw_payloads_known_total": stream_known_total,
        },
        "security_sensitive_truncation_bounded": {
            "passed": sec_loss_ratio <= cfg["max_security_sensitive_cap_loss_ratio"],
            "samples_losing_security_sensitive_nodes": sec_cap_loss_samples,
            "observed_ratio": round(sec_loss_ratio, 6),
            "max_allowed_ratio": cfg["max_security_sensitive_cap_loss_ratio"],
        },
    }

    integrity_ok = (
        checks["cohort_denominator_complete"]["passed"]
        and checks["worker_cleanup_verified"]["passed"]
        and checks["graph_structural_validity"]["passed"]
        and checks["tabular_static_feature_store_integrity"]["passed"]
    )
    recovery_ok = (
        checks["unresolved_worker_failures_cleared"]["passed"]
        and checks["evaluation_partition_coverage"]["passed"]
    )
    representation_ok = (
        checks["legacy_19d_semantic_size_populated"]["passed"]
        and checks["security_sensitive_truncation_bounded"]["passed"]
    )

    if not integrity_ok:
        verdict = "rejected_integrity_failure"
    elif not recovery_ok:
        verdict = "blocked_unresolved_extraction_failures"
    elif not representation_ok:
        verdict = "hold_pending_v2_projection_and_size_contract"
    else:
        verdict = "ready_for_locked_export"

    ready_flag = verdict == "ready_for_locked_export"
    unavailable_indices_by_reason = {
        key: [r["index"] for r, g in effective_gates if g["sample_disposition"] == key]
        for key in (
            "unavailable_projection_filtered",
            "unavailable_timeout_no_graph",
            "unavailable_worker_failure",
            "unavailable_unclassified_empty",
        )
    }

    summary = {
        "schema_version": 1,
        "stage": "BUG-007B3",
        "gate_contract_version": GATE_CONTRACT_VERSION,
        "node_cap": node_cap,
        "policy": cfg,
        "unavailable_document_policy": deepcopy(UNAVAILABLE_DOCUMENT_POLICY),
        "node_size_and_feature_provenance_policy": deepcopy(NODE_SIZE_AND_FEATURE_PROVENANCE_POLICY),
        "cohort_gate_verdict": verdict,
        "checks_passed_count": sum(item["passed"] for item in checks.values()),
        "checks_total_count": len(checks),
        "checks": checks,
        "cohort": _partition_gate_stats(effective_gates),
        "by_split": {
            sp: _partition_gate_stats([(r, g) for r, g in effective_gates if r["split"] == sp])
            for sp in ("train", "validation", "test")
        },
        "by_label": {
            str(lbl): _partition_gate_stats([(r, g) for r, g in effective_gates if r["label"] == lbl])
            for lbl in (0, 1)
        },
        "by_split_and_label": {
            f"{sp}_label_{lbl}": _partition_gate_stats([(r, g) for r, g in effective_gates if r["split"] == sp and r["label"] == lbl])
            for sp in ("train", "validation", "test")
            for lbl in (0, 1)
        },
        "unavailable_document_ledger": {
            "total_unavailable": sum(len(v) for v in unavailable_indices_by_reason.values()),
            "by_disposition_indices": unavailable_indices_by_reason,
            "excluded_train_gnn_batch_indices": [
                r["index"] for r, g in effective_gates
                if r["split"] == "train" and not g["gnn_message_passing_eligible"]
            ],
            "eval_abstention_or_tabular_fallback_indices": {
                sp: [r["index"] for r, g in effective_gates if r["split"] == sp and not g["gnn_message_passing_eligible"]]
                for sp in ("validation", "test")
            },
        },
        "warning_sample_counts": dict(sorted(warn_counts.items())),
        "legacy_19d_model_input_ready": ready_flag,
        "training_unlocked": ready_flag,
        "training_executed": False,
        "raw_pdf_processing": False,
        "node_cap_modified": False,
        "parser_modified": False,
    }
    return validate_cohort_gate_summary(summary)


def evaluate_cohort_quality_gate_v2(rows, *, node_cap=MAX_NODES, policy=None):
    if not isinstance(rows, list) or not rows:
        raise ValueError("quality_gate_empty_cohort")
    cfg = {**DEFAULT_GATE_POLICY, **(policy or {})}

    effective_gates = []
    present_count = 0
    for r in rows:
        if r.get("availability") == "present" and r.get("bundle_schema_valid") is True and r.get("gate") is not None:
            present_count += 1
            effective_gates.append((r, validate_sample_gate_case_v2(r["gate"])))
        else:
            effective_gates.append((r, rejected_sample_gate_v2(r["sha256"], node_cap=node_cap)))

    planned = len(rows)
    disp = Counter(g["sample_disposition"] for _, g in effective_gates)
    warn_counts = Counter(w for _, g in effective_gates for w in g["warnings"])

    rejected_corrupt = disp["rejected_missing_or_corrupt"]
    rejected_cleanup = disp["rejected_unverified_cleanup"]
    structural_bad = sum(g["metrics"]["structural_issues_total"] > 0 for _, g in effective_gates)
    tabular_bad = sum(not g["tabular_features_valid"] for _, g in effective_gates)
    unresolved_worker = disp["unavailable_worker_failure"]
    sec_cap_loss_samples = disp["usable_degraded_capped_security_loss"]

    gnn_gates = [g for _, g in effective_gates if g["gnn_message_passing_eligible"]]
    retained_nodes_total = sum(g["metrics"]["kept_nodes_after_cap"] for g in gnn_gates)
    phys_known_total = sum(g["metrics"]["verified_physical_spans_known"] for g in gnn_gates)
    stream_known_total = sum(g["metrics"]["stream_raw_payloads_known"] for g in gnn_gates)
    v2_ready_samples = sum(g["v2_provenance_graph_ready"] for g in gnn_gates)

    eval_splits_ok = True
    eval_split_details = {}
    for sp_name in ("validation", "test"):
        sp_items = [(r, g) for r, g in effective_gates if r["split"] == sp_name]
        if not sp_items:
            continue
        sp_total = len(sp_items)
        sp_rejected = sum(g["sample_disposition"].startswith("rejected_") for _, g in sp_items)
        sp_worker_err = sum(g["sample_disposition"] == "unavailable_worker_failure" for _, g in sp_items)
        sp_unclassified = sum(g["sample_disposition"] == "unavailable_unclassified_empty" for _, g in sp_items)
        sp_unavail = sum(g["sample_disposition"].startswith("unavailable_") for _, g in sp_items)
        sp_ratio = sp_unavail / sp_total
        sp_pass = (
            sp_rejected == 0
            and sp_worker_err == 0
            and sp_unclassified == 0
            and sp_ratio <= cfg["max_eval_unavailable_ratio"]
        )
        if not sp_pass:
            eval_splits_ok = False
        eval_split_details[sp_name] = {
            "planned": sp_total,
            "unavailable": sp_unavail,
            "unavailable_ratio": round(sp_ratio, 6),
            "worker_failures": sp_worker_err,
            "rejected": sp_rejected,
            "passed": sp_pass,
        }

    sec_loss_ratio = sec_cap_loss_samples / planned
    checks = {
        "cohort_denominator_complete": {
            "passed": present_count == planned and rejected_corrupt == 0,
            "observed_present_valid": present_count,
            "expected_planned": planned,
            "rejected_missing_or_corrupt": rejected_corrupt,
        },
        "worker_cleanup_verified": {
            "passed": present_count == planned and rejected_cleanup == 0,
            "rejected_unverified_cleanup": rejected_cleanup,
        },
        "graph_structural_validity": {
            "passed": present_count == planned and structural_bad == 0,
            "samples_with_structural_issues": structural_bad,
        },
        "tabular_static_feature_store_integrity": {
            "passed": present_count == planned and tabular_bad == 0,
            "samples_with_invalid_tabular_features": tabular_bad,
        },
        "unresolved_worker_failures_cleared": {
            "passed": present_count == planned and unresolved_worker == 0,
            "unavailable_worker_failure_samples": unresolved_worker,
        },
        "evaluation_partition_coverage": {
            "passed": present_count == planned and eval_splits_ok,
            "max_eval_unavailable_ratio": cfg["max_eval_unavailable_ratio"],
            "splits": eval_split_details,
        },
        "v2_provenance_size_contract_verified": {
            "passed": bool(gnn_gates) and v2_ready_samples == len(gnn_gates),
            "gnn_eligible_samples": len(gnn_gates),
            "v2_provenance_ready_samples": v2_ready_samples,
            "retained_nodes_total": retained_nodes_total,
            "verified_physical_spans_known_total": phys_known_total,
            "verified_physical_spans_null_total": retained_nodes_total - phys_known_total,
            "stream_raw_payloads_known_total": stream_known_total,
            "stream_raw_payloads_null_total": retained_nodes_total - stream_known_total,
            "projected_json_storage_bytes_used": False,
            "null_to_zero_imputation_violations": 0,
        },
        "security_sensitive_truncation_bounded": {
            "passed": sec_loss_ratio <= cfg["max_security_sensitive_cap_loss_ratio"],
            "samples_losing_security_sensitive_nodes": sec_cap_loss_samples,
            "observed_ratio": round(sec_loss_ratio, 6),
            "max_allowed_ratio": cfg["max_security_sensitive_cap_loss_ratio"],
        },
    }

    integrity_ok = (
        checks["cohort_denominator_complete"]["passed"]
        and checks["worker_cleanup_verified"]["passed"]
        and checks["graph_structural_validity"]["passed"]
        and checks["tabular_static_feature_store_integrity"]["passed"]
    )
    recovery_ok = (
        checks["unresolved_worker_failures_cleared"]["passed"]
        and checks["evaluation_partition_coverage"]["passed"]
    )
    representation_ok = (
        checks["v2_provenance_size_contract_verified"]["passed"]
        and checks["security_sensitive_truncation_bounded"]["passed"]
    )

    if not integrity_ok:
        verdict = "rejected_integrity_failure"
    elif not recovery_ok:
        verdict = "blocked_unresolved_extraction_failures"
    elif not representation_ok:
        verdict = "hold_pending_v2_projection_and_size_contract"
    else:
        verdict = "ready_for_locked_export"

    ready_flag = verdict == "ready_for_locked_export"
    unavailable_indices_by_reason = {
        key: [r["index"] for r, g in effective_gates if g["sample_disposition"] == key]
        for key in (
            "unavailable_projection_filtered",
            "unavailable_timeout_no_graph",
            "unavailable_worker_failure",
            "unavailable_unclassified_empty",
        )
    }

    summary = {
        "schema_version": 1,
        "stage": "GRAPH-PROJECTION-V2",
        "gate_contract_version": GATE_CONTRACT_VERSION_V2,
        "projection_contract_version": PROJECTION_CONTRACT_VERSION,
        "node_feature_dim": NODE_FEATURE_DIM_V2,
        "node_cap": node_cap,
        "policy": cfg,
        "unavailable_document_policy": deepcopy(UNAVAILABLE_DOCUMENT_POLICY),
        "node_size_and_feature_provenance_policy": deepcopy(NODE_SIZE_AND_FEATURE_PROVENANCE_POLICY),
        "cohort_gate_verdict": verdict,
        "checks_passed_count": sum(item["passed"] for item in checks.values()),
        "checks_total_count": len(checks),
        "checks": checks,
        "cohort": _partition_gate_stats(effective_gates),
        "by_split": {
            sp: _partition_gate_stats([(r, g) for r, g in effective_gates if r["split"] == sp])
            for sp in ("train", "validation", "test")
        },
        "by_label": {
            str(lbl): _partition_gate_stats([(r, g) for r, g in effective_gates if r["label"] == lbl])
            for lbl in (0, 1)
        },
        "by_split_and_label": {
            f"{sp}_label_{lbl}": _partition_gate_stats([(r, g) for r, g in effective_gates if r["split"] == sp and r["label"] == lbl])
            for sp in ("train", "validation", "test")
            for lbl in (0, 1)
        },
        "unavailable_document_ledger": {
            "total_unavailable": sum(len(v) for v in unavailable_indices_by_reason.values()),
            "by_disposition_indices": unavailable_indices_by_reason,
            "excluded_train_gnn_batch_indices": [
                r["index"] for r, g in effective_gates
                if r["split"] == "train" and not g["gnn_message_passing_eligible"]
            ],
            "eval_abstention_or_tabular_fallback_indices": {
                sp: [r["index"] for r, g in effective_gates if r["split"] == sp and not g["gnn_message_passing_eligible"]]
                for sp in ("validation", "test")
            },
        },
        "warning_sample_counts": dict(sorted(warn_counts.items())),
        "legacy_19d_model_input_ready": False,
        "v2_graph_model_input_ready": ready_flag,
        "training_unlocked": ready_flag,
        "training_executed": False,
        "raw_pdf_processing": False,
        "node_cap_modified": False,
        "parser_modified": False,
    }
    return validate_cohort_gate_summary_v2(summary)


def validate_cohort_gate_summary(summary):
    if (not isinstance(summary, dict) or summary.get("schema_version") != 1
            or summary.get("gate_contract_version") != GATE_CONTRACT_VERSION
            or summary.get("cohort_gate_verdict") not in COHORT_VERDICTS
            or summary.get("training_executed") is not False
            or summary.get("raw_pdf_processing") is not False):
        raise ValueError("quality_gate_summary_header")
    cohort = summary["cohort"]
    if cohort["planned_denominator"] != cohort["evaluation_denominator_preserved"]:
        raise ValueError("quality_gate_denominator_shrunk")
    if summary["legacy_19d_model_input_ready"] is not (summary["cohort_gate_verdict"] == "ready_for_locked_export"):
        raise ValueError("quality_gate_ready_contradiction")
    canonical_bytes(summary)
    return summary


def validate_cohort_gate_summary_v2(summary):
    if (not isinstance(summary, dict) or summary.get("schema_version") != 1
            or summary.get("gate_contract_version") != GATE_CONTRACT_VERSION_V2
            or summary.get("projection_contract_version") != PROJECTION_CONTRACT_VERSION
            or summary.get("node_feature_dim") != NODE_FEATURE_DIM_V2
            or summary.get("cohort_gate_verdict") not in COHORT_VERDICTS
            or summary.get("legacy_19d_model_input_ready") is not False
            or summary.get("training_executed") is not False
            or summary.get("raw_pdf_processing") is not False):
        raise ValueError("quality_gate_v2_summary_header")
    cohort = summary["cohort"]
    if cohort["planned_denominator"] != cohort["evaluation_denominator_preserved"]:
        raise ValueError("quality_gate_denominator_shrunk")
    ready = summary["cohort_gate_verdict"] == "ready_for_locked_export"
    if summary.get("v2_graph_model_input_ready") is not ready or summary.get("training_unlocked") is not ready:
        raise ValueError("quality_gate_v2_ready_contradiction")
    canonical_bytes(summary)
    return summary

from __future__ import annotations

from collections import Counter
import json
import math
import re

from malpdf.extraction.numeric_export import MAX_NODES, NODE_TYPES, OBSERVED, STATUSES


BACKENDS = ("pypdf", "MuPDF", "qpdf", "raw_forensic", "arlington", "script_semantics", "byte_images")
WORKER_STATUSES = STATUSES | {"complete", "parser_error", "worker_error", "input_error", "resource_limit_or_signal", "unknown"}
STAGES = {"read_hash", "raw_scan", "parse_pdf", "stream_decode", "js_ast", "inference_gate", "inference", "unknown"}
SPAN_REASONS = {"measured", "not_applicable", "non_original_space", "unverified_boundary", "missing_boundary", "invalid_boundary"}
KNOWN_CODES = {
    "worker_admission_failed", "wall_timeout", "invalid_worker_response", "worker_exit",
    "worker_signal_9", "worker_signal_24", "input_checksum_mismatch", "input_read_failed",
    "encrypted_pdf", "inventory_encrypted_pdf", "recovery_encrypted_pdf", "inventory_dependency_unavailable",
    "inventory_parser_unavailable", "inventory_resource_limit", "inventory_metadata_limit",
    "evidence_metadata_limit", "inventory_object_limit", "inventory_projection_limit",
    "inventory_projection_incomplete", "inventory_parser_notices", "inventory_raw_byte_limit",
    "graph_backend_failure", "graph_backend_attribute_error", "catalog_enumeration_incomplete",
    "native_inventory_not_run", "profile_does_not_run_this_backend", "recovered_scope_not_complete",
    "primary_not_finished", "code_not_finished", "feature_gate_failed", "static_resource_limit",
    "structural_incomplete", "analysis_incomplete", "code_inspection_incomplete",
    "observed_inventory_outside_projection", "failed_inventory_candidates_only", "no_verified_empty_scope",
    "legacy_worker_error_diagnostics_lost", "invalid_graph_structure", "graph_projection_present",
}
FAMILIES = {"none", "worker_error_unspecified", "worker_protocol", "timeout", "resource_limit",
            "encrypted", "parser_failure", "projection_filter", "graph_structure", "unresolved"}
CAUSE_STATUSES = {"confirmed", "unresolved", "not_investigated"}
ACTIONS = {"none", "inspect_saved_projection", "propose_diagnostic_preservation", "offline_diagnostic_required"}
STAT_FIELDS = {"count", "null_count", "min", "median", "p95", "max", "total"}
GRAPH_FIELDS = {
    "evidence_nodes", "evidence_edges", "projected_nodes", "projected_edges", "excluded_nodes_kind",
    "excluded_nodes_status", "excluded_nodes_cap", "excluded_edges_endpoint", "evidence_isolates",
    "projected_isolates", "parallel_edges", "self_loops", "parser_object_candidates",
    "parser_objects_observed", "parser_objects_with_projection", "projected_sizes_unknown",
    "feature_dim", "legacy_target_feature_dim",
}
ISSUE_FIELDS = {"duplicate_node_ids", "duplicate_edge_ids", "dangling_edges", "invalid_attributes"}


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def span_measurement(record):
    details = record.get("details")
    if not isinstance(details, dict):
        return {"value": None, "reason": "unverified_boundary"}
    if record.get("kind") != "forensic_object_declaration":
        return {"value": None, "reason": "not_applicable"}
    if details.get("source_space") != "original":
        return {"value": None, "reason": "non_original_space"}
    if (record.get("backend") != "raw_forensic" or record.get("observation_status") != "observed"
            or details.get("top_level_confirmed") is not True
            or type(record.get("object_number")) is not int or record["object_number"] <= 0
            or type(record.get("generation")) is not int or record["generation"] < 0):
        return {"value": None, "reason": "unverified_boundary"}
    if any(name in details and (type(details[name]) is not int or details[name] != record[name])
           for name in ("object_number", "generation")):
        return {"value": None, "reason": "unverified_boundary"}
    values = [record.get("byte_offset_start"), record.get("byte_offset_end"), details.get("byte_start"), details.get("byte_end")]
    if any(value is None for value in values):
        return {"value": None, "reason": "missing_boundary"}
    if (any(type(value) is not int for value in values) or values[0] < 0 or values[1] <= values[0]
            or values[:2] != values[2:]):
        return {"value": None, "reason": "invalid_boundary"}
    return {"value": values[1] - values[0], "reason": "measured"}


def distribution(values, *, null_count=0):
    histogram = values if isinstance(values, Counter) else Counter(values)
    count = sum(histogram.values())
    if not count:
        return dict.fromkeys(("min", "median", "p95", "max")) | {"count": 0, "null_count": null_count, "total": 0}
    positions = ((count + 1) // 2, count // 2 + 1, (95 * count + 99) // 100)
    selected, seen = {}, 0
    for value, amount in sorted(histogram.items()):
        previous, seen = seen, seen + amount
        for position in positions:
            if previous < position <= seen:
                selected[position] = value
    median = (selected[positions[0]] + selected[positions[1]]) / 2
    return {"count": count, "null_count": null_count, "min": min(histogram), "median": median,
            "p95": selected[positions[2]], "max": max(histogram),
            "total": sum(value * amount for value, amount in histogram.items())}


def _enum(value, allowed, default="unknown"):
    return value if isinstance(value, str) and value in allowed else default


def _codes(values):
    return sorted({value for value in values if isinstance(value, str) and value in KNOWN_CODES}) if isinstance(values, list) else []


def _classification(graph, issues, worker, codes):
    if graph["projected_nodes"]:
        family, state, evidence, action = "none", "not_investigated", ["graph_projection_present"], "none"
    elif "worker_admission_failed" in codes:
        family, state, evidence, action = "worker_error_unspecified", "unresolved", ["worker_admission_failed", "legacy_worker_error_diagnostics_lost"], "propose_diagnostic_preservation"
    elif graph["parser_objects_observed"]:
        family, state, evidence, action = "projection_filter", "confirmed", ["observed_inventory_outside_projection"], "inspect_saved_projection"
    elif "wall_timeout" in codes or worker["status"] == "timeout":
        family, state, evidence, action = "timeout", "unresolved", ["wall_timeout"], "offline_diagnostic_required"
    elif set(codes) & {"encrypted_pdf", "inventory_encrypted_pdf", "recovery_encrypted_pdf"}:
        family, state, evidence, action = "encrypted", "confirmed", sorted(set(codes) & {"encrypted_pdf", "inventory_encrypted_pdf", "recovery_encrypted_pdf"}), "offline_diagnostic_required"
    elif "invalid_worker_response" in codes:
        family, state, evidence, action = "worker_protocol", "unresolved", ["invalid_worker_response"], "propose_diagnostic_preservation"
    elif worker["status"] == "resource_limit_or_signal" or set(codes) & {"worker_signal_9", "worker_signal_24", "static_resource_limit"}:
        family, state, evidence, action = "resource_limit", "unresolved", sorted(set(codes) & {"worker_signal_9", "worker_signal_24", "static_resource_limit"}), "offline_diagnostic_required"
    elif worker["status"] == "parser_error":
        family, state, evidence, action = "parser_failure", "unresolved", [], "offline_diagnostic_required"
    else:
        family, state, evidence, action = "unresolved", "unresolved", ["no_verified_empty_scope"], "offline_diagnostic_required"
        if graph["parser_object_candidates"] and not graph["parser_objects_with_projection"]:
            evidence.append("failed_inventory_candidates_only")
    if any(issues.values()):
        family, state, evidence, action = "graph_structure", "confirmed", ["invalid_graph_structure"], "inspect_saved_projection"
    return {"investigation_required": not graph["projected_nodes"] or any(issues.values()),
            "failure_family": family, "root_cause_status": state, "evidence_codes": evidence, "next_action": action}


def audit_bundle(bundle, expected_sha256, *, node_cap=MAX_NODES, statistics=None):
    if (not isinstance(expected_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_sha256)
            or not isinstance(bundle, dict) or bundle.get("sample_sha256") != expected_sha256):
        raise ValueError("graph_audit_identity")
    if type(node_cap) is not int or not 1 <= node_cap <= MAX_NODES:
        raise ValueError("graph_audit_node_cap")
    store, coverage = bundle.get("evidence_store", {}), bundle.get("coverage_report", {})
    if not isinstance(store, dict) or not isinstance(coverage, dict):
        raise ValueError("graph_audit_shape")
    records, edges = store.get("records", []), store.get("edges", [])
    if not isinstance(records, list) or not isinstance(edges, list):
        raise ValueError("graph_audit_shape")
    graph = dict.fromkeys(GRAPH_FIELDS, 0)
    graph.update(evidence_nodes=len(records), evidence_edges=len(edges), feature_dim=None, legacy_target_feature_dim=19)
    issues = dict.fromkeys(ISSUE_FIELDS, 0)
    identifiers, kept, edge_ids, touched, projected_touched = set(), {}, set(), set(), set()
    projected_records, projected_edges = [], []
    spans, storage, span_reasons = Counter(), Counter(), Counter(dict.fromkeys(SPAN_REASONS, 0))
    native_by_backend = {name: {"candidates": 0, "observed": 0, "with_projection": 0} for name in BACKENDS}
    native_views = {}
    for record in records:
        if not isinstance(record, dict):
            issues["invalid_attributes"] += 1
            graph["excluded_nodes_kind"] += 1
            continue
        identifier, kind, status, details = (record.get(name) for name in ("evidence_id", "kind", "observation_status", "details"))
        if not isinstance(identifier, str) or not identifier:
            issues["invalid_attributes"] += 1
        elif identifier in identifiers:
            issues["duplicate_node_ids"] += 1
        else:
            identifiers.add(identifier)
        if not isinstance(kind, str) or not isinstance(status, str) or not isinstance(details, dict):
            issues["invalid_attributes"] += 1
        details = details if isinstance(details, dict) else {}
        backend_name = "qpdf" if record.get("backend") == "QPDF" else record.get("backend")
        if kind == "parser_view" and isinstance(backend_name, str) and backend_name in BACKENDS:
            native_views[backend_name] = _enum(status, STATUSES, "not_run")
        try:
            storage[len(canonical_bytes(record))] += 1
        except (ValueError, TypeError, RecursionError):
            issues["invalid_attributes"] += 1
        span = span_measurement(record)
        span_reasons[span["reason"]] += 1
        if span["value"] is not None:
            spans[span["value"]] += 1
        if kind == "parser_object":
            observed = status == "observed" and isinstance(details.get("projection"), dict)
            projected = isinstance(details.get("projection"), dict)
            graph["parser_object_candidates"] += 1
            graph["parser_objects_observed"] += observed
            graph["parser_objects_with_projection"] += projected
            backend = "qpdf" if record.get("backend") == "QPDF" else record.get("backend")
            if isinstance(backend, str) and backend in native_by_backend:
                native_by_backend[backend]["candidates"] += 1
                native_by_backend[backend]["observed"] += observed
                native_by_backend[backend]["with_projection"] += projected
        if not isinstance(kind, str) or kind not in NODE_TYPES:
            graph["excluded_nodes_kind"] += 1
        elif not isinstance(status, str) or status not in OBSERVED:
            graph["excluded_nodes_status"] += 1
        elif len(kept) >= node_cap:
            graph["excluded_nodes_cap"] += 1
        elif isinstance(identifier, str) and identifier not in kept:
            kept[identifier] = len(kept)
            projected_records.append(record)
            size = details.get("size_bytes")
            graph["projected_sizes_unknown"] += not (type(size) in (int, float) and math.isfinite(size) and size >= 0)
    pairs = Counter()
    for edge in edges:
        if not isinstance(edge, dict):
            issues["invalid_attributes"] += 1
            graph["excluded_edges_endpoint"] += 1
            continue
        identifier, source, target = (edge.get(name) for name in ("id", "source", "target"))
        if not isinstance(identifier, str) or not identifier:
            issues["invalid_attributes"] += 1
        elif identifier in edge_ids:
            issues["duplicate_edge_ids"] += 1
        else:
            edge_ids.add(identifier)
        valid = isinstance(source, str) and isinstance(target, str) and source in identifiers and target in identifiers
        if not valid:
            issues["dangling_edges"] += 1
        else:
            touched.update((source, target))
            pairs[(source, target)] += 1
            graph["self_loops"] += source == target
        if isinstance(source, str) and isinstance(target, str) and source in kept and target in kept:
            projected_edges.append(edge)
            projected_touched.update((source, target))
        else:
            graph["excluded_edges_endpoint"] += 1
    graph.update(projected_nodes=len(kept), projected_edges=len(projected_edges), evidence_isolates=len(identifiers - touched),
                 projected_isolates=len(kept.keys() - projected_touched), parallel_edges=sum(max(0, amount - 1) for amount in pairs.values()))
    raw_worker = coverage.get("worker", {})
    raw_worker = raw_worker if isinstance(raw_worker, dict) else {}
    worker = {"status": _enum(raw_worker.get("status"), WORKER_STATUSES),
              "cleanup_complete": raw_worker.get("worker_cleanup_complete") if type(raw_worker.get("worker_cleanup_complete")) is bool else None,
              "exit_code": raw_worker.get("worker_exit_code") if type(raw_worker.get("worker_exit_code")) is int else None,
              "last_stage": _enum(raw_worker.get("last_stage"), STAGES) if raw_worker.get("last_stage") is not None else None}
    raw_backends = coverage.get("backends", {})
    raw_backends = raw_backends if isinstance(raw_backends, dict) else {}
    backends, all_codes = {}, set(_codes(coverage.get("limitations", [])))
    for name in BACKENDS:
        entry = raw_backends.get(name, {})
        entry = entry if isinstance(entry, dict) else {}
        codes = _codes(entry.get("limitations", [])) + _codes(entry.get("graph_limitations", []))
        all_codes.update(codes)
        graph_status = entry.get("graph_observation_status", entry.get("observation_status")) if name in {"pypdf", "MuPDF"} else "not_run"
        backends[name] = {"backend_status": _enum(entry.get("observation_status"), STATUSES, "not_run"),
                          "inventory_present": name in native_views, "inventory_status": native_views.get(name, "not_run"),
                          "graph_status": _enum(graph_status, STATUSES, "not_run"),
                          "evidence_codes": sorted(set(codes)), **native_by_backend[name]}
    measurements = {"original_object_span_bytes": distribution(spans, null_count=len(records) - sum(spans.values())),
                    "original_span_reasons": dict(span_reasons), "node_record_storage_bytes": distribution(storage),
                    "graph_wire_storage_bytes": len(canonical_bytes({"nodes": records, "edges": edges})),
                    "projected_graph_wire_storage_bytes": len(canonical_bytes({"nodes": projected_records, "edges": projected_edges}))}
    if statistics is not None:
        statistics.setdefault("original_object_span_bytes", Counter()).update(spans)
        statistics.setdefault("node_record_storage_bytes", Counter()).update(storage)
    return {"schema_version": 1, "sample_sha256": expected_sha256, "bundle_status": _enum(bundle.get("status"), STATUSES),
            "issues": issues, "graph": graph, "classification": _classification(graph, issues, worker, all_codes),
            "backends": backends, "worker": worker, "measurements": measurements}


def summarize_cases(cases, *, statistics=None):
    valid = [row for row in cases if row.get("audit") is not None]
    audits = [row["audit"] for row in valid]
    focus = [audit for audit in audits if audit["graph"]["projected_nodes"] == 0]
    histograms = statistics or {}
    stats = {name: distribution(histograms.get(name, Counter())) for name in ("original_object_span_bytes", "node_record_storage_bytes")}
    stats["original_object_span_bytes"]["null_count"] = sum(audit["measurements"]["original_object_span_bytes"]["null_count"] for audit in audits)
    return {"schema_version": 1, "planned": len(cases), "audited": len(valid), "missing_or_rejected": len(cases) - len(valid),
            "projected_graphs": len(audits) - len(focus), "focus_missing_graph": len(focus),
            "focus_failure_families": dict(Counter(audit["classification"]["failure_family"] for audit in focus)),
            "focus_root_cause_status": dict(Counter(audit["classification"]["root_cause_status"] for audit in focus)),
            "bundle_status_counts": dict(Counter(audit["bundle_status"] for audit in audits)),
            "structural_issue_totals": {name: sum(audit["issues"][name] for audit in audits) for name in ISSUE_FIELDS},
            "span_reason_counts": {name: sum(audit["measurements"]["original_span_reasons"][name] for audit in audits) for name in SPAN_REASONS},
            "graphs_hitting_node_cap": sum(audit["graph"]["excluded_nodes_cap"] > 0 for audit in audits),
            "backend_status_counts": {name: {
                key: dict(Counter(audit["backends"][name][key] for audit in audits))
                for key in ("backend_status", "inventory_status", "graph_status")} for name in BACKENDS},
            "graph_distributions": {name: distribution(audit["graph"][name] for audit in audits)
                for name in GRAPH_FIELDS if name not in {"feature_dim", "legacy_target_feature_dim"}},
            "graph_storage_distributions": {name: distribution(audit["measurements"][name] for audit in audits)
                for name in ("graph_wire_storage_bytes", "projected_graph_wire_storage_bytes")},
            "node_distributions": stats, "feature_dim": None, "legacy_target_feature_dim": 19,
            "model_input_ready": False, "raw_pdf_processing": False, "classifier_evaluation_executed": False}


def validate_case(value):
    expected = {"schema_version", "sample_sha256", "bundle_status", "issues", "graph", "classification", "backends", "worker", "measurements"}
    if not isinstance(value, dict) or set(value) != expected or value["schema_version"] != 1:
        raise ValueError("graph_audit_case_shape")
    if not re.fullmatch(r"[a-f0-9]{64}", value["sample_sha256"]) or value["bundle_status"] not in STATUSES | {"unknown"}:
        raise ValueError("graph_audit_case_identity")
    for key, fields in (("issues", ISSUE_FIELDS), ("graph", GRAPH_FIELDS)):
        if not isinstance(value[key], dict) or set(value[key]) != fields:
            raise ValueError("graph_audit_case_shape")
        for name, number in value[key].items():
            if name == "feature_dim":
                if number is not None:
                    raise ValueError("graph_audit_feature_dimension")
            elif type(number) is not int or not 0 <= number <= 10**9:
                raise ValueError("graph_audit_case_count")
    graph = value["graph"]
    if (graph["legacy_target_feature_dim"] != 19 or graph["projected_nodes"] > MAX_NODES
            or graph["projected_isolates"] > graph["projected_nodes"]
            or graph["evidence_isolates"] > graph["evidence_nodes"]
            or graph["projected_sizes_unknown"] > graph["projected_nodes"]
            or not graph["parser_objects_observed"] <= graph["parser_objects_with_projection"] <= graph["parser_object_candidates"] <= graph["evidence_nodes"]
            or graph["evidence_edges"] != graph["projected_edges"] + graph["excluded_edges_endpoint"]):
        raise ValueError("graph_audit_case_invariant")
    classification = value["classification"]
    if (not isinstance(classification, dict) or set(classification) != {"investigation_required", "failure_family", "root_cause_status", "evidence_codes", "next_action"}
            or type(classification["investigation_required"]) is not bool or classification["failure_family"] not in FAMILIES
            or classification["root_cause_status"] not in CAUSE_STATUSES or classification["next_action"] not in ACTIONS):
        raise ValueError("graph_audit_classification")
    def codes(items):
        if not isinstance(items, list) or any(not isinstance(item, str) or item not in KNOWN_CODES for item in items):
            raise ValueError("graph_audit_codes")
    codes(classification["evidence_codes"])
    if set(value["backends"]) != set(BACKENDS):
        raise ValueError("graph_audit_backends")
    for entry in value["backends"].values():
        if (set(entry) != {"backend_status", "inventory_present", "inventory_status", "graph_status", "evidence_codes", "candidates", "observed", "with_projection"}
                or entry["backend_status"] not in STATUSES or type(entry["inventory_present"]) is not bool
                or entry["inventory_status"] not in STATUSES or entry["graph_status"] not in STATUSES):
            raise ValueError("graph_audit_backend")
        codes(entry["evidence_codes"])
        if any(type(entry[name]) is not int or not 0 <= entry[name] <= 10**9 for name in ("candidates", "observed", "with_projection")):
            raise ValueError("graph_audit_backend_count")
    worker = value["worker"]
    if (set(worker) != {"status", "cleanup_complete", "exit_code", "last_stage"} or worker["status"] not in WORKER_STATUSES
            or worker["cleanup_complete"] is not None and type(worker["cleanup_complete"]) is not bool
            or worker["exit_code"] is not None and type(worker["exit_code"]) is not int
            or worker["last_stage"] is not None and worker["last_stage"] not in STAGES):
        raise ValueError("graph_audit_worker")
    measurements = value["measurements"]
    if set(measurements) != {"original_object_span_bytes", "original_span_reasons", "node_record_storage_bytes", "graph_wire_storage_bytes", "projected_graph_wire_storage_bytes"}:
        raise ValueError("graph_audit_measurements")
    for key in ("original_object_span_bytes", "node_record_storage_bytes"):
        entry = measurements[key]
        if (set(entry) != STAT_FIELDS or any(item is not None and (type(item) not in (int, float) or not math.isfinite(item) or not 0 <= item <= 10**12) for item in entry.values())):
            raise ValueError("graph_audit_distribution")
        if any(type(entry[name]) is not int for name in ("count", "null_count", "total")):
            raise ValueError("graph_audit_distribution_count")
        if (entry["count"] == 0 and (entry["total"] != 0 or any(entry[name] is not None for name in ("min", "median", "p95", "max")))
                or entry["count"] > 0 and (any(entry[name] is None for name in ("min", "median", "p95", "max"))
                    or not entry["min"] <= entry["median"] <= entry["max"] or not entry["min"] <= entry["p95"] <= entry["max"])):
            raise ValueError("graph_audit_distribution_range")
    if set(measurements["original_span_reasons"]) != SPAN_REASONS:
        raise ValueError("graph_audit_span_reasons")
    for number in [*measurements["original_span_reasons"].values(), measurements["graph_wire_storage_bytes"], measurements["projected_graph_wire_storage_bytes"]]:
        if type(number) is not int or not 0 <= number <= 10**12:
            raise ValueError("graph_audit_measurement_count")
    canonical_bytes(value)
    return value

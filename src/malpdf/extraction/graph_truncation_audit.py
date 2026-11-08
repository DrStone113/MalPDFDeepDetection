from __future__ import annotations

from collections import Counter, deque
import math
import re

from malpdf.extraction.graph_audit import canonical_bytes, distribution, span_measurement
from malpdf.extraction.numeric_export import EDGE_TYPES, MAX_EDGES, MAX_NODES, NODE_TYPES, OBSERVED, STATUSES


CONTRACT_VERSION = "pdf-graph-truncation-audit-v1"
QUALITY_CONTRACT_VERSION = "pdf-extraction-quality-v1"
HASH_RE = re.compile(r"[a-f0-9]{64}\Z")
SECURITY_SENSITIVE_KINDS = ("action", "script", "annotation", "filespec", "stream")
ORIGIN_BUCKETS = ("indirect_pypdf", "direct_pypdf", "indirect_mupdf", "direct_mupdf", "other")
SPAN_PROVENANCE_REASONS = (
    "measured",
    "direct_inline_object",
    "synthetic_repaired_backend",
    "script_derived_node",
    "missing_verified_header_offset",
    "no_matching_confirmed_original_declaration",
    "ambiguous_declaration_match",
)
GRAPH_STATES = frozenset({
    "nonempty_uncapped",
    "nonempty_capped",
    "empty_projection_filtered",
    "empty_timeout",
    "empty_worker_error",
    "empty_other",
})
EXTRACTION_STATUSES = frozenset({"complete", "bounded_complete", "timeout_partial", "failed", "unknown"})


def _finite_nonneg(value):
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 1e100


def _stats(values, *, null_count):
    base = distribution([int(v) if type(v) is int else v for v in values], null_count=null_count)
    return {
        "known_count": base["count"],
        "null_count": base["null_count"],
        "min": base["min"],
        "median": base["median"],
        "p95": base["p95"],
        "max": base["max"],
        "total": base["total"],
    }


def _origin_bucket(record):
    backend = record.get("backend")
    indirect = type(record.get("object_number")) is int and record["object_number"] > 0
    if backend == "pypdf" and record.get("is_synthetic_repaired") is not True:
        return "indirect_pypdf" if indirect else "direct_pypdf"
    if backend == "MuPDF" or record.get("is_synthetic_repaired") is True:
        return "indirect_mupdf" if indirect else "direct_mupdf"
    return "other"


def _wcc_labels(num_nodes, undirected_adj):
    labels = [-1] * num_nodes
    components = 0
    for start in range(num_nodes):
        if labels[start] != -1:
            continue
        labels[start] = components
        queue = deque([start])
        while queue:
            cur = queue.popleft()
            for nxt in undirected_adj[cur]:
                if labels[nxt] == -1:
                    labels[nxt] = components
                    queue.append(nxt)
        components += 1
    return components, labels


def _reachable_from_roots(roots, directed_adj):
    visited = set(roots)
    queue = deque(roots)
    while queue:
        cur = queue.popleft()
        for nxt in directed_adj[cur]:
            if nxt not in visited:
                visited.add(nxt)
                queue.append(nxt)
    return visited


def _confirmed_declarations(records):
    by_key = {}
    for record in records:
        if not isinstance(record, dict) or record.get("kind") != "forensic_object_declaration":
            continue
        measured = span_measurement(record)
        if measured["reason"] != "measured" or measured["value"] is None:
            continue
        key = (record["object_number"], record["generation"], record["byte_offset_start"])
        by_key.setdefault(key, []).append(measured["value"])
    return by_key


def _physical_span_for_node(record, decl_index):
    if record.get("kind") == "script":
        return None, "script_derived_node"
    if record.get("backend") != "pypdf" or record.get("is_synthetic_repaired") is True:
        return None, "synthetic_repaired_backend"
    number, generation = record.get("object_number"), record.get("generation")
    if number is None and generation is None:
        return None, "direct_inline_object"
    if type(number) is not int or number <= 0 or type(generation) is not int or generation < 0:
        return None, "direct_inline_object"
    offset = record.get("byte_offset_start")
    if type(offset) is not int or offset < 0:
        return None, "missing_verified_header_offset"
    matches = decl_index.get((number, generation, offset), [])
    if not matches:
        return None, "no_matching_confirmed_original_declaration"
    unique = set(matches)
    if len(unique) > 1:
        return None, "ambiguous_declaration_match"
    return matches[0], "measured"


def _graph_state(kept_count, is_capped, parser_observed, bundle_status, worker_status, limitations):
    if kept_count > 0:
        return "nonempty_capped" if is_capped else "nonempty_uncapped"
    codes = set(limitations)
    if "worker_admission_failed" in codes or worker_status == "worker_error":
        return "empty_worker_error"
    if parser_observed > 0:
        return "empty_projection_filtered"
    if bundle_status == "timeout" or worker_status == "timeout" or "wall_timeout" in codes:
        return "empty_timeout"
    return "empty_other"


def audit_truncation_bundle(bundle, expected_sha256, *, node_cap=MAX_NODES):
    if (not isinstance(expected_sha256, str) or not HASH_RE.fullmatch(expected_sha256)
            or not isinstance(bundle, dict) or bundle.get("sample_sha256") != expected_sha256):
        raise ValueError("truncation_audit_identity")
    if type(node_cap) is not int or not 1 <= node_cap <= MAX_NODES:
        raise ValueError("truncation_audit_node_cap")
    store = bundle.get("evidence_store")
    coverage = bundle.get("coverage_report")
    if not isinstance(store, dict) or not isinstance(coverage, dict):
        raise ValueError("truncation_audit_shape")
    records = store.get("records", [])
    edges = store.get("edges", [])
    if not isinstance(records, list) or not isinstance(edges, list):
        raise ValueError("truncation_audit_shape")

    decl_index = _confirmed_declarations(records)
    by_kind = {name: {"eligible": 0, "kept": 0, "dropped_cap": 0} for name in NODE_TYPES}
    by_origin = {name: {"eligible": 0, "kept": 0, "dropped_cap": 0} for name in ORIGIN_BUCKETS}

    excluded_kind = 0
    excluded_status = 0
    duplicate_eligible = 0
    eligible_index = {}
    eligible_records = []
    parser_candidates = 0
    parser_observed = 0

    for record in records:
        if not isinstance(record, dict):
            excluded_kind += 1
            continue
        kind = record.get("kind")
        status = record.get("observation_status")
        details = record.get("details") if isinstance(record.get("details"), dict) else {}
        if kind == "parser_object":
            parser_candidates += 1
            if status == "observed" and isinstance(details.get("projection"), dict):
                parser_observed += 1
        if not isinstance(kind, str) or kind not in NODE_TYPES:
            excluded_kind += 1
            continue
        if not isinstance(status, str) or status not in OBSERVED:
            excluded_status += 1
            continue
        identifier = record.get("evidence_id")
        if not isinstance(identifier, str) or not identifier:
            raise ValueError("truncation_audit_node_id")
        if identifier in eligible_index:
            duplicate_eligible += 1
            continue
        pos = len(eligible_records)
        eligible_index[identifier] = pos
        eligible_records.append(record)
        origin = _origin_bucket(record)
        by_kind[kind]["eligible"] += 1
        by_origin[origin]["eligible"] += 1
        if pos < node_cap:
            by_kind[kind]["kept"] += 1
            by_origin[origin]["kept"] += 1
        else:
            by_kind[kind]["dropped_cap"] += 1
            by_origin[origin]["dropped_cap"] += 1

    eligible_count = len(eligible_records)
    kept_count = min(eligible_count, node_cap)
    dropped_cap = eligible_count - kept_count
    is_capped = dropped_cap > 0
    node_drop_ratio = (dropped_cap / eligible_count) if eligible_count > 0 else None

    eligible_types = [NODE_TYPES[rec["kind"]] for rec in eligible_records]
    by_edge_rel = {str(rel): {"eligible": 0, "kept": 0, "dropped_cap": 0} for rel in range(8)}

    excluded_non_eligible_edges = 0
    eligible_edges = 0
    kept_edges = 0
    excluded_edge_cap = 0
    dropped_one_ep = 0
    dropped_both_ep = 0

    undir_before = [[] for _ in range(eligible_count)]
    dir_before = [[] for _ in range(eligible_count)]
    in_deg_before = [0] * eligible_count
    out_deg_before = [0] * eligible_count

    undir_after = [[] for _ in range(kept_count)]
    dir_after = [[] for _ in range(kept_count)]
    in_deg_after = [0] * kept_count
    out_deg_after = [0] * kept_count

    for edge in edges:
        if not isinstance(edge, dict):
            excluded_non_eligible_edges += 1
            continue
        src_pos = eligible_index.get(edge.get("source"))
        dst_pos = eligible_index.get(edge.get("target"))
        if src_pos is None or dst_pos is None:
            excluded_non_eligible_edges += 1
            continue
        eligible_edges += 1
        rel = EDGE_TYPES.get((eligible_types[src_pos], eligible_types[dst_pos]), 7)
        rel_key = str(rel)
        by_edge_rel[rel_key]["eligible"] += 1

        dir_before[src_pos].append(dst_pos)
        undir_before[src_pos].append(dst_pos)
        undir_before[dst_pos].append(src_pos)
        out_deg_before[src_pos] += 1
        in_deg_before[dst_pos] += 1

        src_kept = src_pos < kept_count
        dst_kept = dst_pos < kept_count
        if src_kept and dst_kept:
            if kept_edges >= MAX_EDGES:
                excluded_edge_cap += 1
            else:
                kept_edges += 1
                by_edge_rel[rel_key]["kept"] += 1
                dir_after[src_pos].append(dst_pos)
                undir_after[src_pos].append(dst_pos)
                undir_after[dst_pos].append(src_pos)
                out_deg_after[src_pos] += 1
                in_deg_after[dst_pos] += 1
        else:
            by_edge_rel[rel_key]["dropped_cap"] += 1
            if src_kept or dst_kept:
                dropped_one_ep += 1
            else:
                dropped_both_ep += 1

    dropped_edges_cap = dropped_one_ep + dropped_both_ep
    edge_drop_ratio = (dropped_edges_cap / eligible_edges) if eligible_edges > 0 else None

    isolates_before = sum((in_deg_before[i] + out_deg_before[i]) == 0 for i in range(eligible_count))
    isolates_after = sum((in_deg_after[i] + out_deg_after[i]) == 0 for i in range(kept_count))
    newly_isolated = sum(
        (in_deg_before[i] + out_deg_before[i]) > 0 and (in_deg_after[i] + out_deg_after[i]) == 0
        for i in range(kept_count)
    )

    orphans_before = sum(eligible_types[i] != 0 and in_deg_before[i] == 0 for i in range(eligible_count))
    orphans_after = sum(eligible_types[i] != 0 and in_deg_after[i] == 0 for i in range(kept_count))
    newly_orphaned = sum(
        eligible_types[i] != 0 and in_deg_before[i] > 0 and in_deg_after[i] == 0
        for i in range(kept_count)
    )

    wcc_before, before_labels = _wcc_labels(eligible_count, undir_before)
    wcc_after, _ = _wcc_labels(kept_count, undir_after)
    kept_precap_wcc = len({before_labels[i] for i in range(kept_count)})

    roots_before = [i for i in range(eligible_count) if eligible_types[i] == 0]
    roots_after = [i for i in range(kept_count) if eligible_types[i] == 0]
    reach_before = _reachable_from_roots(roots_before, dir_before)
    reach_after = _reachable_from_roots(roots_after, dir_after)
    kept_disconnected = sum((i in reach_before) and (i not in reach_after) for i in range(kept_count))

    legacy_vals, legacy_nulls = [], 0
    phys_vals, phys_nulls = [], 0
    phys_reasons_kept = Counter(dict.fromkeys(SPAN_PROVENANCE_REASONS, 0))
    phys_reasons_eligible = Counter(dict.fromkeys(SPAN_PROVENANCE_REASONS, 0))
    stream_vals, stream_nulls = [], 0
    json_vals = []

    for pos, rec in enumerate(eligible_records):
        p_val, p_reason = _physical_span_for_node(rec, decl_index)
        phys_reasons_eligible[p_reason] += 1
        if pos >= kept_count:
            continue
        details = rec.get("details") if isinstance(rec.get("details"), dict) else {}
        s_val = details.get("size_bytes")
        if _finite_nonneg(s_val):
            legacy_vals.append(s_val)
        else:
            legacy_nulls += 1

        phys_reasons_kept[p_reason] += 1
        if p_val is not None:
            phys_vals.append(p_val)
        else:
            phys_nulls += 1

        r_val = details.get("raw_bytes")
        if type(r_val) is int and 0 <= r_val <= 10**12:
            stream_vals.append(r_val)
        else:
            stream_nulls += 1

        json_vals.append(len(canonical_bytes(rec)))

    bundle_status = bundle.get("status") if bundle.get("status") in STATUSES else "partial"
    raw_ext_status = bundle.get("extraction_status", coverage.get("extraction_status", "unknown"))
    ext_status = raw_ext_status if isinstance(raw_ext_status, str) and raw_ext_status in EXTRACTION_STATUSES else "unknown"
    worker = coverage.get("worker") if isinstance(coverage.get("worker"), dict) else {}
    worker_status = worker.get("status") if isinstance(worker.get("status"), str) else "unknown"
    cleanup_ok = worker.get("worker_cleanup_complete") if type(worker.get("worker_cleanup_complete")) is bool else None
    limitations = [x for x in coverage.get("limitations", []) if isinstance(x, str)]
    g_state = _graph_state(kept_count, is_capped, parser_observed, bundle_status, worker_status, limitations)

    result = {
        "schema_version": 1,
        "contract_version": CONTRACT_VERSION,
        "sample_sha256": expected_sha256,
        "node_cap": node_cap,
        "node_accounting": {
            "evidence_nodes": len(records),
            "excluded_nodes_kind": excluded_kind,
            "excluded_nodes_status": excluded_status,
            "duplicate_eligible_ids": duplicate_eligible,
            "eligible_nodes_before_cap": eligible_count,
            "kept_nodes_after_cap": kept_count,
            "dropped_nodes_cap": dropped_cap,
            "is_capped": is_capped,
            "node_drop_ratio": node_drop_ratio,
            "security_sensitive_dropped_cap": sum(by_kind[k]["dropped_cap"] for k in SECURITY_SENSITIVE_KINDS),
            "by_kind": by_kind,
            "by_origin": by_origin,
        },
        "edge_accounting": {
            "evidence_edges": len(edges),
            "excluded_edges_non_eligible_endpoint": excluded_non_eligible_edges,
            "eligible_edges_before_cap": eligible_edges,
            "kept_edges_after_cap": kept_edges,
            "excluded_edges_edge_cap": excluded_edge_cap,
            "dropped_edges_cap": dropped_edges_cap,
            "dropped_edges_one_endpoint_capped": dropped_one_ep,
            "dropped_edges_both_endpoints_capped": dropped_both_ep,
            "edge_drop_ratio": edge_drop_ratio,
            "by_edge_rel": by_edge_rel,
        },
        "structural_impact": {
            "isolates_before_cap": isolates_before,
            "isolates_after_cap": isolates_after,
            "newly_isolated_kept_nodes": newly_isolated,
            "orphans_before_cap": orphans_before,
            "orphans_after_cap": orphans_after,
            "newly_orphaned_kept_nodes": newly_orphaned,
            "wcc_before_cap": wcc_before,
            "wcc_after_cap": wcc_after,
            "wcc_delta": wcc_after - wcc_before,
            "kept_precap_wcc_count": kept_precap_wcc,
            "kept_fragmentation_wcc_gain": wcc_after - kept_precap_wcc,
            "catalog_reachable_before_cap": len(reach_before),
            "catalog_reachable_after_cap": len(reach_after),
            "kept_disconnected_from_catalog_by_cap": kept_disconnected,
            "max_out_degree_before_cap": max(out_deg_before, default=0),
            "max_out_degree_after_cap": max(out_deg_after, default=0),
            "max_in_degree_before_cap": max(in_deg_before, default=0),
            "max_in_degree_after_cap": max(in_deg_after, default=0),
        },
        "size_provenance": {
            "legacy_semantic_size_bytes": {
                "producer": "record.details.size_bytes",
                "is_model_feature_producer": True,
                **_stats(legacy_vals, null_count=legacy_nulls),
            },
            "verified_physical_declaration_span_bytes": {
                "producer": "raw_forensic.forensic_object_declaration[original,top_level_confirmed,exact_pypdf_header_offset]",
                "is_model_feature_producer": True,
                **_stats(phys_vals, null_count=phys_nulls),
            },
            "verified_physical_declaration_span_reasons": dict(phys_reasons_kept),
            "verified_physical_declaration_span_reasons_eligible": dict(phys_reasons_eligible),
            "stream_raw_payload_bytes": {
                "producer": "evidence_v9.StreamObject.details.raw_bytes",
                "is_model_feature_producer": True,
                **_stats(stream_vals, null_count=stream_nulls),
            },
            "projected_json_storage_bytes": {
                "producer": "canonical_utf8_json_record_length",
                "is_model_feature_producer": False,
                **_stats(json_vals, null_count=0),
            },
        },
        "quality_gate_view": {
            "quality_contract_version": QUALITY_CONTRACT_VERSION,
            "bundle_status": bundle_status,
            "extraction_status": ext_status,
            "worker_cleanup_complete": cleanup_ok,
            "graph_state": g_state,
            "parser_object_candidates": parser_candidates,
            "parser_objects_observed": parser_observed,
            "valid_under_contract": bool(cleanup_ok is True and kept_count > 0),
            "feature_dim": None,
            "model_input_ready": False,
        },
    }
    return validate_truncation_case(result)


def validate_truncation_case(value):
    top_keys = {
        "schema_version",
        "contract_version",
        "sample_sha256",
        "node_cap",
        "node_accounting",
        "edge_accounting",
        "structural_impact",
        "size_provenance",
        "quality_gate_view",
    }
    if (not isinstance(value, dict) or set(value) != top_keys or value["schema_version"] != 1
            or value["contract_version"] != CONTRACT_VERSION
            or not isinstance(value["sample_sha256"], str) or not HASH_RE.fullmatch(value["sample_sha256"])
            or type(value["node_cap"]) is not int or not 1 <= value["node_cap"] <= MAX_NODES):
        raise ValueError("truncation_case_header")

    na = value["node_accounting"]
    if (na["evidence_nodes"] != na["excluded_nodes_kind"] + na["excluded_nodes_status"]
            + na["duplicate_eligible_ids"] + na["eligible_nodes_before_cap"]
            or na["eligible_nodes_before_cap"] != na["kept_nodes_after_cap"] + na["dropped_nodes_cap"]
            or na["kept_nodes_after_cap"] > value["node_cap"]
            or na["is_capped"] is not (na["dropped_nodes_cap"] > 0)):
        raise ValueError("truncation_case_nodes")
    if na["eligible_nodes_before_cap"] == 0 and na["node_drop_ratio"] is not None:
        raise ValueError("truncation_case_node_ratio")
    if na["eligible_nodes_before_cap"] > 0 and (
        type(na["node_drop_ratio"]) not in (int, float) or not 0.0 <= na["node_drop_ratio"] <= 1.0
    ):
        raise ValueError("truncation_case_node_ratio")

    ea = value["edge_accounting"]
    if (ea["evidence_edges"] != ea["excluded_edges_non_eligible_endpoint"] + ea["eligible_edges_before_cap"]
            or ea["eligible_edges_before_cap"] != ea["kept_edges_after_cap"] + ea["excluded_edges_edge_cap"] + ea["dropped_edges_cap"]
            or ea["dropped_edges_cap"] != ea["dropped_edges_one_endpoint_capped"] + ea["dropped_edges_both_endpoints_capped"]):
        raise ValueError("truncation_case_edges")
    if ea["eligible_edges_before_cap"] == 0 and ea["edge_drop_ratio"] is not None:
        raise ValueError("truncation_case_edge_ratio")

    st = value["structural_impact"]
    if st["kept_fragmentation_wcc_gain"] < 0:
        raise ValueError("truncation_case_wcc_gain")

    sp = value["size_provenance"]
    kept = na["kept_nodes_after_cap"]
    eligible = na["eligible_nodes_before_cap"]
    for field in ("legacy_semantic_size_bytes", "verified_physical_declaration_span_bytes",
                  "stream_raw_payload_bytes", "projected_json_storage_bytes"):
        entry = sp[field]
        if entry["known_count"] + entry["null_count"] != kept:
            raise ValueError("truncation_case_size_denominator")
    if sum(sp["verified_physical_declaration_span_reasons"].values()) != kept:
        raise ValueError("truncation_case_span_reasons")
    if sum(sp["verified_physical_declaration_span_reasons_eligible"].values()) != eligible:
        raise ValueError("truncation_case_span_reasons_eligible")
    if sp["projected_json_storage_bytes"]["is_model_feature_producer"] is not False:
        raise ValueError("truncation_case_json_producer_flag")

    qg = value["quality_gate_view"]
    if (qg["quality_contract_version"] != QUALITY_CONTRACT_VERSION
            or qg["graph_state"] not in GRAPH_STATES
            or qg["feature_dim"] is not None or qg["model_input_ready"] is not False):
        raise ValueError("truncation_case_quality")
    canonical_bytes(value)
    return value


def _subset_summary(rows):
    valid = [r for r in rows if r.get("truncation") is not None]
    audits = [r["truncation"] for r in valid]
    capped = [a for a in audits if a["node_accounting"]["is_capped"]]
    empty = [a for a in audits if a["node_accounting"]["kept_nodes_after_cap"] == 0]
    by_state = Counter(a["quality_gate_view"]["graph_state"] for a in audits)
    by_status = Counter(a["quality_gate_view"]["bundle_status"] for a in audits)
    return {
        "planned": len(rows),
        "audited": len(valid),
        "nonempty_graphs": len(audits) - len(empty),
        "empty_graphs": len(empty),
        "capped_graphs": len(capped),
        "uncapped_nonempty_graphs": len(audits) - len(empty) - len(capped),
        "valid_under_contract": sum(a["quality_gate_view"]["valid_under_contract"] for a in audits),
        "graph_state_counts": dict(sorted(by_state.items())),
        "bundle_status_counts": dict(sorted(by_status.items())),
        "eligible_nodes_distribution": distribution([a["node_accounting"]["eligible_nodes_before_cap"] for a in audits]),
        "kept_nodes_distribution": distribution([a["node_accounting"]["kept_nodes_after_cap"] for a in audits]),
        "dropped_nodes_cap_distribution": distribution([a["node_accounting"]["dropped_nodes_cap"] for a in audits]),
        "eligible_edges_distribution": distribution([a["edge_accounting"]["eligible_edges_before_cap"] for a in audits]),
        "kept_edges_distribution": distribution([a["edge_accounting"]["kept_edges_after_cap"] for a in audits]),
        "dropped_edges_cap_distribution": distribution([a["edge_accounting"]["dropped_edges_cap"] for a in audits]),
    }


def summarize_truncation_cases(rows, *, node_cap=MAX_NODES):
    valid = [r for r in rows if r.get("truncation") is not None]
    audits = [r["truncation"] for r in valid]
    capped_rows = [r for r in valid if r["truncation"]["node_accounting"]["is_capped"]]
    capped = [r["truncation"] for r in capped_rows]

    kind_totals_all = {k: {"eligible": 0, "kept": 0, "dropped_cap": 0} for k in NODE_TYPES}
    origin_totals_all = {k: {"eligible": 0, "kept": 0, "dropped_cap": 0} for k in ORIGIN_BUCKETS}
    kind_totals_capped = {k: {"eligible": 0, "kept": 0, "dropped_cap": 0} for k in NODE_TYPES}
    samples_dropping_by_kind = {k: 0 for k in NODE_TYPES}
    origin_totals_capped = {k: {"eligible": 0, "kept": 0, "dropped_cap": 0} for k in ORIGIN_BUCKETS}
    edge_rel_capped = {str(rel): {"eligible": 0, "kept": 0, "dropped_cap": 0} for rel in range(8)}
    span_reasons_kept_all = Counter(dict.fromkeys(SPAN_PROVENANCE_REASONS, 0))
    span_reasons_eligible_all = Counter(dict.fromkeys(SPAN_PROVENANCE_REASONS, 0))

    size_totals = {
        name: {"known_count": 0, "null_count": 0, "total_bytes": 0}
        for name in (
            "legacy_semantic_size_bytes",
            "verified_physical_declaration_span_bytes",
            "stream_raw_payload_bytes",
            "projected_json_storage_bytes",
        )
    }

    for a in audits:
        for k in NODE_TYPES:
            for m in ("eligible", "kept", "dropped_cap"):
                kind_totals_all[k][m] += a["node_accounting"]["by_kind"][k][m]
        for o in ORIGIN_BUCKETS:
            for m in ("eligible", "kept", "dropped_cap"):
                origin_totals_all[o][m] += a["node_accounting"]["by_origin"][o][m]
        for reason, amount in a["size_provenance"]["verified_physical_declaration_span_reasons"].items():
            span_reasons_kept_all[reason] += amount
        for reason, amount in a["size_provenance"]["verified_physical_declaration_span_reasons_eligible"].items():
            span_reasons_eligible_all[reason] += amount
        for s_name in size_totals:
            entry = a["size_provenance"][s_name]
            size_totals[s_name]["known_count"] += entry["known_count"]
            size_totals[s_name]["null_count"] += entry["null_count"]
            size_totals[s_name]["total_bytes"] += entry["total"]

    for a in capped:
        for k in NODE_TYPES:
            samples_dropping_by_kind[k] += a["node_accounting"]["by_kind"][k]["dropped_cap"] > 0
            for m in ("eligible", "kept", "dropped_cap"):
                kind_totals_capped[k][m] += a["node_accounting"]["by_kind"][k][m]
        for o in ORIGIN_BUCKETS:
            for m in ("eligible", "kept", "dropped_cap"):
                origin_totals_capped[o][m] += a["node_accounting"]["by_origin"][o][m]
        for rel in map(str, range(8)):
            for m in ("eligible", "kept", "dropped_cap"):
                edge_rel_capped[rel][m] += a["edge_accounting"]["by_edge_rel"][rel][m]

    node_ratios = [round(a["node_accounting"]["node_drop_ratio"], 6) for a in capped if a["node_accounting"]["node_drop_ratio"] is not None]
    edge_ratios = [round(a["edge_accounting"]["edge_drop_ratio"], 6) for a in capped if a["edge_accounting"]["edge_drop_ratio"] is not None]

    by_split = {
        split: _subset_summary([r for r in rows if r["split"] == split])
        for split in ("train", "validation", "test")
    }
    by_label = {
        str(lbl): _subset_summary([r for r in rows if r["label"] == lbl])
        for lbl in (0, 1)
    }
    by_split_label = {
        f"{split}_label_{lbl}": _subset_summary([r for r in rows if r["split"] == split and r["label"] == lbl])
        for split in ("train", "validation", "test")
        for lbl in (0, 1)
    }

    projection_filtered_indices = [
        r["index"] for r in valid if r["truncation"]["quality_gate_view"]["graph_state"] == "empty_projection_filtered"
    ]
    empty_unresolved_indices = [
        r["index"] for r in valid
        if r["truncation"]["node_accounting"]["kept_nodes_after_cap"] == 0
        and r["truncation"]["quality_gate_view"]["graph_state"] != "empty_projection_filtered"
    ]

    return {
        "schema_version": 1,
        "stage": "BUG-007B2",
        "contract_version": CONTRACT_VERSION,
        "quality_contract_version": QUALITY_CONTRACT_VERSION,
        "node_cap": node_cap,
        "cohort": _subset_summary(rows),
        "capped_cohort": {
            "count": len(capped),
            "indices": [r["index"] for r in capped_rows],
            "eligible_nodes_before_cap": distribution([a["node_accounting"]["eligible_nodes_before_cap"] for a in capped]),
            "kept_nodes_after_cap": distribution([a["node_accounting"]["kept_nodes_after_cap"] for a in capped]),
            "dropped_nodes_cap": distribution([a["node_accounting"]["dropped_nodes_cap"] for a in capped]),
            "node_drop_ratio_percent": distribution([round(x * 100.0, 4) for x in node_ratios]),
            "eligible_edges_before_cap": distribution([a["edge_accounting"]["eligible_edges_before_cap"] for a in capped]),
            "kept_edges_after_cap": distribution([a["edge_accounting"]["kept_edges_after_cap"] for a in capped]),
            "dropped_edges_cap": distribution([a["edge_accounting"]["dropped_edges_cap"] for a in capped]),
            "excluded_edges_edge_cap_total": sum(a["edge_accounting"]["excluded_edges_edge_cap"] for a in capped),
            "dropped_edges_one_endpoint_capped_total": sum(a["edge_accounting"]["dropped_edges_one_endpoint_capped"] for a in capped),
            "dropped_edges_both_endpoints_capped_total": sum(a["edge_accounting"]["dropped_edges_both_endpoints_capped"] for a in capped),
            "excluded_edges_non_eligible_endpoint_total": sum(a["edge_accounting"]["excluded_edges_non_eligible_endpoint"] for a in capped),
            "edge_drop_ratio_percent": distribution(
                [round(x * 100.0, 4) for x in edge_ratios],
                null_count=len(capped) - len(edge_ratios),
            ),
            "by_kind_totals": kind_totals_capped,
            "samples_dropping_by_kind": samples_dropping_by_kind,
            "by_origin_totals": origin_totals_capped,
            "by_edge_rel_totals": edge_rel_capped,
            "samples_dropping_security_sensitive_nodes": sum(
                a["node_accounting"]["security_sensitive_dropped_cap"] > 0 for a in capped
            ),
            "security_sensitive_nodes_dropped_total": sum(
                a["node_accounting"]["security_sensitive_dropped_cap"] for a in capped
            ),
            "structural_impact": {
                "newly_isolated_kept_nodes_total": sum(a["structural_impact"]["newly_isolated_kept_nodes"] for a in capped),
                "samples_with_newly_isolated_nodes": sum(a["structural_impact"]["newly_isolated_kept_nodes"] > 0 for a in capped),
                "newly_orphaned_kept_nodes_total": sum(a["structural_impact"]["newly_orphaned_kept_nodes"] for a in capped),
                "samples_with_newly_orphaned_nodes": sum(a["structural_impact"]["newly_orphaned_kept_nodes"] > 0 for a in capped),
                "kept_disconnected_from_catalog_total": sum(a["structural_impact"]["kept_disconnected_from_catalog_by_cap"] for a in capped),
                "samples_with_catalog_disconnection": sum(a["structural_impact"]["kept_disconnected_from_catalog_by_cap"] > 0 for a in capped),
                "kept_fragmentation_wcc_gain_total": sum(a["structural_impact"]["kept_fragmentation_wcc_gain"] for a in capped),
                "samples_with_kept_wcc_fragmentation": sum(a["structural_impact"]["kept_fragmentation_wcc_gain"] > 0 for a in capped),
                "wcc_delta_distribution": distribution([a["structural_impact"]["wcc_delta"] for a in capped]),
            },
        },
        "structural_metric_definitions": {
            "newly_isolated_kept_nodes": "retained nodes (< node_cap) with total eligible degree > 0 before cap and total retained degree == 0 after cap",
            "newly_orphaned_kept_nodes": "retained non-catalog nodes (< node_cap) with eligible in-degree > 0 before cap and retained in-degree == 0 after cap (flips model feature is_orphan from 0 to 1)",
            "kept_disconnected_from_catalog_by_cap": "retained nodes directed-reachable from a catalog node in the eligible graph before cap that lose directed reachability from any retained catalog node after cap",
            "kept_fragmentation_wcc_gain": "wcc_after_cap minus the number of pre-cap eligible WCCs containing at least one retained node; strictly >= 0 and isolates splitting of retained subgraphs from deletion of >=200 components",
            "wcc_delta": "wcc_after_cap minus wcc_before_cap across the full eligible vs retained node sets",
        },
        "all_cohort_by_kind_totals": kind_totals_all,
        "all_cohort_by_origin_totals": origin_totals_all,
        "by_split": by_split,
        "by_label": by_label,
        "by_split_and_label": by_split_label,
        "empty_projection_separation": {
            "projection_filter_confirmed_indices": projection_filtered_indices,
            "other_empty_projection_indices": empty_unresolved_indices,
        },
        "node_size_producers_and_provenance": {
            "definitions": {
                "legacy_semantic_size_bytes": "record.details.size_bytes read by numeric_export.py; currently populated only on non-projected document record, never on the 9 semantic node kinds",
                "verified_physical_declaration_span_bytes": "half-open [byte_start, byte_end) of original-space confirmed raw_forensic indirect declaration joined strictly on (pypdf non-repaired backend, object_number, generation, verified header byte_offset_start)",
                "stream_raw_payload_bytes": "record.details.raw_bytes encoded stream body byte length on StreamObject-backed nodes; excludes obj/endobj wrapper and dictionary header",
                "projected_json_storage_bytes": "canonical UTF-8 JSON serialization size of the evidence record; wire/storage cost only, forbidden as a PDF object size feature",
            },
            "missing_value_policy": "null_preserved_never_zero_filled_or_cross_substituted",
            "totals_across_retained_projected_nodes": size_totals,
            "verified_physical_declaration_span_reasons_totals": dict(span_reasons_kept_all),
            "verified_physical_declaration_span_reasons_eligible_totals": dict(span_reasons_eligible_all),
        },
        "feature_dim": None,
        "model_input_ready": False,
        "raw_pdf_processing": False,
        "node_cap_modified": False,
        "parser_modified": False,
        "training_executed": False,
    }

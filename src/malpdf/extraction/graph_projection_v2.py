from __future__ import annotations

from collections import deque
import math
import re

import numpy as np

from malpdf.extraction.graph_audit import canonical_bytes
from malpdf.extraction.graph_truncation_audit import (
    SECURITY_SENSITIVE_KINDS,
    SPAN_PROVENANCE_REASONS,
    _confirmed_declarations,
    _physical_span_for_node,
)
from malpdf.extraction.numeric_export import (
    EDGE_TYPES,
    MAX_EDGES,
    MAX_FEATURES,
    MAX_NODES,
    NODE_TYPES,
    OBSERVED,
    STATUSES,
    _feature_value,
    _number,
)
from malpdf.extraction.numeric_feature_names import FEATURE_NAMES


SCHEMA_VERSION = 2
PROJECTION_CONTRACT_VERSION = "pdf-graph-projection-v2"
NODE_FEATURE_DIM_V2 = 23
RWSE_STEPS = 16
MAX_CONTAINER_HOPS = 8
HASH_RE = re.compile(r"[a-f0-9]{64}\Z")

PRIORITY_TIER_0_KINDS = frozenset({
    "catalog",
    "pages",
    "action",
    "script",
    "annotation",
    "filespec",
    "stream",
})
PRIORITY_TIER_1_KINDS = frozenset({"page"})
CONTAINER_KINDS = frozenset({
    "array",
    "form",
    "field",
    "pdf_object",
    "embedded_stream",
    "xfa_packet",
})


def _priority_tier(kind: str) -> int:
    if kind in PRIORITY_TIER_0_KINDS:
        return 0
    if kind in PRIORITY_TIER_1_KINDS:
        return 1
    return 2


def _is_indirect_record(record: dict) -> bool:
    number = record.get("object_number")
    return type(number) is int and number > 0


def _is_dict_valued_inline_pdf_object(record: dict) -> bool:
    details = record.get("details")
    if not isinstance(details, dict):
        return False
    proj = details.get("projection")
    if not isinstance(proj, dict):
        return False
    return proj.get("value_type") == "dict" or proj.get("type") == "dict"


def compute_rwse_v2(
    num_nodes: int,
    edge_src: list[int],
    edge_dst: list[int],
    steps: int = RWSE_STEPS,
) -> list[list[float]]:
    if num_nodes == 0:
        return []
    adj = np.zeros((num_nodes, num_nodes), dtype=np.float32)
    for src, dst in zip(edge_src, edge_dst):
        if 0 <= src < num_nodes and 0 <= dst < num_nodes:
            adj[src, dst] += 1.0
    deg = adj.sum(axis=1, keepdims=True)
    transition = np.divide(adj, deg, out=np.zeros_like(adj), where=deg > 0)
    zero_rows = np.where(deg.squeeze(-1) == 0)[0]
    transition[zero_rows, zero_rows] = 1.0
    power = transition.copy()
    diag_steps = np.empty((num_nodes, steps), dtype=np.float32)
    for step_idx in range(steps):
        diag_steps[:, step_idx] = np.clip(np.diag(power), 0.0, 1.0)
        if step_idx + 1 < steps:
            power = power @ transition
    return [[float(val) for val in row] for row in diag_steps]


def _extract_worker_view(bundle: dict) -> dict:
    worker = {}
    raw_worker = (bundle.get("coverage_report") or {}).get("worker") or {}
    if not isinstance(raw_worker, dict):
        raise ValueError("graph_projection_v2_worker")
    for key in ("worker_cleanup_complete", "peak_rss_bytes", "worker_exit_code", "worker_seconds"):
        value = raw_worker.get(key)
        if key == "worker_cleanup_complete":
            if value is not None and type(value) is not bool:
                raise ValueError("graph_projection_v2_worker")
        elif value is not None and (
            type(value) not in (int, float)
            or not _number(value)
            or (key != "worker_exit_code" and value < 0)
        ):
            raise ValueError("graph_projection_v2_worker")
        worker[key] = value
    return worker


def _extract_tabular_features(bundle: dict) -> tuple[dict, int]:
    features = {}
    excluded = 0
    feature_store = bundle.get("feature_store") or {}
    records = feature_store.get("records", []) if isinstance(feature_store, dict) else []
    if not isinstance(records, list):
        raise ValueError("graph_projection_v2_features")
    for item in records:
        if not isinstance(item, dict):
            excluded += 1
            continue
        name = item.get("feature_name")
        if not isinstance(name, str) or name not in FEATURE_NAMES:
            excluded += 1
            continue
        if name in features or len(features) >= MAX_FEATURES:
            raise ValueError("graph_projection_v2_feature_identity")
        features[name] = _feature_value(item)
    return features, excluded


def project_graph_bundle_v2(bundle: dict, expected_sha256: str, *, node_cap: int = MAX_NODES) -> dict:
    if (
        not isinstance(expected_sha256, str)
        or not HASH_RE.fullmatch(expected_sha256)
        or not isinstance(bundle, dict)
        or bundle.get("sample_sha256") != expected_sha256
    ):
        raise ValueError("graph_projection_v2_identity")
    if type(node_cap) is not int or not 1 <= node_cap <= MAX_NODES:
        raise ValueError("graph_projection_v2_node_cap")
    status = bundle.get("status")
    if not isinstance(status, str) or status not in STATUSES:
        raise ValueError("graph_projection_v2_status")

    features, excluded_features = _extract_tabular_features(bundle)
    worker = _extract_worker_view(bundle)

    evidence = bundle.get("evidence_store") or {}
    if not isinstance(evidence, dict):
        raise ValueError("graph_projection_v2_evidence_store")
    records = evidence.get("records", [])
    raw_edges = evidence.get("edges", [])
    if not isinstance(records, list) or not isinstance(raw_edges, list):
        raise ValueError("graph_projection_v2_evidence_shape")

    decl_index = _confirmed_declarations(records)

    excluded_kind = 0
    excluded_status = 0
    excluded_inline = 0
    duplicate_ids = 0
    seen_candidate_ids: set[str] = set()
    candidates: list[tuple[int, int, str, dict]] = []
    fallback_inline_dicts: list[tuple[int, str, dict]] = []
    observed_containers: dict[str, dict] = {}

    for rec_pos, record in enumerate(records):
        if not isinstance(record, dict):
            excluded_kind += 1
            continue
        kind = record.get("kind")
        obs_status = record.get("observation_status")
        identifier = record.get("evidence_id")
        if (
            isinstance(identifier, str)
            and identifier
            and isinstance(kind, str)
            and kind in CONTAINER_KINDS
            and isinstance(obs_status, str)
            and obs_status in OBSERVED
            and identifier not in observed_containers
        ):
            observed_containers[identifier] = record

        if not isinstance(kind, str) or kind not in NODE_TYPES:
            excluded_kind += 1
            continue
        if not isinstance(obs_status, str) or obs_status not in OBSERVED:
            excluded_status += 1
            continue
        if not isinstance(identifier, str) or not identifier:
            raise ValueError("graph_projection_v2_node_identity")
        if identifier in seen_candidate_ids:
            duplicate_ids += 1
            continue
        if kind == "pdf_object" and not _is_indirect_record(record):
            excluded_inline += 1
            if _is_dict_valued_inline_pdf_object(record):
                fallback_inline_dicts.append((rec_pos, identifier, record))
            continue
        seen_candidate_ids.add(identifier)
        candidates.append((_priority_tier(kind), rec_pos, identifier, record))

    if not candidates and fallback_inline_dicts:
        for rec_pos, identifier, record in fallback_inline_dicts:
            if identifier in seen_candidate_ids:
                duplicate_ids += 1
                excluded_inline -= 1
                continue
            seen_candidate_ids.add(identifier)
            excluded_inline -= 1
            candidates.append((2, rec_pos, identifier, record))

    eligible_before_cap = len(candidates)
    ranked = sorted(candidates, key=lambda item: (item[0], item[1]))
    kept_ranked = ranked[:node_cap]
    dropped_ranked = ranked[node_cap:]
    dropped_cap = len(dropped_ranked)
    sec_dropped_cap = sum(1 for _, _, _, rec in dropped_ranked if rec.get("kind") in SECURITY_SENSITIVE_KINDS)

    kept_ordered = sorted(kept_ranked, key=lambda item: item[1])
    kept_index = {identifier: idx for idx, (_, _, identifier, _) in enumerate(kept_ordered)}
    kept_records = [rec for _, _, _, rec in kept_ordered]
    node_types = [NODE_TYPES[rec["kind"]] for rec in kept_records]
    num_nodes = len(kept_records)

    unretained_containers = {
        cid for cid in observed_containers if cid not in kept_index
    }

    adj_from_id: dict[str, list[str]] = {}
    excluded_edges = 0
    excluded_edge_cap = 0
    direct_kept_edges = 0
    contracted_container_edges = 0
    edge_src: list[int] = []
    edge_dst: list[int] = []
    edge_rel: list[int] = []
    emitted_pairs: set[tuple[int, int]] = set()

    for edge in raw_edges:
        if not isinstance(edge, dict) or edge.get("status") == "unresolved":
            excluded_edges += 1
            continue
        src_id = edge.get("source")
        dst_id = edge.get("target")
        if not isinstance(src_id, str) or not isinstance(dst_id, str):
            excluded_edges += 1
            continue
        if src_id in kept_index or src_id in unretained_containers:
            adj_from_id.setdefault(src_id, []).append(dst_id)
        u_idx = kept_index.get(src_id)
        v_idx = kept_index.get(dst_id)
        if u_idx is not None and v_idx is not None:
            pair = (u_idx, v_idx)
            if pair in emitted_pairs:
                continue
            if len(edge_src) >= MAX_EDGES:
                excluded_edge_cap += 1
                continue
            emitted_pairs.add(pair)
            edge_src.append(u_idx)
            edge_dst.append(v_idx)
            edge_rel.append(EDGE_TYPES.get((node_types[u_idx], node_types[v_idx]), 7))
            direct_kept_edges += 1
        elif src_id not in kept_index and src_id not in unretained_containers:
            excluded_edges += 1
        elif dst_id not in kept_index and dst_id not in unretained_containers:
            excluded_edges += 1

    for u_idx, (_, _, u_id, _) in enumerate(kept_ordered):
        visited_containers: set[str] = set()
        queue: deque[tuple[str, int]] = deque()
        for nxt_id in adj_from_id.get(u_id, ()):
            if nxt_id in unretained_containers and nxt_id not in visited_containers:
                visited_containers.add(nxt_id)
                queue.append((nxt_id, 1))
        while queue:
            cur_id, hops = queue.popleft()
            for nxt_id in adj_from_id.get(cur_id, ()):
                v_idx = kept_index.get(nxt_id)
                if v_idx is not None:
                    if v_idx == u_idx:
                        continue
                    pair = (u_idx, v_idx)
                    if pair in emitted_pairs:
                        continue
                    if len(edge_src) >= MAX_EDGES:
                        excluded_edge_cap += 1
                        continue
                    emitted_pairs.add(pair)
                    edge_src.append(u_idx)
                    edge_dst.append(v_idx)
                    edge_rel.append(EDGE_TYPES.get((node_types[u_idx], node_types[v_idx]), 7))
                    contracted_container_edges += 1
                elif hops < MAX_CONTAINER_HOPS and nxt_id in unretained_containers and nxt_id not in visited_containers:
                    visited_containers.add(nxt_id)
                    queue.append((nxt_id, hops + 1))

    in_deg = [0] * num_nodes
    for dst_idx in edge_dst:
        in_deg[dst_idx] += 1

    rwse = compute_rwse_v2(num_nodes, edge_src, edge_dst, steps=RWSE_STEPS)
    verified_spans: list[int | None] = []
    verified_reasons: list[str] = []
    stream_payloads: list[int | None] = []
    node_features: list[list[float]] = []

    for idx, rec in enumerate(kept_records):
        phys_val, phys_reason = _physical_span_for_node(rec, decl_index)
        verified_spans.append(phys_val)
        verified_reasons.append(phys_reason)

        details = rec.get("details") if isinstance(rec.get("details"), dict) else {}
        raw_bytes = details.get("raw_bytes")
        stream_val = raw_bytes if type(raw_bytes) is int and 0 <= raw_bytes <= 10**12 else None
        stream_payloads.append(stream_val)

        phys_log = float(math.log1p(phys_val)) if phys_val is not None else 0.0
        phys_mask = 1.0 if phys_val is not None else 0.0
        stream_log = float(math.log1p(stream_val)) if stream_val is not None else 0.0
        stream_mask = 1.0 if stream_val is not None else 0.0
        ind_flag = 1.0 if _is_indirect_record(rec) else 0.0
        rep_flag = 1.0 if rec.get("is_synthetic_repaired") is True else 0.0
        orphan_flag = 1.0 if (in_deg[idx] == 0 and node_types[idx] != 0) else 0.0

        row = [
            phys_log,
            phys_mask,
            stream_log,
            stream_mask,
            ind_flag,
            rep_flag,
            orphan_flag,
            *rwse[idx],
        ]
        node_features.append(row)

    model_ready = bool(
        num_nodes > 0
        and worker["worker_cleanup_complete"] is True
        and sec_dropped_cap == 0
    )

    output = {
        "schema_version": SCHEMA_VERSION,
        "projection_contract_version": PROJECTION_CONTRACT_VERSION,
        "sample_sha256": expected_sha256,
        "status": status,
        "features": features,
        "excluded_feature_count": excluded_features,
        "graph": {
            "node_cap": node_cap,
            "node_feature_dim": NODE_FEATURE_DIM_V2,
            "num_nodes": num_nodes,
            "num_edges": len(edge_src),
            "node_types": node_types,
            "node_features": node_features,
            "verified_physical_span_bytes": verified_spans,
            "verified_physical_span_reasons": verified_reasons,
            "stream_raw_payload_bytes": stream_payloads,
            "edge_src": edge_src,
            "edge_dst": edge_dst,
            "edge_rel": edge_rel,
            "evidence_nodes": len(records),
            "excluded_nodes_kind": excluded_kind,
            "excluded_nodes_status": excluded_status,
            "excluded_inline_pdf_objects": excluded_inline,
            "duplicate_eligible_ids": duplicate_ids,
            "eligible_nodes_before_cap": eligible_before_cap,
            "dropped_nodes_cap": dropped_cap,
            "security_sensitive_dropped_cap": sec_dropped_cap,
            "direct_kept_edges": direct_kept_edges,
            "contracted_container_edges": contracted_container_edges,
            "excluded_edges_unresolved_or_unretained": excluded_edges,
            "excluded_edges_edge_cap": excluded_edge_cap,
            "projected_json_storage_bytes_used": False,
            "model_input_ready": model_ready,
        },
        "worker": worker,
    }
    return validate_graph_projection_v2(output, expected_sha256)


def validate_graph_projection_v2(value: dict, expected_sha256: str) -> dict:
    top_keys = {
        "schema_version",
        "projection_contract_version",
        "sample_sha256",
        "status",
        "features",
        "excluded_feature_count",
        "graph",
        "worker",
    }
    if not isinstance(value, dict) or set(value) != top_keys:
        raise ValueError("graph_projection_v2_shape")
    if (
        value["schema_version"] != SCHEMA_VERSION
        or value["projection_contract_version"] != PROJECTION_CONTRACT_VERSION
        or not isinstance(expected_sha256, str)
        or not HASH_RE.fullmatch(expected_sha256)
        or value["sample_sha256"] != expected_sha256
        or not isinstance(value["status"], str)
        or value["status"] not in STATUSES
        or type(value["excluded_feature_count"]) is not int
        or value["excluded_feature_count"] < 0
    ):
        raise ValueError("graph_projection_v2_metadata")

    features = value["features"]
    if not isinstance(features, dict) or len(features) > MAX_FEATURES:
        raise ValueError("graph_projection_v2_features")
    for name, item in features.items():
        if name not in FEATURE_NAMES or not isinstance(item, dict) or set(item) != {"value", "status", "scope_complete"}:
            raise ValueError("graph_projection_v2_feature_shape")
        _feature_value({
            "value": item["value"],
            "observation_status": item["status"],
            "scope_complete": item["scope_complete"],
        })

    g = value["graph"]
    graph_keys = {
        "node_cap",
        "node_feature_dim",
        "num_nodes",
        "num_edges",
        "node_types",
        "node_features",
        "verified_physical_span_bytes",
        "verified_physical_span_reasons",
        "stream_raw_payload_bytes",
        "edge_src",
        "edge_dst",
        "edge_rel",
        "evidence_nodes",
        "excluded_nodes_kind",
        "excluded_nodes_status",
        "excluded_inline_pdf_objects",
        "duplicate_eligible_ids",
        "eligible_nodes_before_cap",
        "dropped_nodes_cap",
        "security_sensitive_dropped_cap",
        "direct_kept_edges",
        "contracted_container_edges",
        "excluded_edges_unresolved_or_unretained",
        "excluded_edges_edge_cap",
        "projected_json_storage_bytes_used",
        "model_input_ready",
    }
    if not isinstance(g, dict) or set(g) != graph_keys:
        raise ValueError("graph_projection_v2_graph_shape")

    node_cap = g["node_cap"]
    num_nodes = g["num_nodes"]
    num_edges = g["num_edges"]
    if (
        type(node_cap) is not int
        or not 1 <= node_cap <= MAX_NODES
        or g["node_feature_dim"] != NODE_FEATURE_DIM_V2
        or type(num_nodes) is not int
        or not 0 <= num_nodes <= node_cap
        or type(num_edges) is not int
        or not 0 <= num_edges <= MAX_EDGES
        or g["projected_json_storage_bytes_used"] is not False
        or type(g["model_input_ready"]) is not bool
    ):
        raise ValueError("graph_projection_v2_graph_bounds")

    if (
        g["evidence_nodes"]
        != g["excluded_nodes_kind"]
        + g["excluded_nodes_status"]
        + g["excluded_inline_pdf_objects"]
        + g["duplicate_eligible_ids"]
        + g["eligible_nodes_before_cap"]
        or g["eligible_nodes_before_cap"] != num_nodes + g["dropped_nodes_cap"]
        or g["security_sensitive_dropped_cap"] > g["dropped_nodes_cap"]
        or num_edges != g["direct_kept_edges"] + g["contracted_container_edges"]
    ):
        raise ValueError("graph_projection_v2_accounting")

    node_types = g["node_types"]
    node_features = g["node_features"]
    spans = g["verified_physical_span_bytes"]
    reasons = g["verified_physical_span_reasons"]
    payloads = g["stream_raw_payload_bytes"]

    if (
        not isinstance(node_types, list)
        or len(node_types) != num_nodes
        or any(type(t) is not int or not 0 <= t < 9 for t in node_types)
        or not isinstance(node_features, list)
        or len(node_features) != num_nodes
        or not isinstance(spans, list)
        or len(spans) != num_nodes
        or not isinstance(reasons, list)
        or len(reasons) != num_nodes
        or not isinstance(payloads, list)
        or len(payloads) != num_nodes
    ):
        raise ValueError("graph_projection_v2_node_arrays")

    for idx in range(num_nodes):
        span_val = spans[idx]
        reason = reasons[idx]
        pay_val = payloads[idx]
        feat_row = node_features[idx]
        if reason not in SPAN_PROVENANCE_REASONS:
            raise ValueError("graph_projection_v2_span_reason")
        if span_val is not None and (type(span_val) is not int or span_val < 0 or reason != "measured"):
            raise ValueError("graph_projection_v2_span_value")
        if span_val is None and reason == "measured":
            raise ValueError("graph_projection_v2_span_contradiction")
        if pay_val is not None and (type(pay_val) is not int or not 0 <= pay_val <= 10**12):
            raise ValueError("graph_projection_v2_stream_payload")
        if (
            not isinstance(feat_row, list)
            or len(feat_row) != NODE_FEATURE_DIM_V2
            or any(type(x) not in (int, float) or not math.isfinite(x) for x in feat_row)
        ):
            raise ValueError("graph_projection_v2_feature_row")
        if span_val is None:
            if feat_row[0] != 0.0 or feat_row[1] != 0.0:
                raise ValueError("graph_projection_v2_span_mask_imputation")
        else:
            if feat_row[1] != 1.0 or not math.isclose(feat_row[0], math.log1p(span_val), rel_tol=1e-5, abs_tol=1e-6):
                raise ValueError("graph_projection_v2_span_encoding")
        if pay_val is None:
            if feat_row[2] != 0.0 or feat_row[3] != 0.0:
                raise ValueError("graph_projection_v2_stream_mask_imputation")
        else:
            if feat_row[3] != 1.0 or not math.isclose(feat_row[2], math.log1p(pay_val), rel_tol=1e-5, abs_tol=1e-6):
                raise ValueError("graph_projection_v2_stream_encoding")
        if any(feat_row[pos] not in (0.0, 1.0) for pos in (4, 5, 6)):
            raise ValueError("graph_projection_v2_binary_flags")
        if any(not -1e-6 <= feat_row[pos] <= 1.0 + 1e-5 for pos in range(7, NODE_FEATURE_DIM_V2)):
            raise ValueError("graph_projection_v2_rwse_bounds")

    for key, bound in (("edge_src", num_nodes), ("edge_dst", num_nodes), ("edge_rel", 8)):
        arr = g[key]
        if not isinstance(arr, list) or len(arr) != num_edges or any(type(x) is not int or not 0 <= x < bound for x in arr):
            raise ValueError("graph_projection_v2_edges")

    worker = value["worker"]
    if not isinstance(worker, dict) or set(worker) != {
        "worker_cleanup_complete",
        "peak_rss_bytes",
        "worker_exit_code",
        "worker_seconds",
    }:
        raise ValueError("graph_projection_v2_worker_shape")
    _extract_worker_view({"coverage_report": {"worker": worker}})

    expected_ready = bool(
        num_nodes > 0
        and worker["worker_cleanup_complete"] is True
        and g["security_sensitive_dropped_cap"] == 0
    )
    if g["model_input_ready"] is not expected_ready:
        raise ValueError("graph_projection_v2_ready_flag")

    canonical_bytes(value)
    return value


def to_measured_graph_record_v2(
    projected: dict,
    *,
    index: int | None = None,
    split: str | None = None,
    label: int | None = None,
) -> dict:
    if not isinstance(projected, dict):
        raise ValueError("graph_projection_v2_shape")
    sha256 = projected.get("sample_sha256")
    validate_graph_projection_v2(projected, sha256)
    g = projected["graph"]
    if g["num_nodes"] <= 0:
        raise ValueError("empty_v2_graph_cannot_export_to_gnn")
    record = {
        "schema_version": SCHEMA_VERSION,
        "projection_contract_version": PROJECTION_CONTRACT_VERSION,
        "sha256": sha256,
        "status": projected["status"],
        "node_feature_dim": NODE_FEATURE_DIM_V2,
        "num_nodes": g["num_nodes"],
        "num_edges": g["num_edges"],
        "node_types": list(g["node_types"]),
        "node_features": [[float(x) for x in row] for row in g["node_features"]],
        "verified_physical_span_bytes": list(g["verified_physical_span_bytes"]),
        "verified_physical_span_reasons": list(g["verified_physical_span_reasons"]),
        "stream_raw_payload_bytes": list(g["stream_raw_payload_bytes"]),
        "edge_src": list(g["edge_src"]),
        "edge_dst": list(g["edge_dst"]),
        "edge_rel": list(g["edge_rel"]),
        "direct_kept_edges": g["direct_kept_edges"],
        "contracted_container_edges": g["contracted_container_edges"],
        "dropped_nodes_cap": g["dropped_nodes_cap"],
        "security_sensitive_dropped_cap": g["security_sensitive_dropped_cap"],
    }
    if index is not None:
        record["index"] = index
    if split is not None:
        record["split"] = split
    if label is not None:
        record["label"] = label
    canonical_bytes(record)
    return record


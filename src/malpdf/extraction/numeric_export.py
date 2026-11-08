from __future__ import annotations

import math
import re

from malpdf.extraction.contracts import ObservationStatus, UNAVAILABLE
from malpdf.extraction.numeric_feature_names import FEATURE_NAMES


STATUSES = frozenset(str(value) for value in ObservationStatus)
HASH = re.compile(r"[a-f0-9]{64}\Z")
NODE_TYPES = {name: index for index, name in enumerate((
    "catalog", "pages", "page", "action", "annotation", "script", "stream", "filespec", "pdf_object"))}
EDGE_TYPES = {(0, 1): 0, (1, 2): 1, (0, 3): 2, (2, 3): 3, (3, 5): 4, (0, 5): 5, (2, 6): 6}
OBSERVED = frozenset({"observed", "partial", "bounded_complete"})
MAX_NODES = 200
MAX_EDGES = 40000
MAX_FEATURES = 1024


def _number(value):
    return type(value) in (int, float, bool) and abs(value) <= 1e100 and math.isfinite(value)


def _feature_value(item):
    status = item.get("observation_status")
    value, complete = item.get("value"), item.get("scope_complete")
    if (not isinstance(status, str) or status not in STATUSES or type(complete) is not bool
            or value is not None and not _number(value)
            or status in UNAVAILABLE and value is not None
            or status in {"observed", "absent_within_scope"} and value is None
            or status == "absent_within_scope" and (value != 0 or not complete)):
        raise ValueError("numeric_export_feature")
    return {"value": value, "status": status, "scope_complete": complete}


def project_numeric_bundle(bundle, expected_sha256):
    if (not isinstance(expected_sha256, str) or not HASH.fullmatch(expected_sha256)
            or not isinstance(bundle, dict) or bundle.get("sample_sha256") != expected_sha256):
        raise ValueError("numeric_export_identity")
    status = bundle.get("status")
    if not isinstance(status, str) or status not in STATUSES:
        raise ValueError("numeric_export_status")
    features, excluded = {}, 0
    for item in bundle.get("feature_store", {}).get("records", []):
        name = item.get("feature_name")
        if not isinstance(name, str) or name not in FEATURE_NAMES:
            excluded += 1
            continue
        if name in features or len(features) >= MAX_FEATURES:
            raise ValueError("numeric_export_feature_identity")
        features[name] = _feature_value(item)
    evidence = bundle.get("evidence_store", {})
    indices, node_types, sizes = {}, [], []
    excluded_nodes = 0
    for item in evidence.get("records", []):
        identifier, kind = item.get("evidence_id"), item.get("kind")
        if (not isinstance(kind, str) or kind not in NODE_TYPES
                or item.get("observation_status") not in OBSERVED
                or len(node_types) >= MAX_NODES):
            excluded_nodes += 1
            continue
        if not isinstance(identifier, str) or identifier in indices:
            raise ValueError("numeric_export_node_identity")
        indices[identifier] = len(node_types)
        node_types.append(NODE_TYPES[kind])
        value = item.get("details", {}).get("size_bytes")
        sizes.append(value if type(value) in (int, float) and _number(value) and value >= 0 else None)
    edge_src, edge_dst, edge_rel = [], [], []
    excluded_edges = 0
    for item in evidence.get("edges", []):
        source, target = indices.get(item.get("source")), indices.get(item.get("target"))
        if source is None or target is None or len(edge_src) >= MAX_EDGES:
            excluded_edges += 1
            continue
        edge_src.append(source)
        edge_dst.append(target)
        edge_rel.append(EDGE_TYPES.get((node_types[source], node_types[target]), 7))
    worker = {}
    raw_worker = bundle.get("coverage_report", {}).get("worker", {})
    for key in ("worker_cleanup_complete", "peak_rss_bytes", "worker_exit_code", "worker_seconds"):
        value = raw_worker.get(key)
        if key == "worker_cleanup_complete":
            if value is not None and type(value) is not bool:
                raise ValueError("numeric_export_worker")
        elif value is not None and (type(value) not in (int, float) or not _number(value)
                or key != "worker_exit_code" and value < 0):
            raise ValueError("numeric_export_worker")
        worker[key] = value
    return {"schema_version": 1, "sample_sha256": expected_sha256, "status": status,
            "features": features, "excluded_feature_count": excluded,
            "graph": {"node_types": node_types, "node_sizes_bytes": sizes,
                      "edge_src": edge_src, "edge_dst": edge_dst, "edge_rel": edge_rel,
                      "excluded_node_count": excluded_nodes, "excluded_edge_count": excluded_edges,
                      "observed_attributes_complete": bool(sizes) and all(value is not None for value in sizes),
                      "model_input_ready": False},
            "worker": worker}


def validate_numeric_projection(value, expected_sha256):
    if not isinstance(value, dict) or set(value) != {
            "schema_version", "sample_sha256", "status", "features", "graph", "worker", "excluded_feature_count"}:
        raise ValueError("numeric_export_shape")
    if (value["schema_version"] != 1 or value["sample_sha256"] != expected_sha256
            or not isinstance(expected_sha256, str) or not HASH.fullmatch(expected_sha256)
            or not isinstance(value["status"], str) or value["status"] not in STATUSES
            or type(value["excluded_feature_count"]) is not int or value["excluded_feature_count"] < 0):
        raise ValueError("numeric_export_metadata")
    features = value["features"]
    if not isinstance(features, dict) or len(features) > MAX_FEATURES:
        raise ValueError("numeric_export_features")
    for name, item in features.items():
        if (name not in FEATURE_NAMES or not isinstance(item, dict)
                or set(item) != {"value", "status", "scope_complete"}):
            raise ValueError("numeric_export_feature_shape")
        _feature_value({"value": item["value"], "observation_status": item["status"],
                        "scope_complete": item["scope_complete"]})
    graph = value["graph"]
    if not isinstance(graph, dict) or set(graph) != {"node_types", "node_sizes_bytes", "edge_src", "edge_dst",
            "edge_rel", "excluded_node_count", "excluded_edge_count", "observed_attributes_complete", "model_input_ready"}:
        raise ValueError("numeric_export_graph_shape")
    nodes, sizes = graph["node_types"], graph["node_sizes_bytes"]
    if (not isinstance(nodes, list) or len(nodes) > MAX_NODES or not isinstance(sizes, list) or len(nodes) != len(sizes)
            or any(type(item) is not int or not 0 <= item < 9 for item in nodes)
            or any(item is not None and (type(item) not in (int, float) or not _number(item) or item < 0) for item in sizes)):
        raise ValueError("numeric_export_nodes")
    for key, bound in (("edge_src", len(nodes)), ("edge_dst", len(nodes)), ("edge_rel", 8)):
        items = graph[key]
        if (not isinstance(items, list) or len(items) > MAX_EDGES
                or any(type(item) is not int or not 0 <= item < bound for item in items)):
            raise ValueError("numeric_export_edges")
    if (len(graph["edge_src"]) != len(graph["edge_dst"]) or len(graph["edge_src"]) != len(graph["edge_rel"])
            or graph["model_input_ready"] is not False
            or graph["observed_attributes_complete"] is not (bool(sizes) and all(item is not None for item in sizes))
            or any(type(graph[key]) is not int or graph[key] < 0 for key in ("excluded_node_count", "excluded_edge_count"))):
        raise ValueError("numeric_export_graph_metadata")
    worker = value["worker"]
    if not isinstance(worker, dict) or set(worker) != {"worker_cleanup_complete", "peak_rss_bytes", "worker_exit_code", "worker_seconds"}:
        raise ValueError("numeric_export_worker_shape")
    projected = project_numeric_bundle({"sample_sha256": expected_sha256, "status": value["status"],
                                       "coverage_report": {"worker": worker}}, expected_sha256)
    if projected["worker"] != worker:
        raise ValueError("numeric_export_worker")
    return value

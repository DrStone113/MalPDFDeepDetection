from __future__ import annotations

import numpy as np


NODE_FEATURE_DIM_V1 = 19
NODE_FEATURE_DIM_V2 = 23


def _index_measured_graphs_with_dim(
    raw_graphs: list[dict],
    expected_sha256s: set[str],
    *,
    feature_dim: int,
) -> dict[str, dict]:
    indexed = {}
    for graph in raw_graphs:
        digest = graph["sha256"]
        if digest in indexed:
            raise ValueError("duplicate_measured_graph")
        nodes = graph["num_nodes"]
        features = np.asarray(graph["node_features"], dtype=np.float32)
        if type(nodes) is not int or nodes <= 0 or features.shape != (nodes, feature_dim) or not np.isfinite(features).all():
            raise ValueError("invalid_measured_graph_nodes")
        if len(graph["node_types"]) != nodes or any(type(t) is not int or not 0 <= t < 9 for t in graph["node_types"]):
            raise ValueError("invalid_measured_graph_node_types")
        edges = graph["num_edges"]
        if type(edges) is not int or edges < 0 or any(len(graph[key]) != edges for key in ("edge_src", "edge_dst", "edge_rel")):
            raise ValueError("invalid_measured_graph_edges")
        if any(type(index) is not int or not 0 <= index < nodes for key in ("edge_src", "edge_dst") for index in graph[key]):
            raise ValueError("invalid_measured_graph_endpoints")
        if any(type(rel) is not int or not 0 <= rel < 8 for rel in graph["edge_rel"]):
            raise ValueError("invalid_measured_graph_relations")
        indexed[digest] = graph
    missing = expected_sha256s - indexed.keys()
    if missing:
        raise ValueError(f"missing_measured_graphs:{len(missing)}; extract actual graphs in LAB before training")
    return indexed


def index_measured_graphs(raw_graphs: list[dict], expected_sha256s: set[str]) -> dict[str, dict]:
    return _index_measured_graphs_with_dim(raw_graphs, expected_sha256s, feature_dim=NODE_FEATURE_DIM_V1)


def index_measured_graphs_v2(raw_graphs: list[dict], expected_sha256s: set[str]) -> dict[str, dict]:
    return _index_measured_graphs_with_dim(raw_graphs, expected_sha256s, feature_dim=NODE_FEATURE_DIM_V2)

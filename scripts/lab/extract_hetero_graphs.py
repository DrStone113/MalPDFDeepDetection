import gzip
import json
from multiprocessing import Pool
import os
from pathlib import Path
import sys
import numpy as np

NODE_TYPES = {
    "catalog": 0,
    "pages": 1,
    "page": 2,
    "action": 3,
    "annotation": 4,
    "script": 5,
    "stream": 6,
    "filespec": 7,
    "pdf_object": 8,
}

EDGE_TYPES = {
    ("catalog", "pages"): 0,
    ("pages", "page"): 1,
    ("catalog", "action"): 2,
    ("page", "action"): 3,
    ("action", "script"): 4,
    ("catalog", "script"): 5,
    ("page", "stream"): 6,
    ("pdf_object", "pdf_object"): 7,
}


def compute_rwse(adj_matrix: np.ndarray, steps: int = 16) -> np.ndarray:
    n = adj_matrix.shape[0]
    if n == 0:
        return np.zeros((0, steps), dtype=np.float32)
    degrees = adj_matrix.sum(axis=1)
    degrees[degrees == 0] = 1.0
    transition = adj_matrix / degrees[:, None]
    for i in range(n):
        if adj_matrix[i].sum() == 0:
            transition[i, i] = 1.0
    rwse = np.zeros((n, steps), dtype=np.float32)
    power = transition.copy()
    for k in range(steps):
        rwse[:, k] = np.diag(power)
        power = np.matmul(power, transition)
    return rwse


def process_bundle(bundle_path_str: str) -> dict | None:
    path = Path(bundle_path_str)
    try:
        with path.open("r", encoding="utf-8") as stream:
            data = json.load(stream)
    except Exception:
        return None
    sha256 = data.get("sample_sha256")
    if not sha256:
        return None
    store = data.get("evidence_store", {})
    records = store.get("records", [])
    raw_edges = store.get("edges", [])
    id_map = {}
    node_types = []
    node_raw_features = []
    incoming_counts = {}
    for r in records:
        eid = r.get("evidence_id")
        kind = r.get("kind", "")
        if eid and kind in NODE_TYPES:
            if len(node_types) >= 200:
                break
            idx = len(node_types)
            id_map[eid] = idx
            node_types.append(NODE_TYPES[kind])
            size_val = float(r.get("details", {}).get("size_bytes") or 0.0)
            has_stream_val = 1.0 if kind == "stream" else 0.0
            node_raw_features.append([np.log1p(size_val), has_stream_val])
            incoming_counts[idx] = 0
    num_nodes = len(node_types)
    if num_nodes == 0:
        return None
    adj = np.zeros((num_nodes, num_nodes), dtype=np.float32)
    edge_src = []
    edge_dst = []
    edge_rel = []
    inv_node_types = {v: k for k, v in NODE_TYPES.items()}
    for e in raw_edges:
        s_id = e.get("source")
        t_id = e.get("target")
        s_idx = id_map.get(s_id)
        t_idx = id_map.get(t_id)
        if s_idx is not None and t_idx is not None:
            adj[s_idx, t_idx] = 1.0
            incoming_counts[t_idx] = incoming_counts.get(t_idx, 0) + 1
            s_kind = inv_node_types[node_types[s_idx]]
            t_kind = inv_node_types[node_types[t_idx]]
            rel = EDGE_TYPES.get((s_kind, t_kind), 7)
            edge_src.append(s_idx)
            edge_dst.append(t_idx)
            edge_rel.append(rel)
    rwse = compute_rwse(adj, steps=16)
    full_node_features = []
    for i in range(num_nodes):
        is_orphan = 1.0 if incoming_counts.get(i, 0) == 0 and node_types[i] != 0 else 0.0
        feat = node_raw_features[i] + [is_orphan] + rwse[i].tolist()
        full_node_features.append(feat)
    return {
        "sha256": sha256,
        "num_nodes": num_nodes,
        "num_edges": len(edge_src),
        "node_types": node_types,
        "node_features": full_node_features,
        "edge_src": edge_src,
        "edge_dst": edge_dst,
        "edge_rel": edge_rel,
    }


def main():
    bundles_dir = Path("/var/lib/malpdf/jobs/7d0196367b50d13c286bb78aa8e64baa9f989f9ce4d1fa99581f2c80ebd04573/private_bundles")
    output_path = Path("/home/remnux/hetero_cic_graphs.json.gz")
    if not bundles_dir.exists():
        print("ERROR: Bundles directory not found")
        sys.exit(1)
    file_paths = sorted([str(p) for p in bundles_dir.glob("*.json")])
    total = len(file_paths)
    print(f"Starting parallel graph extraction for {total} bundles...")
    with Pool(processes=10) as pool:
        results = pool.map(process_bundle, file_paths)
    valid_results = [r for r in results if r is not None]
    print(f"Extraction finished: {len(valid_results)} / {total} valid graphs")
    with gzip.open(output_path, "wt", encoding="utf-8") as out:
        json.dump(valid_results, out)
    size_mb = output_path.stat().st_size / (1024 * 1024)
    print(f"SUCCESS: Saved {len(valid_results)} graphs to {output_path} ({size_mb:.2f} MB)")


if __name__ == "__main__":
    main()


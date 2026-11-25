"""Torch-free pure-NumPy DAG structural encodings, 24D ActionSubgraphIR, and ONNX batch collation for v4."""

from __future__ import annotations

from typing import Any

import numpy as np

NUM_NODE_TYPES = 9
NUM_BASE_RELATIONS = 8
GRAPH_SUMMARY_DIM = 12
MAX_SPD_HOPS = 8
SPD_UNREACHABLE = MAX_SPD_HOPS + 1
ACTION_IR_DIM = 24

CANONICAL_NODE_TYPES: dict[str, int] = {
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
SINK_NODE_TYPES: tuple[int, int, int] = (3, 5, 7)


def compute_dag_structural_encodings(
    num_nodes: int,
    node_types: np.ndarray,
    edge_src: np.ndarray,
    edge_dst: np.ndarray,
    edge_rel: np.ndarray,
    *,
    max_hops: int = MAX_SPD_HOPS,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Compute bounded all-pairs shortest path, direct edge relation, root depth, and sink distance."""
    unreachable = max_hops + 1
    if num_nodes <= 0:
        return (
            np.zeros((0, 0), dtype=np.int64),
            np.zeros((0, 0), dtype=np.int64),
            np.zeros((0,), dtype=np.int64),
            np.zeros((0,), dtype=np.int64),
        )

    spd = np.full((num_nodes, num_nodes), unreachable, dtype=np.int64)
    np.fill_diagonal(spd, 0)
    direct_rel = np.zeros((num_nodes, num_nodes), dtype=np.int64)

    es = np.asarray(edge_src, dtype=np.int64)
    ed = np.asarray(edge_dst, dtype=np.int64)
    er = np.asarray(edge_rel, dtype=np.int64)
    valid = (es >= 0) & (es < num_nodes) & (ed >= 0) & (ed < num_nodes)
    es, ed, er = es[valid], ed[valid], er[valid]

    if len(es) > 0:
        non_self = es != ed
        ns_s, ns_d, ns_r = es[non_self], ed[non_self], (er[non_self] % NUM_BASE_RELATIONS) + 1
        # Preserve first-seen direct relation per (s, d) pair by assigning reversed order
        direct_rel[ns_s[::-1], ns_d[::-1]] = ns_r[::-1]
        adj_f = np.zeros((num_nodes, num_nodes), dtype=np.float32)
        adj_f[ns_s, ns_d] = 1.0
        spd[ns_s, ns_d] = 1
        reach = adj_f.copy()
        for hop in range(2, max_hops + 1):
            reach = (reach @ adj_f > 0.5).astype(np.float32)
            newly_reached = (reach > 0.5) & (spd == unreachable)
            if not newly_reached.any():
                break
            spd[newly_reached] = hop

    catalog_nodes = np.flatnonzero(node_types == 0)
    roots = catalog_nodes if len(catalog_nodes) > 0 else np.array([0], dtype=np.int64)
    roots = roots[(roots >= 0) & (roots < num_nodes)]
    root_depth = spd[roots].min(axis=0) if len(roots) > 0 else np.full((num_nodes,), unreachable, dtype=np.int64)

    has_exec_trigger = bool(((node_types == 3) | (node_types == 5)).any())
    sink_mask_enc = (
        ((node_types == 3) | (node_types == 5) | (node_types == 7))
        if has_exec_trigger
        else ((node_types == 3) | (node_types == 5))
    )
    sink_nodes = np.flatnonzero(sink_mask_enc)
    sink_dist = (
        spd[:, sink_nodes].min(axis=1) if len(sink_nodes) > 0 else np.full((num_nodes,), unreachable, dtype=np.int64)
    )

    return spd, direct_rel, root_depth, sink_dist


def extract_single_graph_action_ir_np(
    node_x: np.ndarray | None,
    node_type: np.ndarray | None,
    edge_src: np.ndarray | None,
    edge_dst: np.ndarray | None,
    edge_rel: np.ndarray | None,
    spd: np.ndarray | None = None,
    root_depth: np.ndarray | None = None,
    sink_dist: np.ndarray | None = None,
) -> tuple[np.ndarray, bool]:
    """Compute pure 24D graph-topological ActionSubgraphIR with zero tabular lexical overlap."""
    ir = np.zeros((ACTION_IR_DIM,), dtype=np.float32)
    ir[12] = 1.0
    ir[13] = 1.0
    if node_x is None or node_type is None or len(node_type) == 0:
        return ir, False

    nx = np.asarray(node_x, dtype=np.float32)
    nt = np.asarray(node_type, dtype=np.int64)
    n = int(len(nt))
    es = np.asarray(edge_src if edge_src is not None else (), dtype=np.int64)
    ed = np.asarray(edge_dst if edge_dst is not None else (), dtype=np.int64)
    er = np.asarray(edge_rel if edge_rel is not None else (), dtype=np.int64)
    valid_e = (es >= 0) & (es < n) & (ed >= 0) & (ed < n)
    es, ed, er = es[valid_e], ed[valid_e], er[valid_e]

    if spd is None or root_depth is None or sink_dist is None:
        spd, _, root_depth, sink_dist = compute_dag_structural_encodings(n, nt, es, ed, er)

    n_action = float((nt == 3).sum())
    n_annot = float((nt == 4).sum())
    n_script = float((nt == 5).sum())
    has_exec_trigger = (n_action > 0.0) or (n_script > 0.0)
    sink_mask = ((nt == 3) | (nt == 5) | (nt == 7)) if has_exec_trigger else ((nt == 3) | (nt == 5))
    annot_mask = nt == 4
    in_cone = sink_dist < SPD_UNREACHABLE
    n_cone_stream = float(((nt == 6) & in_cone).sum())
    n_filespec = float((nt == 7).sum())
    n_sinks = float(sink_mask.sum())
    cone_mask = (nt == 0) | (nt == 3) | (nt == 4) | (nt == 5) | (nt == 7) | in_cone
    cone_tot = float(max(int(cone_mask.sum()), 1))

    ir[0] = np.log1p(n_action)
    ir[1] = np.log1p(n_annot)
    ir[2] = np.log1p(n_script)
    ir[3] = np.log1p(n_cone_stream)
    ir[4] = np.log1p(n_filespec) if has_exec_trigger else 0.0
    ir[5] = n_sinks / cone_tot
    ir[6] = n_annot / cone_tot

    orphan_col = nx[:, 6] if nx.shape[1] > 6 else np.zeros(n, dtype=np.float32)
    ir[7] = float(orphan_col[sink_mask].mean()) if sink_mask.any() else 0.0

    if len(er) > 0:
        src_t, dst_t = nt[es], nt[ed]
        trig_dst = (dst_t == 3) | (dst_t == 4) | (dst_t == 5) | (dst_t == 7)
        cat_trig_e = float((((er == 2) | (er == 5)) & trig_dst).sum())
        page_act_e = float(((er == 3) & trig_dst).sum())
        act_scr_e = float(((er == 4) & trig_dst).sum())
        annot_chain_e = float((((src_t == 4) & ((dst_t == 3) | (dst_t == 5))) | ((src_t == 2) & (dst_t == 4))).sum())
    else:
        cat_trig_e = page_act_e = act_scr_e = annot_chain_e = 0.0

    ir[8] = np.log1p(cat_trig_e)
    ir[9] = np.log1p(page_act_e)
    ir[10] = np.log1p(act_scr_e)
    ir[11] = np.log1p(annot_chain_e)

    if sink_mask.any():
        rd_sinks = root_depth[sink_mask]
        ir[12] = float(rd_sinks.min()) / float(SPD_UNREACHABLE)
        ir[14] = float((rd_sinks <= 2).mean())
        if annot_mask.any():
            sub_spd = spd[np.ix_(annot_mask, sink_mask)]
            min_per_sink = sub_spd.min(axis=0)
            ir[13] = float(min_per_sink.min()) / float(SPD_UNREACHABLE)
            ir[15] = float((min_per_sink <= 2).mean())

        phys_obs = sink_mask & (nx[:, 1] > 0.5)
        if phys_obs.any():
            ir[16] = float(nx[phys_obs, 0].max())
            ir[17] = float(nx[phys_obs, 0].mean())
        stream_obs = sink_mask & (nx[:, 3] > 0.5)
        if stream_obs.any():
            ir[18] = float(nx[stream_obs, 2].max())
        ir[19] = float((nx[sink_mask, 3] > 0.5).mean())
        if nx.shape[1] > 5:
            ir[20] = float(nx[sink_mask, 5].max())
        if nx.shape[1] >= 9:
            ir[21] = float(nx[sink_mask, 7:9].mean())
        ir[22] = float(np.log1p(in_cone.sum()))
        if len(es) > 0:
            cone_edges = int((in_cone[es] & in_cone[ed]).sum())
        else:
            cone_edges = 0
        ir[23] = float(np.log1p(cone_edges))
    return ir, True


def collate_v4_numpy_feed(
    tab_batch: np.ndarray,
    graphs_batch: list[tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray] | None],
) -> dict[str, np.ndarray]:
    """Build branchless ONNX input feed dictionary (always N >= 1) for PDFTransGraphV4."""
    bsz = int(tab_batch.shape[0])
    max_n = max(1, max((len(g[0]) for g in graphs_batch if g is not None and len(g[0]) > 0), default=0))
    nx_pad = np.zeros((bsz, max_n, 23), dtype=np.float32)
    nt_pad = np.zeros((bsz, max_n), dtype=np.int64)
    deg_pad = np.zeros((bsz, max_n, 2), dtype=np.float32)
    mask_pad = np.zeros((bsz, max_n), dtype=np.float32)
    spd_pad = np.full((bsz, max_n, max_n), SPD_UNREACHABLE, dtype=np.int64)
    rel_pad = np.zeros((bsz, max_n, max_n), dtype=np.int64)
    rd_pad = np.full((bsz, max_n), SPD_UNREACHABLE, dtype=np.int64)
    sd_pad = np.full((bsz, max_n), SPD_UNREACHABLE, dtype=np.int64)
    sum_12 = np.zeros((bsz, GRAPH_SUMMARY_DIM), dtype=np.float32)
    ir_batch = np.zeros((bsz, ACTION_IR_DIM), dtype=np.float32)
    ir_batch[:, 12] = 1.0
    ir_batch[:, 13] = 1.0
    ir_active = np.zeros((bsz, 1), dtype=np.float32)

    for b_i, g in enumerate(graphs_batch):
        if g is None or len(g[0]) == 0:
            continue
        nx, nt, es, ed, er = g
        n = int(len(nx))
        if n == 0:
            continue
        spd, direct_rel, rd, sd = compute_dag_structural_encodings(n, nt, es, ed, er)
        ir_vec, act = extract_single_graph_action_ir_np(nx, nt, es, ed, er, spd, rd, sd)
        ir_batch[b_i] = ir_vec
        ir_active[b_i, 0] = 1.0 if act else 0.0

        nx_pad[b_i, :n] = nx
        nt_pad[b_i, :n] = nt
        mask_pad[b_i, :n] = 1.0
        spd_pad[b_i, :n, :n] = spd
        rel_pad[b_i, :n, :n] = direct_rel
        rd_pad[b_i, :n] = rd
        sd_pad[b_i, :n] = sd

        valid_pair = (es >= 0) & (es < n) & (ed >= 0) & (ed < n) if len(es) > 0 else np.zeros((0,), dtype=bool)
        v_es = es[valid_pair] if valid_pair.any() else np.zeros((0,), dtype=np.int64)
        v_ed = ed[valid_pair] if valid_pair.any() else np.zeros((0,), dtype=np.int64)
        out_deg = np.bincount(v_es, minlength=n).astype(np.float32) if len(v_es) > 0 else np.zeros(n, np.float32)
        in_deg = np.bincount(v_ed, minlength=n).astype(np.float32) if len(v_ed) > 0 else np.zeros(n, np.float32)
        deg_pad[b_i, :n, 0] = np.log1p(out_deg)
        deg_pad[b_i, :n, 1] = np.log1p(in_deg)
        type_cnts = np.bincount(np.clip(nt, 0, NUM_NODE_TYPES - 1), minlength=NUM_NODE_TYPES).astype(np.float32)
        orphan_cnt = float(((out_deg + in_deg) == 0.0).sum())
        sum_12[b_i] = np.log1p(
            np.array([*type_cnts.tolist(), float(n), float(len(v_es)), orphan_cnt], dtype=np.float32)
        )

    return {
        "tabular_features": np.ascontiguousarray(tab_batch, dtype=np.float32),
        "action_ir_features": np.ascontiguousarray(ir_batch, dtype=np.float32),
        "action_ir_active": np.ascontiguousarray(ir_active, dtype=np.float32),
        "node_features": np.ascontiguousarray(nx_pad, dtype=np.float32),
        "node_types": np.ascontiguousarray(nt_pad, dtype=np.int64),
        "deg_features": np.ascontiguousarray(deg_pad, dtype=np.float32),
        "node_pad_mask": np.ascontiguousarray(mask_pad, dtype=np.float32),
        "spd": np.ascontiguousarray(spd_pad, dtype=np.int64),
        "direct_rel": np.ascontiguousarray(rel_pad, dtype=np.int64),
        "root_depth": np.ascontiguousarray(rd_pad, dtype=np.int64),
        "sink_dist": np.ascontiguousarray(sd_pad, dtype=np.int64),
        "summary_12": np.ascontiguousarray(sum_12, dtype=np.float32),
    }


def single_graph_tuple(
    nf: Any, nt: Any, ei: Any, er: Any, graph_present: bool
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray] | None:
    """Convert ingested single-PDF graph arrays/tensors into the 5-tuple expected by v4 collation."""
    if not graph_present:
        return None
    nx_np = nf.detach().cpu().numpy() if hasattr(nf, "detach") else np.asarray(nf, dtype=np.float32)
    nt_np = nt.detach().cpu().numpy() if hasattr(nt, "detach") else np.asarray(nt, dtype=np.int64)
    if len(nx_np) == 0:
        return None
    ei_np = ei.detach().cpu().numpy() if hasattr(ei, "detach") else np.asarray(ei, dtype=np.int64)
    er_np = er.detach().cpu().numpy() if hasattr(er, "detach") else np.asarray(er, dtype=np.int64)
    if ei_np.ndim == 2 and ei_np.shape[1] > 0:
        es_np, ed_np = ei_np[0], ei_np[1]
    else:
        es_np = np.zeros((0,), dtype=np.int64)
        ed_np = np.zeros((0,), dtype=np.int64)
        er_np = np.zeros((0,), dtype=np.int64)
    return (
        np.asarray(nx_np, dtype=np.float32),
        np.asarray(nt_np, dtype=np.int64),
        np.asarray(es_np, dtype=np.int64),
        np.asarray(ed_np, dtype=np.int64),
        np.asarray(er_np, dtype=np.int64),
    )

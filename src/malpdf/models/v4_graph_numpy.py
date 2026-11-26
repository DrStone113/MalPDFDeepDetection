"""Torch-free pure-NumPy DAG structural encodings, 24D ActionSubgraphIR, and ONNX batch collation for v4."""

from __future__ import annotations

import math
from typing import Any

import numpy as np

MULTILABEL_V4_CONTRACT_VERSION = "pdf-multilabel-v4-regime-b"
EXPECTED_MULTILABEL_HEAD_IDS_V4: tuple[str, ...] = (
    "js_script_exec",
    "auto_open_trigger",
    "obfuscated_payload",
    "buffer_loop_staging",
    "active_form_or_exploit",
    "embedded_dropper_or_launch",
    "suspicious_uri_redirect",
    "structural_parser_evasion",
)
EXPECTED_REGIME_B_NAMES_V4: tuple[str, ...] = (
    "lexical_AA",
    "lexical_EmbeddedFile",
    "lexical_Encrypt",
    "lexical_JBIG2Decode",
    "lexical_JS",
    "lexical_JavaScript",
    "lexical_Launch",
    "lexical_ObjStm",
    "lexical_OpenAction",
    "lexical_Resources",
    "lexical_RichMedia",
    "lexical_Root",
    "lexical_URI",
    "lexical_XFA",
    "lexical_endobj",
    "lexical_endstream",
    "lexical_obj",
    "lexical_page_command",
    "lexical_stream",
    "lexical_trailer",
    "lexical_xref",
    "lexical_startxref",
    "raw_size_bytes",
    "raw_entropy",
    "raw_header_offset",
    "js_per_obj",
    "stream_per_obj",
    "obj_endobj_diff",
    "stream_endstream_diff",
)
EXPECTED_MULTILABEL_V4_ONNX_INPUTS: tuple[str, ...] = (
    "tabular_features",
    "action_ir_features",
    "action_ir_active",
    "node_features",
    "node_types",
    "deg_features",
    "node_pad_mask",
    "spd",
    "direct_rel",
    "root_depth",
    "sink_dist",
    "summary_12",
    "aux_telemetry_features",
)
EXPECTED_MULTILABEL_V4_ONNX_OUTPUTS: tuple[str, ...] = ("label_logits", "mal_logit")

NUM_NODE_TYPES = 9
NUM_BASE_RELATIONS = 8
GRAPH_SUMMARY_DIM = 12
MAX_SPD_HOPS = 8
SPD_UNREACHABLE = MAX_SPD_HOPS + 1
ACTION_IR_DIM = 24
AUX_TELEMETRY_V4_DIM = 16

AUX_TELEMETRY_V4_NAMES: tuple[str, ...] = (
    "log1p_lexical_acroform",
    "log1p_escaped_name_candidates",
    "ast_observed",
    "log1p_ast_node_count",
    "log1p_ast_max_depth",
    "log1p_ast_loops",
    "log1p_ast_computed_members",
    "ast_call_ratio",
    "ast_has_loop",
    "js_has_deobf_call",
    "js_has_exploit_api",
    "js_has_launch_or_export",
    "has_action_launch_or_gotor",
    "has_action_submit_or_uri",
    "has_embedded_payload",
    "has_parser_or_stream_anomaly",
)

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


def extract_runtime_aux_v4_np(
    *,
    lexical_acroform: float,
    escaped_name_candidates: float,
    ast_observed: bool,
    ast_node_count: float,
    ast_max_depth: float,
    ast_loops: float,
    ast_computed_members: float,
    ast_call_expressions: float,
    ast_has_loop: bool,
    js_has_deobf_call: bool,
    js_has_exploit_api: bool,
    js_has_launch_or_export: bool,
    has_action_launch_or_gotor: bool,
    has_action_submit_or_uri: bool,
    has_embedded_payload: bool,
    has_parser_or_stream_anomaly: bool,
) -> np.ndarray:
    """Build bounded 16D auxiliary telemetry vector [1, 16] with zero linear page/size dependence."""
    out = np.zeros((1, AUX_TELEMETRY_V4_DIM), dtype=np.float32)
    out[0, 0] = float(np.log1p(max(0.0, float(lexical_acroform))))
    out[0, 1] = float(np.log1p(max(0.0, float(escaped_name_candidates))))
    if ast_observed:
        nc = max(0.0, float(ast_node_count))
        out[0, 2] = 1.0
        out[0, 3] = float(np.log1p(nc))
        out[0, 4] = float(np.log1p(max(0.0, float(ast_max_depth))))
        out[0, 5] = float(np.log1p(max(0.0, float(ast_loops))))
        out[0, 6] = float(np.log1p(max(0.0, float(ast_computed_members))))
        out[0, 7] = float(np.clip(max(0.0, float(ast_call_expressions)) / max(nc, 1.0), 0.0, 1.0)) if nc > 0.0 else 0.0
        out[0, 8] = 1.0 if ast_has_loop else 0.0
    out[0, 9] = 1.0 if js_has_deobf_call else 0.0
    out[0, 10] = 1.0 if js_has_exploit_api else 0.0
    out[0, 11] = 1.0 if js_has_launch_or_export else 0.0
    out[0, 12] = 1.0 if has_action_launch_or_gotor else 0.0
    out[0, 13] = 1.0 if has_action_submit_or_uri else 0.0
    out[0, 14] = 1.0 if has_embedded_payload else 0.0
    out[0, 15] = 1.0 if has_parser_or_stream_anomaly else 0.0
    return np.ascontiguousarray(out, dtype=np.float32)


_V4_NODE_KIND_SET: frozenset[str] = frozenset(
    {"catalog", "pages", "page", "action", "script", "stream", "acroform", "filespec", "pdf_object"}
)


def _canonical_23d_node_features_np(ingest_data: dict[str, Any]) -> np.ndarray | None:
    nf = ingest_data.get("node_features")
    if nf is None:
        return None
    nx_np = nf.detach().cpu().numpy() if hasattr(nf, "detach") else np.asarray(nf, dtype=np.float32)
    if nx_np.ndim != 2:
        return None
    if nx_np.shape[1] == 23:
        return np.asarray(nx_np, dtype=np.float32)
    if nx_np.shape[1] != 19:
        return None
    out = np.zeros((nx_np.shape[0], 23), dtype=np.float32)
    if not bool(ingest_data.get("graph_present", True)):
        return out
    recs = [r for r in (ingest_data.get("raw_records") or [])[:200] if r.get("kind") in _V4_NODE_KIND_SET]
    for i in range(nx_np.shape[0]):
        if i < len(recs):
            r = recs[i]
            size_val = float(r.get("phys_span_bytes") or r.get("size_bytes") or 0.0)
            has_s = 1.0 if r.get("has_stream") else 0.0
            log_size = float(np.log1p(max(0.0, size_val)))
            phys_mask = 1.0 if size_val > 0.0 else 0.0
            raw_stream = r.get("raw_stream_bytes")
            stream_val = float(raw_stream) if isinstance(raw_stream, int) and raw_stream >= 0 else size_val
            stream_log = float(np.log1p(max(0.0, stream_val))) if has_s > 0.0 else 0.0
            rep_flag = 1.0 if r.get("is_repaired") else 0.0
            out[i, :6] = (log_size, phys_mask, stream_log, has_s, 1.0, rep_flag)
        else:
            log_size = float(nx_np[i, 0])
            has_s = 1.0 if float(nx_np[i, 1]) > 0.5 else 0.0
            out[i, :6] = (
                log_size,
                1.0 if log_size > 0.0 else 0.0,
                log_size if has_s > 0.0 else 0.0,
                has_s,
                1.0,
                0.0,
            )
        out[i, 6] = nx_np[i, 2]
        out[i, 7:23] = nx_np[i, 3:19]
    return out


def validate_multilabel_v4_contract_np(contract: dict[str, Any]) -> None:
    if contract.get("contract_version") != MULTILABEL_V4_CONTRACT_VERSION:
        raise ValueError("invalid_multilabel_v4_contract_version")
    mcfg = contract.get("model_config")
    if not isinstance(mcfg, dict):
        raise ValueError("invalid_multilabel_v4_model_config")
    hidden_dim = mcfg.get("hidden_dim")
    num_heads = mcfg.get("num_heads")
    num_layers = mcfg.get("num_graph_layers")
    if (
        mcfg.get("tab_dim") != len(EXPECTED_REGIME_B_NAMES_V4)
        or mcfg.get("action_ir_dim") != ACTION_IR_DIM
        or mcfg.get("node_dim") != 23
        or mcfg.get("aux_dim") != AUX_TELEMETRY_V4_DIM
        or mcfg.get("num_labels") != len(EXPECTED_MULTILABEL_HEAD_IDS_V4)
        or mcfg.get("num_node_types") != NUM_NODE_TYPES
        or mcfg.get("num_base_relations") != NUM_BASE_RELATIONS
        or not isinstance(hidden_dim, int)
        or not isinstance(num_heads, int)
        or not isinstance(num_layers, int)
        or hidden_dim <= 0
        or num_heads <= 0
        or num_layers <= 0
        or hidden_dim % num_heads != 0
    ):
        raise ValueError("invalid_multilabel_v4_model_config")
    if tuple(contract.get("tab_feature_names") or ()) != EXPECTED_REGIME_B_NAMES_V4:
        raise ValueError("invalid_multilabel_v4_tab_feature_names")
    if tuple(contract.get("aux_feature_names") or ()) != AUX_TELEMETRY_V4_NAMES:
        raise ValueError("invalid_multilabel_v4_aux_feature_names")
    labels = contract.get("labels") or []
    if tuple(str(item.get("id", "")) for item in labels) != EXPECTED_MULTILABEL_HEAD_IDS_V4:
        raise ValueError("invalid_multilabel_v4_head_order")
    temps = contract.get("label_temperatures") or []
    if len(temps) != len(EXPECTED_MULTILABEL_HEAD_IDS_V4) or not all(
        isinstance(t, (int, float)) and math.isfinite(float(t)) and float(t) > 0.0 for t in temps
    ):
        raise ValueError("invalid_multilabel_v4_label_temperatures")
    mal_t = contract.get("mal_temperature")
    if not isinstance(mal_t, (int, float)) or not math.isfinite(float(mal_t)) or float(mal_t) <= 0.0:
        raise ValueError("invalid_multilabel_v4_mal_temperature")
    center = np.asarray(contract.get("tab29_center") or (), dtype=np.float64)
    scale = np.asarray(contract.get("tab29_scale") or (), dtype=np.float64)
    if (
        center.shape != (len(EXPECTED_REGIME_B_NAMES_V4),)
        or scale.shape != (len(EXPECTED_REGIME_B_NAMES_V4),)
        or not np.isfinite(center).all()
        or not np.isfinite(scale).all()
        or np.any(scale == 0.0)
    ):
        raise ValueError("invalid_multilabel_v4_scaler")
    for item in labels:
        thr = item.get("threshold")
        enabled = item.get("model_flag_enabled", True)
        if not isinstance(enabled, bool):
            raise ValueError("invalid_multilabel_v4_model_flag_enabled")
        if not isinstance(thr, (int, float)) or not math.isfinite(float(thr)) or float(thr) <= 0.0:
            raise ValueError("invalid_multilabel_v4_head_threshold")
        if enabled and float(thr) > 1.0:
            raise ValueError("invalid_multilabel_v4_enabled_threshold_range")


def build_runtime_multilabel_v4_feed_np(
    *,
    raw_pdf_bytes: bytes,
    raw_tokens: dict[str, int],
    ingest_data: dict[str, Any],
    tab29_center: np.ndarray,
    tab29_scale: np.ndarray,
    escaped_names: float,
    has_obfuscated_js: bool,
    all_indicators: set[str],
    matched_cves: list[tuple[str, str]],
    has_export_dropper: bool,
    has_launch: bool,
    has_submit_form: bool,
    has_embedded_file: bool,
    has_stream_anomaly: bool,
    v4_graph_feed: dict[str, np.ndarray] | None = None,
) -> dict[str, np.ndarray] | None:
    raw_29 = ingest_data.get("v4_raw_feature_vec")
    if not isinstance(raw_29, list) or len(raw_29) != len(EXPECTED_REGIME_B_NAMES_V4):
        if not raw_pdf_bytes:
            return None
        header_pos = max(raw_pdf_bytes.find(b"%PDF-"), 0)
        denom = max(float(raw_tokens.get("obj", 0)), 1.0)
        raw_29 = [
            float(raw_tokens.get(name.removeprefix("lexical_"), 0))
            for name in EXPECTED_REGIME_B_NAMES_V4
            if name.startswith("lexical_")
        ]
        raw_29.extend(
            (
                float(len(raw_pdf_bytes)),
                float(ingest_data.get("raw_entropy") or 0.0),
                float(header_pos),
                float(raw_tokens.get("JS", 0) + raw_tokens.get("JavaScript", 0)) / denom,
                float(raw_tokens.get("stream", 0)) / denom,
                float(raw_tokens.get("obj", 0) - raw_tokens.get("endobj", 0)),
                float(raw_tokens.get("stream", 0) - raw_tokens.get("endstream", 0)),
            )
        )
    arr_29 = np.asarray(raw_29, dtype=np.float64).reshape(1, -1)
    if not np.isfinite(arr_29).all():
        return None
    log_29 = np.sign(arr_29) * np.log1p(np.abs(arr_29))
    tab_29 = np.ascontiguousarray(((log_29 - tab29_center) / tab29_scale).astype(np.float32), dtype=np.float32)

    if (
        isinstance(v4_graph_feed, dict)
        and all(k in v4_graph_feed for k in EXPECTED_MULTILABEL_V4_ONNX_INPUTS[:-1])
        and np.asarray(v4_graph_feed["action_ir_features"]).shape == (1, ACTION_IR_DIM)
    ):
        base_feed = {
            k: np.ascontiguousarray(v4_graph_feed[k])
            for k in EXPECTED_MULTILABEL_V4_ONNX_INPUTS[:-1]
            if k != "tabular_features"
        }
        base_feed["tabular_features"] = tab_29
    else:
        nf_23 = _canonical_23d_node_features_np(ingest_data)
        g_tup = (
            single_graph_tuple(
                nf_23,
                ingest_data.get("node_types"),
                ingest_data.get("edge_index"),
                ingest_data.get("edge_rel"),
                bool(ingest_data.get("graph_present", True)),
            )
            if nf_23 is not None
            else None
        )
        base_feed = collate_v4_numpy_feed(tab_29, [g_tup])

    records = ingest_data.get("raw_records") or []
    encryption = ingest_data.get("encryption_analysis") or {}
    triggers = set(ingest_data.get("non_js_triggers") or ())
    ast_stats = ingest_data.get("ast_stats") or {}
    ast_counts = ingest_data.get("ast_node_counts") or {}

    ast_obs = (not encryption.get("password_locked", False)) and (
        not triggers.intersection(
            {"javascript_body_unavailable", "action_inspection_limit", "supplemental_inspection_incomplete"}
        )
    )
    loops_val = float(ast_stats.get("loops") or 0.0)
    has_loop = (
        loops_val > 0.0
        or int(ast_counts.get("ForStatement") or 0) > 0
        or int(ast_counts.get("WhileStatement") or 0) > 0
    )
    has_exploit_api = bool(matched_cves) or bool(
        all_indicators.intersection(
            {"util_printf_overflow", "collab_overflow", "get_icon_overflow", "media_newplayer_uaf"}
        )
    )
    has_launch_or_export = bool(has_export_dropper) or ("launch_url" in all_indicators)
    has_act_launch = bool(has_launch) or any(
        r.get("action_type") in {"/Launch", "/GoToR", "/GoToE", "/ImportData"} for r in records
    )
    phishing = ingest_data.get("phishing_analysis") or {}
    qr = ingest_data.get("qr_analysis") or {}
    has_act_uri = (
        bool(has_submit_form)
        or bool(phishing.get("suspicious_uris"))
        or bool(qr.get("suspicious_uris"))
        or any(
            r.get("action_type") == "/SubmitForm"
            or (r.get("action_type") == "/URI" and bool(r.get("is_threat_trigger")))
            for r in records
        )
    )
    diff = ingest_data.get("differential_analysis") or {}
    header_offset_pos = (raw_pdf_bytes[:1024].find(b"%PDF-") > 0) if raw_pdf_bytes else False
    has_struct_anom = (
        bool(has_stream_anomaly)
        or bool(diff.get("has_differential_evasion"))
        or abs(float(raw_tokens.get("obj", 0) - raw_tokens.get("endobj", 0))) > 0.0
        or abs(float(raw_tokens.get("stream", 0) - raw_tokens.get("endstream", 0))) > 0.0
        or header_offset_pos
    )
    ast_total_nodes = float(
        ast_stats.get("total_nodes")
        if ast_stats.get("total_nodes") is not None
        else (ast_stats.get("node_count") or 0.0)
    )
    ast_calls = float(
        ast_counts.get("CallExpression")
        if ast_counts.get("CallExpression") is not None
        else (ast_stats.get("call_count") or 0.0)
    )
    aux_16 = extract_runtime_aux_v4_np(
        lexical_acroform=float(raw_tokens.get("AcroForm", 0) + raw_tokens.get("Acroform", 0)),
        escaped_name_candidates=float(escaped_names),
        ast_observed=ast_obs,
        ast_node_count=ast_total_nodes,
        ast_max_depth=float(ast_stats.get("max_depth") or 0.0),
        ast_loops=loops_val,
        ast_computed_members=float(ast_stats.get("computed_members") or 0.0),
        ast_call_expressions=ast_calls,
        ast_has_loop=has_loop,
        js_has_deobf_call=bool(has_obfuscated_js),
        js_has_exploit_api=has_exploit_api,
        js_has_launch_or_export=has_launch_or_export,
        has_action_launch_or_gotor=has_act_launch,
        has_action_submit_or_uri=has_act_uri,
        has_embedded_payload=bool(has_embedded_file),
        has_parser_or_stream_anomaly=has_struct_anom,
    )
    return {**base_feed, "aux_telemetry_features": aux_16}

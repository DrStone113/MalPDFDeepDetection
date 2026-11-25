"""Train and evaluate PDF-TransGraph v4 on frozen numeric inputs."""

from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

import numpy as np
from sklearn.metrics import average_precision_score
import torch
import torch.nn.functional as F

REPO = Path(__file__).resolve().parents[2]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from scripts.lab.score_benign_ood import digest, read_json  # noqa: E402
from scripts.lab.train_eval_transgraph_v3 import (  # noqa: E402
    IDX,
    REGIME_B_INDICES,
    SUPPLEMENT_PREFIX,
    CSRGraphCorpus,
    _load_controls,
    _recompute_derived,
    _update_ema,
    apply_temperature,
    compute_debiased_weights,
    compute_slice_metrics,
    fit_temperature,
    load_pooled_corpus,
    perturb_raw_format,
    set_all_seeds,
    simulate_objstm_tabular_mask,
    slice_regime_inputs,
)

from malpdf.evaluation.operating_point import midpoint_macro_f1  # noqa: E402
from malpdf.evaluation.problem_space_attack import graft_benign_subtree_pair  # noqa: E402
from malpdf.extraction.numeric_export import MAX_NODES  # noqa: E402
from malpdf.features.contract_v3 import FEATURES, RobustTransform  # noqa: E402
from malpdf.models.pdf_transgraph_v4 import (  # noqa: E402
    ACTION_IR_DIM,
    PDFTransGraphV4,
    TransGraphV4Config,
    benign_graft_stability_loss,
    build_padded_graph_tensors,
    compute_dag_structural_encodings,
    extract_observable_action_ir_np,
    extract_single_graph_action_ir_np,
    load_v4_weights_npz,
    save_v4_weights_npz,
    subtree_monotonic_loss,
)

POOL_ROOT = REPO / "data/processed/pooled_bulk"
OFFLINE = POOL_ROOT / "offline_provenance"
DEFAULT_POOL = POOL_ROOT / "unlabeled/run_20261122T054134Z_16abd6134688/transgraph_pooled.json.gz"
DEFAULT_TABULAR = OFFLINE / "tabular_v3.jsonl.gz"
DEFAULT_LABEL_VIEW = OFFLINE / "training_labels_20261122T055618Z.jsonl"
DEFAULT_SPLIT_VIEW = OFFLINE / "clean_split_20261122T064432Z.jsonl"
DEFAULT_CONTROLS = OFFLINE / "reviewed_controls_v3.json"
DEFAULT_SUPP = POOL_ROOT / "benign_v32_cohort/v32_benign_supplement.json"
DEFAULT_STRESS = OFFLINE / "byte_level_stress_v3.json"
LOCKED_V3 = REPO / "reports/experiments/transgraph_v3/run_20261123T095927Z_16abd6134688"
STRESS_SHA256 = "1e13f4f5cff5c9eeeefc884e80a6ee28df83a9fb7c693208f347c9a4a48fd90f"
FULL_MODEL = "pdf_transgraph_v4"
ABLATIONS = {
    "gin_tab_baseline": ({"encoder_type": "gin", "enable_action_ir": False, "enable_spd_bias": False}, False),
    "v4_no_action_ir": ({"enable_action_ir": False}, True),
    "v4_no_spd_bias": ({"enable_spd_bias": False}, True),
    "v4_no_monotonic_loss": ({}, False),
    FULL_MODEL: ({}, True),
}
REGRESSION_DISCLOSURE = (
    "Test_Internal, Phase 2 Byte Stress, reviewed controls and Subset B reuse established study cohorts. "
    "The v4 results are retrospective regression evidence. Subset B scored identities are screened against "
    "the training and validation inputs, including the benign supplement."
)
PackedGraph = tuple[
    np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray
]
EMPTY_IR, _ = extract_single_graph_action_ir_np(None, None, None, None, None)


def write_json(path: Path, data: dict) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, allow_nan=False)
        stream.write("\n")


def pack_graph(graph: Any) -> tuple[np.ndarray, ...] | None:
    if graph is None or not len(graph[0]):
        return None
    nx = np.asarray(graph[0], dtype=np.float32)
    nt, es, ed, er = (np.asarray(v, dtype=np.int64) for v in graph[1:5])
    n = len(nx)
    spd, rel, rd, sd = compute_dag_structural_encodings(n, nt, es, ed, er)
    valid_pair = (es >= 0) & (es < n) & (ed >= 0) & (ed < n) if len(es) > 0 else np.zeros((0,), dtype=bool)
    v_es = es[valid_pair] if valid_pair.any() else np.zeros((0,), dtype=np.int64)
    v_ed = ed[valid_pair] if valid_pair.any() else np.zeros((0,), dtype=np.int64)
    out_deg = np.bincount(v_es, minlength=n).astype(np.float32) if len(v_es) > 0 else np.zeros(n, np.float32)
    in_deg = np.bincount(v_ed, minlength=n).astype(np.float32) if len(v_ed) > 0 else np.zeros(n, np.float32)
    deg = np.stack((np.log1p(out_deg), np.log1p(in_deg)), axis=-1)
    type_cnts = np.bincount(np.clip(nt, 0, 8), minlength=9).astype(np.float32)
    orphan_cnt = float(((out_deg + in_deg) == 0.0).sum())
    sum_12 = np.log1p(np.array([*type_cnts.tolist(), float(n), float(len(v_es)), orphan_cnt], dtype=np.float32))
    return nx, nt, es, ed, er, spd.astype(np.uint8), rel.astype(np.uint8), rd, sd, deg, sum_12


def precompute_corpus(corpus: CSRGraphCorpus) -> tuple[list[PackedGraph | None], np.ndarray, np.ndarray]:
    n_total = len(corpus.shas)
    graphs: list[PackedGraph | None] = [None] * n_total
    for i in np.flatnonzero(corpus.graph_present):
        nodes = slice(corpus.node_ptr[i], corpus.node_ptr[i + 1])
        edges = slice(corpus.edge_ptr[i], corpus.edge_ptr[i + 1])
        graphs[i] = pack_graph(
            (
                corpus.node_x[nodes],
                corpus.node_type[nodes],
                corpus.edge_src[edges],
                corpus.edge_dst[edges],
                corpus.edge_rel[edges],
            )
        )
    ir, active = extract_observable_action_ir_np(
        node_x=corpus.node_x,
        node_type=corpus.node_type,
        node_ptr=corpus.node_ptr,
        row_indices=np.arange(n_total),
        precomputed_graphs=graphs,
    )
    return graphs, ir, active


def packed_action_ir(graphs: list[PackedGraph | None]) -> tuple[np.ndarray, np.ndarray]:
    if not graphs:
        return np.empty((0, ACTION_IR_DIM), dtype=np.float32), np.empty(0, dtype=bool)
    ir, active = zip(
        *[
            (EMPTY_IR, False) if graph is None else extract_single_graph_action_ir_np(*graph[:6], graph[7], graph[8])
            for graph in graphs
        ],
        strict=True,
    )
    return np.stack(ir), np.asarray(active, dtype=bool)


def _tensor(values: np.ndarray, device: torch.device) -> torch.Tensor:
    return torch.from_numpy(values).to(device)


def _make_macro_bucketed_batches(
    positions: np.ndarray,
    node_counts: np.ndarray,
    batch_size: int,
    rng: np.random.Generator,
) -> list[np.ndarray]:
    """Group positions into token-budgeted graph-size tiers so peak VRAM stays well under 2 GiB on 8 GB GPUs."""
    tier_specs = (
        (positions[node_counts[positions] <= 64], batch_size),
        (positions[(node_counts[positions] > 64) & (node_counts[positions] <= 160)], max(16, min(batch_size, 32))),
        (positions[node_counts[positions] > 160], max(8, min(batch_size, 16))),
    )
    batches: list[np.ndarray] = []
    for tier, tier_bsz in tier_specs:
        if len(tier) == 0:
            continue
        shuf = rng.permutation(tier)
        for s in range(0, len(shuf), tier_bsz):
            batches.append(shuf[s : s + tier_bsz])
    if len(batches) > 1:
        order = rng.permutation(len(batches))
        batches = [batches[int(i)] for i in order]
    return batches


@torch.inference_mode()
def predict_v4_logits(
    model: PDFTransGraphV4,
    graphs: list[PackedGraph | None],
    ir: np.ndarray,
    active: np.ndarray,
    tab: np.ndarray,
    indices: np.ndarray,
    device: torch.device,
    *,
    batch_size: int = 128,
) -> tuple[np.ndarray, np.ndarray]:
    model.eval()
    if not len(indices):
        return np.empty(0, dtype=np.float32), np.empty((0, 3), dtype=np.float32)
    lengths = np.asarray([0 if graphs[int(i)] is None else len(graphs[int(i)][0]) for i in indices], dtype=np.int32)
    sort_order = np.argsort(lengths, kind="stable")
    sorted_indices = indices[sort_order]
    sorted_lengths = lengths[sort_order]
    logits, weights = [], []
    start = 0
    while start < len(sorted_indices):
        rem_max = int(sorted_lengths[min(len(sorted_lengths) - 1, start + batch_size - 1)])
        step = 32 if rem_max > 160 else (64 if rem_max > 64 else batch_size)
        batch = sorted_indices[start : start + step]
        start += step
        out = model(
            _tensor(tab[batch], device),
            _tensor(ir[batch], device),
            _tensor(active[batch], device),
            *build_padded_graph_tensors([graphs[i] for i in batch], device),
        )
        logits.append(out["logits"].cpu().numpy())
        weights.append(out["weights"].cpu().numpy())
    all_logits = np.concatenate(logits)
    all_weights = np.concatenate(weights)
    inv_order = np.empty_like(sort_order)
    inv_order[sort_order] = np.arange(len(sort_order))
    return all_logits[inv_order], all_weights[inv_order]


def predict_v4_custom(
    model: PDFTransGraphV4,
    transform: RobustTransform,
    raw_73: np.ndarray,
    raw_graphs: list[Any],
    device: torch.device,
    *,
    batch_size: int = 128,
) -> tuple[np.ndarray, np.ndarray]:
    graphs = [pack_graph(g) for g in raw_graphs]
    ir, active = packed_action_ir(graphs)
    tab, _, _, _ = slice_regime_inputs(*transform.transform(raw_73), "regime_b")
    return predict_v4_logits(model, graphs, ir, active, tab, np.arange(len(tab)), device, batch_size=batch_size)


def _resource_limit_features(raw: np.ndarray, rows: np.ndarray) -> None:
    for name, increment in (
        ("lexical_page_command", 50),
        ("lexical_obj", 150),
        ("lexical_endobj", 150),
        ("lexical_stream", 60),
        ("lexical_endstream", 60),
        ("raw_size_bytes", 65536),
    ):
        raw[rows, IDX[name]] += increment
    _recompute_derived(raw)


def _split_logical_batch_into_microbatches(
    positions: np.ndarray,
    node_counts: np.ndarray,
) -> list[np.ndarray]:
    """Split a uniform logical batch into size-sorted micro-batches to cap VRAM without altering sample weights."""
    order = np.argsort(node_counts[positions], kind="stable")
    sorted_pos = positions[order]
    sorted_len = node_counts[sorted_pos]
    micros: list[np.ndarray] = []
    start = 0
    n = len(sorted_pos)
    while start < n:
        cur_len = int(sorted_len[start])
        if cur_len > 160:
            step = 16
        elif cur_len > 64:
            step = 32
        else:
            # Cap at <= 64 boundary or 128 items
            end_64 = int(np.searchsorted(sorted_len, 64, side="right"))
            step = min(128, max(1, end_64 - start))
        micros.append(sorted_pos[start : start + step])
        start += step
    return micros


def format_view(
    raw: np.ndarray,
    can_linearize: np.ndarray,
    ir: np.ndarray,
    active: np.ndarray,
    graphs: list[PackedGraph | None],
    rng: np.random.Generator,
    *,
    drop_prob: float = 0.10,
    attach_aug_prob: float = 0.0,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, list[PackedGraph | None]]:
    perturbed = perturb_raw_format(raw, can_linearize, rng, enable_padding=True)
    has_graph = np.asarray([g is not None for g in graphs], dtype=bool)
    perturbed = simulate_objstm_tabular_mask(perturbed, has_graph, rng, prob=0.20)
    if attach_aug_prob > 0.0:
        att_draw = (rng.random(len(raw)) < attach_aug_prob) & has_graph
        if att_draw.any():
            ir, active, graphs = ir.copy(), active.copy(), graphs.copy()
            for idx_r in np.flatnonzero(att_draw):
                g_cur = graphs[int(idx_r)]
                if g_cur is None:
                    continue
                k_att = int(rng.integers(4, 96))
                perturbed[idx_r, IDX["lexical_EmbeddedFile"]] += float(k_att)
                perturbed[idx_r, IDX["lexical_obj"]] += float(2 * k_att)
                perturbed[idx_r, IDX["lexical_endobj"]] += float(2 * k_att)
                perturbed[idx_r, IDX["lexical_stream"]] += float(k_att)
                perturbed[idx_r, IDX["lexical_endstream"]] += float(k_att)
                perturbed[idx_r, IDX["raw_size_bytes"]] += float(k_att * int(rng.integers(2048, 16384)))
                nx_b, nt_b, es_b, ed_b, er_b = g_cur[:5]
                room = MAX_NODES - len(nx_b)
                if room > 0:
                    add_m = min(k_att, room)
                    add_nx = np.zeros((add_m, nx_b.shape[1]), dtype=np.float32)
                    add_nt = np.full((add_m,), 7, dtype=np.int64)
                    cat_idx = int(np.flatnonzero(nt_b == 0)[0]) if (nt_b == 0).any() else 0
                    add_es = np.full((add_m,), cat_idx, dtype=np.int64)
                    add_ed = np.arange(len(nx_b), len(nx_b) + add_m, dtype=np.int64)
                    add_er = np.full((add_m,), 5, dtype=np.int64)
                    packed_att = pack_graph(
                        (
                            np.concatenate((nx_b, add_nx), axis=0),
                            np.concatenate((nt_b, add_nt), axis=0),
                            np.concatenate((es_b, add_es), axis=0),
                            np.concatenate((ed_b, add_ed), axis=0),
                            np.concatenate((er_b, add_er), axis=0),
                        )
                    )
                    graphs[int(idx_r)] = packed_att
                    if packed_att is not None:
                        ir[int(idx_r)], active[int(idx_r)] = extract_single_graph_action_ir_np(
                            *packed_att[:6], packed_att[7], packed_att[8]
                        )
            _recompute_derived(perturbed)
    if drop_prob <= 0.0:
        return perturbed, ir, active, graphs
    drops = rng.random(len(raw)) < drop_prob
    _resource_limit_features(perturbed, drops)
    if not drops.any():
        return perturbed, ir, active, graphs
    ir, active, graphs = ir.copy(), active.copy(), graphs.copy()
    ir[drops], active[drops] = EMPTY_IR, False
    for i in np.flatnonzero(drops):
        graphs[i] = None
    return perturbed, ir, active, graphs


def _ssl_pretrain(
    model: PDFTransGraphV4,
    tab: np.ndarray,
    graphs: list[PackedGraph | None],
    rows: np.ndarray,
    device: torch.device,
    rng: np.random.Generator,
    epochs: int,
    batch_size: int,
    *,
    raw_73: np.ndarray | None = None,
    transform: RobustTransform | None = None,
) -> list[float]:
    if not epochs:
        return []
    opt = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=epochs)
    row_node_counts = np.asarray([0 if g is None else len(g[0]) for g in graphs], dtype=np.int32)
    history = []
    for _ in range(epochs):
        model.train()
        total = 0.0
        for batch in _make_macro_bucketed_batches(rows, row_node_counts, batch_size, rng):
            if raw_73 is not None and transform is not None:
                pert_raw = perturb_raw_format(raw_73[batch], np.ones(len(batch), dtype=bool), rng, enable_padding=True)
                pert_tab, _, _, _ = slice_regime_inputs(*transform.transform(pert_raw), "regime_b")
                tx = _tensor(pert_tab, device)
            else:
                tx = _tensor(tab[batch], device)
            tensors = build_padded_graph_tensors([graphs[i] for i in batch], device)
            tab_mask = torch.rand_like(tx) < 0.25
            present = tensors[3]
            node_mask = (torch.rand(present.shape, device=device) < 0.20) & present
            opt.zero_grad(set_to_none=True)
            with torch.amp.autocast("cuda", dtype=torch.bfloat16, enabled=device.type == "cuda"):
                loss = model.ssl_loss(tx, tab_mask, *tensors, node_mask)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0, error_if_nonfinite=True)
            opt.step()
            total += float(loss.detach()) * len(batch)
        sched.step()
        history.append(total / len(rows))
    return history


def _weighted_bce(logits: torch.Tensor, y: torch.Tensor, weights: torch.Tensor) -> torch.Tensor:
    return (
        F.binary_cross_entropy_with_logits(logits.float(), y.float(), reduction="none") * weights.float()
    ).sum() / max(1, y.numel())


def _graft_regularization(
    model: PDFTransGraphV4,
    corpus: CSRGraphCorpus,
    graphs: list[PackedGraph | None],
    donors: np.ndarray,
    large_donors: np.ndarray,
    batch: np.ndarray,
    batch_weights: torch.Tensor,
    clean_logits: torch.Tensor,
    clean_graph_logits: torch.Tensor,
    transform: RobustTransform,
    rng: np.random.Generator,
    device: torch.device,
    monotonic: bool,
) -> torch.Tensor:
    eligible = np.asarray([graphs[i] is not None and len(graphs[i][0]) < MAX_NODES for i in batch])
    positions, raw_rows, grafts = [], [], []
    for label in (0, 1):
        candidates = np.flatnonzero(eligible & (corpus.labels[batch] == label))
        for pos in rng.permutation(candidates)[:12]:
            base = batch[pos]
            want_budget = int(rng.integers(15, 136))
            use_pool = large_donors if (want_budget >= 40 and len(large_donors) > 0) else donors
            pool = use_pool[use_pool != base]
            if not len(pool):
                pool = donors[donors != base]
            if not len(pool):
                continue
            donor = rng.choice(pool)
            base_graph, donor_graph = graphs[base], graphs[donor]
            passive_count = int(np.isin(donor_graph[1], [2, 6, 8]).sum())
            node_budget = min(want_budget, MAX_NODES - len(base_graph[0]), passive_count)
            if node_budget < 1:
                continue
            raw, graft = graft_benign_subtree_pair(
                corpus.raw_73[base],
                base_graph[:5],
                corpus.raw_73[donor],
                donor_graph[:5],
                IDX,
                donor_fraction=node_budget / passive_count,
                max_nodes=MAX_NODES,
            )
            n = len(base_graph[0]) + node_budget
            nx, nt, es, ed, er = graft
            keep_edges = (es < n) & (ed < n)
            grafts.append(pack_graph((nx[:n], nt[:n], es[keep_edges], ed[keep_edges], er[keep_edges])))
            positions.append(pos)
            raw_rows.append(raw)
    if not positions:
        return clean_logits.new_zeros(())
    gt, _, _, _ = slice_regime_inputs(*transform.transform(np.stack(raw_rows)), "regime_b")
    gi, ga = packed_action_ir(grafts)
    graft_out = model(
        _tensor(gt, device), _tensor(gi, device), _tensor(ga, device), *build_padded_graph_tensors(grafts, device)
    )
    out = graft_out["logits"]
    out_g = graft_out["graph_aux_logits"]
    pos_t = _tensor(np.asarray(positions, dtype=np.int64), device)
    labels = _tensor(corpus.labels[batch[np.asarray(positions)]], device)
    sub_w = batch_weights[pos_t]
    clean = clean_logits[pos_t]
    clean_g = clean_graph_logits[pos_t]
    loss = 0.20 * _weighted_bce(out, labels.float(), sub_w)
    if monotonic:
        for label, penalty in ((0, benign_graft_stability_loss), (1, subtree_monotonic_loss)):
            mask = labels == label
            if mask.any():
                loss = loss + 0.65 * penalty(clean[mask], out[mask], margin=0.0)
                if model.config.enable_graph:
                    loss = loss + 0.30 * penalty(clean_g[mask], out_g[mask], margin=0.0)
    return loss


def train_v4_single_seed(
    corpus: CSRGraphCorpus,
    graphs: list[PackedGraph | None],
    ir: np.ndarray,
    active: np.ndarray,
    transform: RobustTransform,
    tab: np.ndarray,
    ssl_rows: np.ndarray,
    train_rows: np.ndarray,
    select_rows: np.ndarray,
    seed: int,
    device: torch.device,
    *,
    arm: str = FULL_MODEL,
    epochs: int = 24,
    batch_size: int = 128,
    ssl_epochs: int = 6,
    ssl_batch_size: int = 256,
) -> tuple[PDFTransGraphV4, dict[str, Any]]:
    set_all_seeds(seed)
    options, monotonic = ABLATIONS[arm]
    cfg = TransGraphV4Config(tab_dim=tab.shape[1], **options)
    model = PDFTransGraphV4(cfg).to(device)
    ssl_history = _ssl_pretrain(
        model,
        tab,
        graphs,
        ssl_rows,
        device,
        np.random.default_rng(seed + 313),
        ssl_epochs,
        ssl_batch_size,
        raw_73=corpus.raw_73,
        transform=transform,
    )
    ema = deepcopy(model).eval().requires_grad_(False)
    opt = torch.optim.AdamW(model.parameters(), lr=8e-4, weight_decay=1e-4)
    sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=epochs)
    rng = np.random.default_rng(seed + 404)
    weights = compute_debiased_weights(
        corpus.labels[train_rows],
        corpus.is_bc[train_rows],
        corpus.label_sources[train_rows],
    )
    donors = np.asarray(
        [
            i
            for i in train_rows
            if corpus.labels[i] == 0
            and corpus.is_bc[i]
            and graphs[i] is not None
            and not np.isin(graphs[i][1], [3, 5, 7]).any()
            and np.isin(graphs[i][1], [2, 6, 8]).any()
        ],
        dtype=np.int64,
    )
    large_donors = np.asarray(
        [i for i in donors if int(np.isin(graphs[int(i)][1], [2, 6, 8]).sum()) >= 50],
        dtype=np.int64,
    )

    best_score, best_epoch, best_state = -np.inf, 0, None
    select_y = corpus.labels[select_rows]
    select_bc = corpus.is_bc[select_rows]
    select_supp_neg = np.asarray(
        [(corpus.labels[r] == 0) and str(corpus.label_sources[r]).startswith(SUPPLEMENT_PREFIX) for r in select_rows],
        dtype=bool,
    )
    val_graft_raw, val_graft_graphs, val_graft_pos = None, None, np.empty(0, dtype=np.int64)
    if len(large_donors) > 0:
        val_mal_cand = np.flatnonzero((select_y == 1) & select_bc)
        vg_rng = np.random.default_rng(1042)
        vg_r, vg_g, vg_p = [], [], []
        for pos_s in val_mal_cand:
            r_idx = int(select_rows[pos_s])
            bg = graphs[r_idx]
            if bg is None or len(bg[0]) >= MAX_NODES:
                continue
            d_idx = int(vg_rng.choice(large_donors))
            dg = graphs[d_idx]
            pc = int(np.isin(dg[1], [2, 6, 8]).sum())
            bud = min(100, MAX_NODES - len(bg[0]), pc)
            if bud < 1:
                continue
            gr, gg = graft_benign_subtree_pair(
                corpus.raw_73[r_idx],
                bg[:5],
                corpus.raw_73[d_idx],
                dg[:5],
                IDX,
                donor_fraction=bud / pc,
                max_nodes=MAX_NODES,
            )
            n_tot = len(bg[0]) + bud
            ke = (gg[2] < n_tot) & (gg[3] < n_tot)
            vg_r.append(gr)
            vg_g.append((gg[0][:n_tot], gg[1][:n_tot], gg[2][ke], gg[3][ke], gg[4][ke]))
            vg_p.append(pos_s)
        if vg_r:
            val_graft_raw = np.stack(vg_r)
            val_graft_graphs = vg_g
            val_graft_pos = np.asarray(vg_p, dtype=np.int64)

    train_node_counts = np.asarray(
        [0 if graphs[int(i)] is None else len(graphs[int(i)][0]) for i in train_rows], dtype=np.int32
    )
    global_step = 0
    logical_bsz = max(batch_size, 256)
    for epoch in range(epochs):
        model.train()
        perm = rng.permutation(len(train_rows))
        for start in range(0, len(perm), logical_bsz):
            logical_pos = perm[start : start + logical_bsz]
            total_m = float(len(logical_pos))
            opt.zero_grad(set_to_none=True)
            logical_teacher_parts: list[tuple[np.ndarray, torch.Tensor, torch.Tensor]] = []
            for positions in _split_logical_batch_into_microbatches(logical_pos, train_node_counts):
                scale = float(len(positions)) / total_m
                batch = train_rows[positions]
                y = _tensor(corpus.labels[batch].astype(np.float32), device)
                w = _tensor(weights[positions], device)
                g = [graphs[i] for i in batch]
                ir_c, active_c = ir[batch], active[batch]
                g_c = build_padded_graph_tensors(g, device)
                clean = (_tensor(tab[batch], device), _tensor(ir_c, device), _tensor(active_c, device), *g_c)
                with torch.no_grad(), torch.amp.autocast("cuda", dtype=torch.bfloat16, enabled=device.type == "cuda"):
                    t_out = ema(*clean)
                    teacher_logits = t_out["logits"].float()
                    teacher_g_logits = t_out["graph_aux_logits"].float()
                    teacher = teacher_logits.sigmoid()
                logical_teacher_parts.append((positions, teacher_logits, teacher_g_logits))
                with torch.amp.autocast("cuda", dtype=torch.bfloat16, enabled=device.type == "cuda"):
                    perturbed, ir_p, active_p, graphs_p = format_view(
                        corpus.raw_73[batch],
                        np.ones(len(batch), dtype=bool),
                        ir_c,
                        active_c,
                        g,
                        rng,
                        drop_prob=0.0,
                        attach_aug_prob=0.12,
                    )
                    tab_p, _, _, _ = slice_regime_inputs(*transform.transform(perturbed), "regime_b")
                    g_p = g_c if graphs_p is g else build_padded_graph_tensors(graphs_p, device)
                    out = model(_tensor(tab_p, device), _tensor(ir_p, device), _tensor(active_p, device), *g_p)
                    loss = _weighted_bce(out["logits"], y, w)
                    aux_loss = 0.35 * _weighted_bce(out["tab_aux_logits"], y, w)
                    if cfg.enable_graph:
                        present = g_p[3].any(dim=1)
                        if present.any():
                            aux_loss = aux_loss + 0.35 * _weighted_bce(
                                out["graph_aux_logits"][present], y[present], w[present]
                            )
                    if cfg.enable_action_ir:
                        present = _tensor(active_p, device)
                        if present.any():
                            aux_loss = aux_loss + 0.35 * _weighted_bce(
                                out["ir_aux_logits"][present], y[present], w[present]
                            )
                    loss = loss + aux_loss + 0.50 * F.mse_loss(out["logits"].float().sigmoid(), teacher)
                (loss * scale).backward()
            if len(donors):
                cat_pos = np.concatenate([p for p, _, _ in logical_teacher_parts])
                cat_t_logits = torch.cat([tl for _, tl, _ in logical_teacher_parts], dim=0)
                cat_tg_logits = torch.cat([tgl for _, _, tgl in logical_teacher_parts], dim=0)
                with torch.amp.autocast("cuda", dtype=torch.bfloat16, enabled=device.type == "cuda"):
                    g_loss = _graft_regularization(
                        model,
                        corpus,
                        graphs,
                        donors,
                        large_donors,
                        train_rows[cat_pos],
                        _tensor(weights[cat_pos], device),
                        cat_t_logits,
                        cat_tg_logits,
                        transform,
                        rng,
                        device,
                        monotonic,
                    )
                g_loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0, error_if_nonfinite=True)
            opt.step()
            _update_ema(ema, model, global_step, 0.99)
            global_step += 1
        sched.step()
        logits, _ = predict_v4_logits(ema, graphs, ir, active, tab, select_rows, device)
        val_probs = apply_temperature(logits, 1.0)
        all_ap = float(average_precision_score(select_y, val_probs))
        bc_ap = float(average_precision_score(select_y[select_bc], val_probs[select_bc]))
        supp_fp_pen = float((val_probs[select_supp_neg] >= 0.50).mean()) if select_supp_neg.any() else 0.0
        graft_drop_pen = 0.0
        if monotonic and val_graft_raw is not None and val_graft_graphs is not None and len(val_graft_pos) > 0:
            vg_probs = apply_temperature(
                predict_v4_custom(ema, transform, val_graft_raw, val_graft_graphs, device)[0], 1.0
            )
            graft_drop_pen = float(np.maximum(0.0, val_probs[val_graft_pos] - vg_probs).mean())
        score = 0.60 * bc_ap + 0.40 * all_ap - 0.01 * supp_fp_pen - 0.015 * graft_drop_pen
        if score > best_score:
            best_score, best_epoch = score, epoch + 1
            best_state = {k: v.detach().cpu().clone() for k, v in ema.state_dict().items()}
    ema.load_state_dict(best_state)
    if device.type == "cuda":
        torch.cuda.empty_cache()
    return ema, {
        "seed": seed,
        "best_epoch": best_epoch,
        "val_select_composite_ap": best_score,
        "ssl_history": ssl_history,
        "enable_graft_aug": True,
        "enable_monotonic_penalty": monotonic,
    }


def benign_fpr(labels: np.ndarray, probabilities: np.ndarray, threshold: float) -> float:
    return float((np.asarray(probabilities, dtype=np.float64)[labels == 0] >= threshold).mean())


def threshold_at_fpr(labels: np.ndarray, probabilities: np.ndarray, target_fpr: float) -> float:
    neg = np.sort(np.asarray(probabilities[labels == 0], dtype=np.float64))[::-1]
    allowed = int(np.floor(target_fpr * len(neg)))
    return float(np.nextafter(neg[allowed], np.inf))


def calibrate_thresholds(labels: np.ndarray, probs: np.ndarray) -> tuple[dict[str, float], dict[str, float]]:
    primary = midpoint_macro_f1(labels, probs, max_threshold=0.50, f1_tolerance=0.001)["threshold"]
    thresholds = {
        "thr_val_calib": primary,
        "thr_f1_macro": primary,
        "thr_fpr_05pct": threshold_at_fpr(labels, probs, 0.005),
        "thr_fpr1": threshold_at_fpr(labels, probs, 0.01),
    }
    return thresholds, {key: benign_fpr(labels, probs, thr) for key, thr in thresholds.items()}


def load_stress() -> tuple[list[dict], np.ndarray, list]:
    doc = read_json(DEFAULT_STRESS, STRESS_SHA256)
    rows = doc["variants"]
    if doc["features"] != list(FEATURES) or len(rows) != 20:
        raise ValueError("invalid_phase_2_stress_contract")
    return rows, np.asarray([row["vector_v3"] for row in rows], dtype=np.float32), [row["graph"] for row in rows]


def stress_report(rows: list[dict], probs: np.ndarray, threshold: float) -> dict:
    items = [
        {
            "id": row["id"],
            "sha256": row["sha256"],
            "group": row["group"],
            "probability": float(p),
            "predicted_malicious": bool(p >= threshold),
        }
        for row, p in zip(rows, probs, strict=True)
    ]
    by_id = {row["id"]: row["probability"] for row in items}
    return {
        "count": len(items),
        "threat_tp_of_8": sum(r["predicted_malicious"] for r in items if r["group"] == "threat"),
        "non_js_benign_fp_of_11": sum(
            r["predicted_malicious"] for r in items if r["group"] == "benign" and r["id"] != "benign_safe_js_alert"
        ),
        "threat_objstm_packed_p": by_id["threat_objstm_packed"],
        "threat_padded_50_pages_p": by_id["threat_padded_50_pages"],
        "rows": items,
    }


def core_metrics(row: dict) -> dict:
    out = {}
    for name in ("test_all", "test_bc"):
        result = row[name]
        out.update({f"{name}_{key}": result[key] for key in ("pr_auc", "roc_auc", "ece")})
        out[f"{name}_f1_macro"] = result["thr_f1_macro"]["f1_macro"]
    out["test_bc_recall_at_1pct_fpr"] = row["test_bc"]["recall_at_1pct_fpr"]
    return out


def compare_locked_v3(reports: list[dict]) -> dict | None:
    path = LOCKED_V3 / "metrics.json"
    if not path.is_file():
        return None
    v3 = read_json(path)["regime_b_multiseed_stability"]
    old = {row["seed"]: row for row in v3["per_seed"]}
    new = {row["seed"]: core_metrics(row) for row in reports}
    common = sorted(old.keys() & new.keys())
    keys = tuple(next(iter(new.values())))

    def deltas(a, b):
        return {key: {"v4": a[key], "v3_2b": b[key], "delta": a[key] - b[key]} for key in keys}

    means = None
    if common:
        means = deltas(
            {k: float(np.mean([new[s][k] for s in common])) for k in keys},
            {k: float(np.mean([old[s][k] for s in common])) for k in keys},
        )
    return {
        "run": LOCKED_V3.name,
        "metrics_sha256": digest(path),
        "matched_seeds": common,
        "matched_seed_count": len(common),
        "matched_seed_means": means,
        "seed_42": deltas(new[42], old[42]) if 42 in common else None,
        "threshold_comparison": "F1 uses each run's recorded Val_Calib operating point.",
    }


def load_checkpoint(art_dir: Path, record: dict, device: torch.device) -> tuple[PDFTransGraphV4, RobustTransform]:
    files = [record[k] for k in ("config_file", "weights_file", "scaler_file")]
    if any(Path(name).name != name for name in files):
        raise ValueError("invalid_checkpoint_artifact_name")
    cfg, weights, scaler = (art_dir / name for name in files)
    for path in (cfg, weights, scaler):
        if digest(path) != record["artifacts"][path.name]:
            raise ValueError(f"locked_checkpoint_artifact_changed:{path.name}")
    model = PDFTransGraphV4(TransGraphV4Config(**read_json(cfg))).to(device).eval()
    load_v4_weights_npz(model, weights, map_location=device)
    with np.load(scaler, allow_pickle=False) as data:
        transform = RobustTransform(data["center"], data["scale"], data["available"])
    return model, transform


def load_run_seed42(
    run: Path | None,
    device: torch.device,
    artifact_dir: Path | None = None,
) -> tuple[Path, dict, PDFTransGraphV4, RobustTransform, dict]:
    if run is None:
        run = REPO / (OFFLINE / "current_transgraph_v4_run.txt").read_text(encoding="utf-8").strip()
    metrics = read_json(run / "metrics.json")
    methodology = read_json(run / "locked_methodology.json", metrics["locked_methodology_sha256"])
    checkpoint = read_json(run / "checkpoint_lock.json", metrics["checkpoint_lock_sha256"])
    if checkpoint["locked_methodology_sha256"] != metrics["locked_methodology_sha256"]:
        raise ValueError("checkpoint_methodology_mismatch")
    seed = next((r for r in checkpoint["arms"][FULL_MODEL] if r["seed"] == 42), None)
    if seed is None:
        raise ValueError("locked_seed_42_missing")
    if seed["weights_file"] != "v4_seed42.npz" or seed["scaler_file"] != "robust_transform_seed42.npz":
        raise ValueError("unexpected_seed_42_artifact_names")
    model, transform = load_checkpoint(artifact_dir or REPO / metrics["artifact_directory"], seed, device)
    return run, seed, model, transform, methodology


def main() -> None:
    from scripts.lab.score_v4_subset_b import DEFAULT_EXPORT, DEFAULT_REFERENCE, load_subset, score_tracks

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seeds", type=int, nargs="+", default=[42, 43, 44, 45, 46])
    parser.add_argument("--epochs", type=int, default=24)
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--ssl-epochs", type=int, default=6)
    parser.add_argument("--ssl-batch-size", type=int, default=256)
    parser.add_argument("--run-ablations", action="store_true")
    parser.add_argument("--ablation-seeds", type=int, nargs="+", default=[42])
    parser.add_argument("--resume-run-id", type=str, default=None)
    args = parser.parse_args()
    if min(args.epochs, args.batch_size, args.ssl_batch_size) < 1 or args.ssl_epochs < 0:
        parser.error("epochs and batch sizes must be positive, or use --ssl-epochs 0 to disable SSL")
    if len(set(args.seeds)) != len(args.seeds) or len(set(args.ablation_seeds)) != len(args.ablation_seeds):
        parser.error("seed lists must contain unique seeds")

    git_rev = subprocess.check_output(["git", "rev-parse", "--short=12", "HEAD"], cwd=REPO, text=True).strip()
    now = datetime.now(timezone.utc)
    run_id = args.resume_run_id or f"run_{now:%Y%m%dT%H%M%S%fZ}_{git_rev}"
    exp_dir = REPO / "reports/experiments/transgraph_v4" / run_id
    art_dir = POOL_ROOT / "transgraph_v4" / run_id
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    torch.set_num_threads(min(torch.get_num_threads(), 4))
    pool = DEFAULT_POOL if DEFAULT_POOL.is_file() else POOL_ROOT / "pooled.jsonl.gz"
    paths = {
        "pool": pool,
        "tabular": DEFAULT_TABULAR,
        "label_view": DEFAULT_LABEL_VIEW,
        "split_view": DEFAULT_SPLIT_VIEW,
        "controls": DEFAULT_CONTROLS,
        "benign_supplement": DEFAULT_SUPP,
        "byte_stress": DEFAULT_STRESS,
    }
    hashes = {name: digest(path) for name, path in paths.items()}
    prior_lock = LOCKED_V3 / "locked_methodology.json"
    if prior_lock.is_file():
        for name, expected in read_json(prior_lock)["inputs_sha256"].items():
            if hashes[name] != expected:
                raise ValueError(f"locked_training_input_changed:{name}")
    ood_inputs, ood_hashes = load_subset(DEFAULT_EXPORT, DEFAULT_REFERENCE, hashes)
    hashes.update(ood_hashes)
    stress_rows, stress_raw, stress_graphs = load_stress()
    corpus = load_pooled_corpus(
        pool_path=pool,
        tabular_path=DEFAULT_TABULAR,
        label_view_path=DEFAULT_LABEL_VIEW,
        split_view_path=DEFAULT_SPLIT_VIEW,
        benign_supplement_path=DEFAULT_SUPP,
    )
    scoreable = np.isfinite(corpus.raw_73[:, REGIME_B_INDICES]).all(axis=1)
    train = (corpus.roles == "train") & scoreable
    ssl_rows = np.flatnonzero(train)
    train_rows = np.flatnonzero(train & (corpus.labels >= 0))
    select_rows, calib_rows, test_rows = [
        np.flatnonzero(corpus.roles == role) for role in ("val_select", "val_calib", "test_internal")
    ]
    for cohort in (
        select_rows,
        calib_rows,
        test_rows,
        select_rows[corpus.is_bc[select_rows]],
        test_rows[corpus.is_bc[test_rows]],
    ):
        if not scoreable[cohort].all() or set(corpus.labels[cohort]) != {0, 1}:
            raise ValueError("incomplete_or_unscoreable_evaluation_cohort")
    if not len(ssl_rows) or set(corpus.labels[train_rows]) != {0, 1}:
        raise ValueError("incomplete_training_cohort")
    graphs, ir, active = precompute_corpus(corpus)
    transform = RobustTransform.fit(corpus.raw_73[train], roles=["train"] * int(train.sum()))
    tab, _, _, _ = slice_regime_inputs(*transform.transform(corpus.raw_73), "regime_b")
    exp_dir.mkdir(parents=True, exist_ok=bool(args.resume_run_id))
    art_dir.mkdir(parents=True, exist_ok=bool(args.resume_run_id))
    methodology = exp_dir / "locked_methodology.json"
    if not methodology.exists():
        write_json(
            methodology,
            {
                "generated_utc": now.isoformat(),
                "revision": git_rev,
                "device": str(device),
                "program_sha256": digest(Path(__file__)),
                "inputs_sha256": hashes,
                **{k: v for k, v in vars(args).items() if k != "resume_run_id"},
                "regression_provenance": REGRESSION_DISCLOSURE,
                "scaler_partition": "scoreable train including benign supplement",
                "ssl_partition": "scoreable train including unlabeled and benign supplement rows",
                "ssl_rows": len(ssl_rows),
                "ssl_unlabeled": int((corpus.labels[ssl_rows] < 0).sum()),
                "supervised_rows": len(train_rows),
                "val_select_rows": len(select_rows),
                "val_calib_rows": len(calib_rows),
                "selection": "EMA: 0.60 * AP(bounded_complete) + 0.40 * AP(all) - 0.01 * supplement_fpr on Val_Select",
                "calibration": "Val_Calib only, temperature and widest macro-F1 plateau (tol=0.001) within (0, 0.50]",
            },
        )

    schedule = {FULL_MODEL: list(dict.fromkeys(args.seeds + (args.ablation_seeds if args.run_ablations else [])))}
    if args.run_ablations:
        schedule.update({arm: args.ablation_seeds for arm in ABLATIONS if arm != FULL_MODEL})
    partial_path = exp_dir / "partial_seed_records.json"
    cached_partial: dict[str, dict[str, dict]] = read_json(partial_path) if partial_path.is_file() else {}
    records: dict[str, dict[int, dict]] = {}
    cal_y = corpus.labels[calib_rows]
    for arm, seeds in schedule.items():
        records[arm] = {}
        for seed in seeds:
            existing = cached_partial.get(arm, {}).get(str(seed))
            if existing is not None and all(
                (art_dir / fn).is_file() and digest(art_dir / fn) == sha
                for fn, sha in existing.get("artifacts", {}).items()
            ):
                records[arm][seed] = existing
                print(f"Resumed verified {arm} seed {seed} from checkpoint", flush=True)
                continue
            model, meta = train_v4_single_seed(
                corpus,
                graphs,
                ir,
                active,
                transform,
                tab,
                ssl_rows,
                train_rows,
                select_rows,
                seed,
                device,
                arm=arm,
                epochs=args.epochs,
                batch_size=args.batch_size,
                ssl_epochs=args.ssl_epochs,
                ssl_batch_size=args.ssl_batch_size,
            )
            prefix = "v4" if arm == FULL_MODEL else arm
            weights = art_dir / f"{prefix}_seed{seed}.npz"
            config = art_dir / (
                f"{prefix}_config.json"
                if arm == "gin_tab_baseline" and seed == 42
                else f"{prefix}_config_seed{seed}.json"
            )
            scaler = art_dir / f"robust_transform_seed{seed}.npz"
            if not scaler.exists():
                np.savez_compressed(
                    scaler, center=transform.center, scale=transform.scale, available=transform.available
                )
            save_v4_weights_npz(model, weights)
            if config.exists():
                config.unlink()
            write_json(config, model.config.to_dict())
            load_v4_weights_npz(model, weights, map_location=device)
            cal_logits, _ = predict_v4_logits(model, graphs, ir, active, tab, calib_rows, device)
            temp = fit_temperature(cal_logits, cal_y)
            thresholds, fprs = calibrate_thresholds(cal_y, apply_temperature(cal_logits, temp))
            records[arm][seed] = {
                **meta,
                "temperature": temp,
                "thresholds": thresholds,
                "achieved_val_calib_fpr": fprs,
                "artifacts": {p.name: digest(p) for p in (weights, config, scaler)},
                "weights_file": weights.name,
                "config_file": config.name,
                "scaler_file": scaler.name,
            }
            cached_partial.setdefault(arm, {})[str(seed)] = records[arm][seed]
            partial_path.write_text(json.dumps(cached_partial, indent=2) + "\n", encoding="utf-8")
            print(
                f"Locked {arm} seed {seed} from Val_Select and Val_Calib (thr={thresholds['thr_val_calib']:.6f})",
                flush=True,
            )
    if partial_path.is_file():
        partial_path.unlink()
    checkpoint = exp_dir / "checkpoint_lock.json"
    write_json(
        checkpoint,
        {
            "locked_methodology_sha256": digest(methodology),
            "arms": {name: list(rows.values()) for name, rows in records.items()},
        },
    )

    control_names, control_raw, control_graphs, _ = _load_controls(DEFAULT_CONTROLS)
    test_y, test_bc = corpus.labels[test_rows], corpus.is_bc[test_rows]
    pad_rows = test_rows[test_bc & (test_y == 1)]
    pad_raw = corpus.raw_73[pad_rows].copy()
    _resource_limit_features(pad_raw, np.ones(len(pad_rows), dtype=bool))
    for rows in records.values():
        for record in rows.values():
            model, saved_transform = load_checkpoint(art_dir, record, device)
            thrs, temp = record["thresholds"], record["temperature"]
            threshold = thrs["thr_val_calib"]
            test_logits, weights = predict_v4_logits(model, graphs, ir, active, tab, test_rows, device)
            test_probs = apply_temperature(test_logits, temp)
            control_probs = apply_temperature(
                predict_v4_custom(model, saved_transform, control_raw, control_graphs, device)[0], temp
            )
            stress_probs = apply_temperature(
                predict_v4_custom(model, saved_transform, stress_raw, stress_graphs, device)[0], temp
            )
            pad_probs = apply_temperature(
                predict_v4_custom(model, saved_transform, pad_raw, [None] * len(pad_rows), device)[0], temp
            )
            record.update(
                {
                    "test_all": compute_slice_metrics(test_y, test_probs, threshold, thrs["thr_fpr1"]),
                    "test_bc": compute_slice_metrics(test_y[test_bc], test_probs[test_bc], threshold, thrs["thr_fpr1"]),
                    "mean_modality_weights_test": weights.mean(axis=0).tolist(),
                    "reviewed_controls_alerts_thr_f1": int((control_probs >= threshold).sum()),
                    "reviewed_controls": dict(zip(control_names, control_probs.tolist(), strict=True)),
                    "byte_stress": stress_report(stress_rows, stress_probs, threshold),
                    "pad_dilute_count": len(pad_rows),
                    "pad_dilute_recall": float((pad_probs >= threshold).mean()),
                }
            )
    per_seed_results = [records[FULL_MODEL][seed] for seed in args.seeds]
    canonical = next((r for r in per_seed_results if r["seed"] == 42), per_seed_results[0])
    ood_model, ood_transform = load_checkpoint(art_dir, canonical, device)
    ood_tracks = score_tracks(ood_model, ood_transform, canonical, ood_inputs, device)
    summaries = [core_metrics(row) for row in per_seed_results]
    summary = {
        key: {
            "mean": float(np.mean([row[key] for row in summaries])),
            "std": float(np.std([row[key] for row in summaries])),
        }
        for key in summaries[0]
    }
    write_json(
        exp_dir / "metrics.json",
        {
            "run_directory": exp_dir.relative_to(REPO).as_posix(),
            "artifact_directory": art_dir.relative_to(REPO).as_posix(),
            "locked_methodology_sha256": digest(methodology),
            "checkpoint_lock_sha256": digest(checkpoint),
            "canonical_seed": canonical["seed"],
            "seeds": per_seed_results,
            "summary": summary,
            "comparison_vs_locked_v3_2b": compare_locked_v3(per_seed_results),
            "prospective_subset_b": {"seed": canonical["seed"], "tracks": ood_tracks},
            "ablations": {arm: [records[arm][seed] for seed in args.ablation_seeds] for arm in ABLATIONS}
            if args.run_ablations
            else {},
        },
    )
    (OFFLINE / "current_transgraph_v4_run.txt").write_text(exp_dir.relative_to(REPO).as_posix(), encoding="utf-8")
    print("Saved TransGraph v4 metrics:", exp_dir / "metrics.json")


if __name__ == "__main__":
    main()

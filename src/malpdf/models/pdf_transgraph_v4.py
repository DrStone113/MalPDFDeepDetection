"""PDF-TransGraph v4: DAG Shortest-Path Graphormer + Observable Action-IR + Subtree Monotonicity."""

from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass
from typing import Any

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

from malpdf.models.pdf_transgraph_v3 import (
    GRAPH_SUMMARY_DIM,
    NUM_BASE_RELATIONS,
    NUM_NODE_TYPES,
    MaskedGatedCrossModalFusionV3,
    TabularEncoderV3,
    extract_graph_summary_features,
)

MAX_SPD_HOPS = 8
SPD_UNREACHABLE = MAX_SPD_HOPS + 1
ACTION_IR_DIM = 24


@dataclass(frozen=True)
class TransGraphV4Config:
    """Architecture hyperparameters persisted alongside compressed NumPy weights."""

    tab_dim: int
    action_ir_dim: int = ACTION_IR_DIM
    node_dim: int = 23
    hidden_dim: int = 128
    num_graph_layers: int = 3
    num_heads: int = 4
    num_node_types: int = NUM_NODE_TYPES
    num_base_relations: int = NUM_BASE_RELATIONS
    num_freq_bins: int = 4
    dropout: float = 0.15
    modality_drop_prob: float = 0.10
    use_missing_mask: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def compute_dag_structural_encodings(
    num_nodes: int,
    node_types: np.ndarray,
    edge_src: np.ndarray,
    edge_dst: np.ndarray,
    edge_rel: np.ndarray,
    *,
    max_hops: int = MAX_SPD_HOPS,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Compute bounded all-pairs shortest path, direct edge relation, root depth, and trigger sink distance."""
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

    fwd_adj: list[list[int]] = [[] for _ in range(num_nodes)]
    rev_adj: list[list[int]] = [[] for _ in range(num_nodes)]
    for s, d, r in zip(edge_src.tolist(), edge_dst.tolist(), edge_rel.tolist(), strict=True):
        if 0 <= s < num_nodes and 0 <= d < num_nodes:
            fwd_adj[s].append(d)
            rev_adj[d].append(s)
            if s != d and direct_rel[s, d] == 0:
                direct_rel[s, d] = int(r % NUM_BASE_RELATIONS) + 1

    for src in range(num_nodes):
        if not fwd_adj[src]:
            continue
        q = deque([(src, 0)])
        seen = {src}
        while q:
            u, dist = q.popleft()
            if dist >= max_hops:
                continue
            nd = dist + 1
            for v in fwd_adj[u]:
                if v not in seen:
                    seen.add(v)
                    spd[src, v] = nd
                    q.append((v, nd))

    root_depth = np.full((num_nodes,), unreachable, dtype=np.int64)
    catalog_nodes = np.flatnonzero(node_types == 0)
    roots = catalog_nodes.tolist() if len(catalog_nodes) > 0 else [0]
    rq = deque()
    for r_idx in roots:
        if 0 <= r_idx < num_nodes:
            root_depth[r_idx] = 0
            rq.append(r_idx)
    while rq:
        u = rq.popleft()
        if root_depth[u] >= max_hops:
            continue
        nd = root_depth[u] + 1
        for v in fwd_adj[u]:
            if root_depth[v] > nd:
                root_depth[v] = nd
                rq.append(v)

    # Trigger sink nodes: action (3), script (4), filespec (6)
    sink_dist = np.full((num_nodes,), unreachable, dtype=np.int64)
    sink_nodes = np.flatnonzero((node_types == 3) | (node_types == 4) | (node_types == 6))
    sq = deque()
    for s_idx in sink_nodes.tolist():
        sink_dist[s_idx] = 0
        sq.append(s_idx)
    while sq:
        u = sq.popleft()
        if sink_dist[u] >= max_hops:
            continue
        nd = sink_dist[u] + 1
        for prev_u in rev_adj[u]:
            if sink_dist[prev_u] > nd:
                sink_dist[prev_u] = nd
                sq.append(prev_u)

    return spd, direct_rel, root_depth, sink_dist


def extract_observable_action_ir_np(
    raw_73: np.ndarray,
    regime_b_indices: np.ndarray,
    idx_map: dict[str, int],
    *,
    node_x: np.ndarray | None,
    node_type: np.ndarray | None,
    node_ptr: np.ndarray,
    row_indices: np.ndarray,
    graph_spd_depths: list[tuple[np.ndarray, np.ndarray]] | None = None,
) -> tuple[np.ndarray, np.ndarray]:
    """Build shortcut-free 24D Object/Action-IR features and active-interaction mask."""
    b = len(row_indices)
    ir = np.zeros((b, ACTION_IR_DIM), dtype=np.float32)
    active = np.zeros((b,), dtype=bool)
    col_names = (
        "lexical_JS",
        "lexical_JavaScript",
        "lexical_OpenAction",
        "lexical_AA",
        "lexical_Launch",
        "lexical_URI",
        "lexical_EmbeddedFile",
        "lexical_XFA",
        "lexical_RichMedia",
        "lexical_JBIG2Decode",
        "lexical_ObjStm",
        "lexical_Encrypt",
        "lexical_page_command",
        "lexical_obj",
        "js_per_obj",
        "stream_per_obj",
    )
    for out_i, cname in enumerate(col_names):
        vals = raw_73[row_indices, idx_map[cname]]
        ir[:, out_i] = np.log1p(np.maximum(vals, 0.0)) if out_i < 14 else np.clip(vals, -10.0, 10.0)

    for b_i, r_idx in enumerate(row_indices.tolist()):
        n0, n1 = int(node_ptr[r_idx]), int(node_ptr[r_idx + 1])
        has_lex_trigger = (
            float(
                raw_73[r_idx, idx_map["lexical_JS"]]
                + raw_73[r_idx, idx_map["lexical_JavaScript"]]
                + raw_73[r_idx, idx_map["lexical_OpenAction"]]
                + raw_73[r_idx, idx_map["lexical_AA"]]
                + raw_73[r_idx, idx_map["lexical_Launch"]]
                + raw_73[r_idx, idx_map["lexical_URI"]]
                + raw_73[r_idx, idx_map["lexical_EmbeddedFile"]]
                + raw_73[r_idx, idx_map["lexical_XFA"]]
                + raw_73[r_idx, idx_map["lexical_RichMedia"]]
                + raw_73[r_idx, idx_map["lexical_JBIG2Decode"]]
            )
            > 0.0
        )
        if node_x is not None and node_type is not None and n1 > n0:
            nt_i = node_type[n0:n1]
            nx_i = node_x[n0:n1]
            tot = max(1.0, float(n1 - n0))
            n_action = float((nt_i == 3).sum())
            n_script = float((nt_i == 4).sum())
            n_annot = float((nt_i == 5).sum())
            n_filespec = float((nt_i == 6).sum())
            n_stream = float((nt_i == 7).sum())
            trig_mask = (nt_i == 3) | (nt_i == 4) | (nt_i == 6)
            max_trig_span = float(nx_i[trig_mask, 0].max()) if trig_mask.any() else 0.0
            max_trig_ent = float(nx_i[trig_mask, 4].max()) if trig_mask.any() and nx_i.shape[1] > 4 else 0.0
            min_root_to_trig = float(SPD_UNREACHABLE)
            if graph_spd_depths is not None and trig_mask.any():
                r_depths, _ = graph_spd_depths[r_idx]
                if len(r_depths) == len(nt_i):
                    min_root_to_trig = float(r_depths[trig_mask].min())

            ir[b_i, 16] = np.log1p(n_action)
            ir[b_i, 17] = np.log1p(n_script)
            ir[b_i, 18] = np.log1p(n_annot + n_filespec)
            ir[b_i, 19] = (n_action + n_script + n_filespec) / tot
            ir[b_i, 20] = max_trig_span
            ir[b_i, 21] = max_trig_ent
            ir[b_i, 22] = min_root_to_trig / float(SPD_UNREACHABLE)
            ir[b_i, 23] = np.log1p(n_stream * float(raw_73[r_idx, idx_map["lexical_ObjStm"]] > 0.0))
            active[b_i] = has_lex_trigger or trig_mask.any() or n_annot > 0
        else:
            ir[b_i, 22] = 1.0
            active[b_i] = has_lex_trigger
    return ir, active


class GraphormerDAGLayerV4(nn.Module):
    """Pre-LN multi-head self-attention with directed/reverse shortest-path and relation biases."""

    def __init__(self, hidden_dim: int, num_heads: int, dropout: float) -> None:
        super().__init__()
        self.hidden_dim = hidden_dim
        self.num_heads = num_heads
        self.head_dim = hidden_dim // num_heads
        if hidden_dim % num_heads != 0:
            raise ValueError("hidden_dim_must_be_divisible_by_num_heads")

        self.norm1 = nn.LayerNorm(hidden_dim)
        self.qkv = nn.Linear(hidden_dim, hidden_dim * 3)
        self.out_proj = nn.Linear(hidden_dim, hidden_dim)
        self.spd_fwd_bias = nn.Embedding(SPD_UNREACHABLE + 1, num_heads)
        self.spd_rev_bias = nn.Embedding(SPD_UNREACHABLE + 1, num_heads)
        self.rel_bias = nn.Embedding(NUM_BASE_RELATIONS + 1, num_heads)
        self.drop = nn.Dropout(dropout)
        self.norm2 = nn.LayerNorm(hidden_dim)
        self.ffn = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim * 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.Dropout(dropout),
        )

    def forward(
        self,
        h: torch.Tensor,
        node_pad_mask: torch.Tensor,
        spd: torch.Tensor,
        direct_rel: torch.Tensor,
    ) -> torch.Tensor:
        bsz, n_max, hdim = h.shape
        if n_max == 0:
            return h
        x = self.norm1(h)
        qkv = self.qkv(x).view(bsz, n_max, 3, self.num_heads, self.head_dim)
        q, k, v = qkv[:, :, 0], qkv[:, :, 1], qkv[:, :, 2]
        q = q.transpose(1, 2)
        k = k.transpose(1, 2)
        v = v.transpose(1, 2)

        scores = torch.matmul(q, k.transpose(-2, -1)) / (self.head_dim**0.5)
        bias = (
            self.spd_fwd_bias(spd).permute(0, 3, 1, 2)
            + self.spd_rev_bias(spd.transpose(1, 2)).permute(0, 3, 1, 2)
            + self.rel_bias(direct_rel).permute(0, 3, 1, 2)
        )
        scores = scores + bias

        key_mask = node_pad_mask.unsqueeze(1).unsqueeze(2)
        scores = scores.masked_fill(~key_mask, -1e9)
        attn = self.drop(F.softmax(scores, dim=-1))
        attn = attn * node_pad_mask.unsqueeze(1).unsqueeze(-1).to(attn.dtype)
        out = torch.matmul(attn, v).transpose(1, 2).contiguous().view(bsz, n_max, hdim)
        h = h + self.drop(self.out_proj(out))
        return h + self.ffn(self.norm2(h))


class ShortestPathGraphEncoderV4(nn.Module):
    """Global Graphormer-style DAG encoder preserving trigger-sink activations under subtree padding."""

    def __init__(
        self,
        node_dim: int = 23,
        hidden_dim: int = 128,
        num_layers: int = 3,
        num_heads: int = 4,
        num_node_types: int = NUM_NODE_TYPES,
        dropout: float = 0.15,
    ) -> None:
        super().__init__()
        self.node_dim = node_dim
        self.hidden_dim = hidden_dim
        self.num_node_types = num_node_types

        self.input_proj = nn.Linear(node_dim + 2, hidden_dim)
        self.type_emb = nn.Embedding(num_node_types, hidden_dim)
        self.root_depth_emb = nn.Embedding(SPD_UNREACHABLE + 1, hidden_dim)
        self.sink_dist_emb = nn.Embedding(SPD_UNREACHABLE + 1, hidden_dim)
        self.input_norm = nn.LayerNorm(hidden_dim)
        self.drop = nn.Dropout(dropout)

        self.layers = nn.ModuleList([GraphormerDAGLayerV4(hidden_dim, num_heads, dropout) for _ in range(num_layers)])
        self.final_norm = nn.LayerNorm(hidden_dim)
        self.attn_gate = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.Tanh(),
            nn.Linear(hidden_dim // 2, 1),
        )
        self.pool_proj = nn.Sequential(
            nn.Linear(hidden_dim * 2 + GRAPH_SUMMARY_DIM, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
        )

    def forward(
        self,
        node_x_pad: torch.Tensor,
        node_type_pad: torch.Tensor,
        deg_pad: torch.Tensor,
        node_pad_mask: torch.Tensor,
        spd_pad: torch.Tensor,
        rel_pad: torch.Tensor,
        root_depth_pad: torch.Tensor,
        sink_dist_pad: torch.Tensor,
        summary_12: torch.Tensor,
    ) -> tuple[torch.Tensor, torch.Tensor]:
        bsz, n_max, _ = node_x_pad.shape
        device = node_x_pad.device
        if n_max == 0:
            return (
                torch.zeros((bsz, self.hidden_dim), device=device, dtype=torch.float32),
                torch.zeros((bsz,), device=device, dtype=torch.bool),
            )

        present = node_pad_mask.any(dim=1)
        safe_types = node_type_pad.clamp(0, self.num_node_types - 1)
        safe_rd = root_depth_pad.clamp(0, SPD_UNREACHABLE)
        safe_sd = sink_dist_pad.clamp(0, SPD_UNREACHABLE)

        h = (
            self.input_proj(torch.cat((node_x_pad, deg_pad), dim=-1))
            + self.type_emb(safe_types)
            + self.root_depth_emb(safe_rd)
            + self.sink_dist_emb(safe_sd)
        )
        h = self.drop(self.input_norm(h))
        h = h * node_pad_mask.unsqueeze(-1).to(h.dtype)

        for layer in self.layers:
            h = layer(h, node_pad_mask, spd_pad, rel_pad)
        h = self.final_norm(h) * node_pad_mask.unsqueeze(-1).to(h.dtype)

        gate_logits = self.attn_gate(h).squeeze(-1).masked_fill(~node_pad_mask, -1e9)
        gate_w = F.softmax(gate_logits, dim=-1) * node_pad_mask.to(h.dtype)
        attn_pool = (h * gate_w.unsqueeze(-1)).sum(dim=1)

        max_pool = h.masked_fill(~node_pad_mask.unsqueeze(-1), -1e9).max(dim=1).values
        max_pool = torch.where(present.unsqueeze(-1), max_pool, torch.zeros_like(max_pool))

        pooled = self.pool_proj(torch.cat((attn_pool, max_pool, summary_12), dim=-1))
        pooled = torch.where(present.unsqueeze(-1), pooled, torch.zeros_like(pooled))
        return pooled, present


class ActionSubgraphIREncoderV4(nn.Module):
    """Shortcut-free Object/Action-IR encoder ensuring active 3rd modality participation."""

    def __init__(self, in_dim: int = ACTION_IR_DIM, hidden_dim: int = 128, dropout: float = 0.15) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
        )

    def forward(self, ir_x: torch.Tensor) -> torch.Tensor:
        return self.net(ir_x)


class PDFTransGraphV4(nn.Module):
    """Global Shortest-Path Graphormer + Tabular + Observable Action-IR Multimodal Detector."""

    def __init__(self, config: TransGraphV4Config) -> None:
        super().__init__()
        self.config = config
        h = config.hidden_dim
        self.tab_encoder = TabularEncoderV3(
            config.tab_dim,
            hidden_dim=h,
            num_freq_bins=config.num_freq_bins,
            dropout=config.dropout,
            use_missing_mask=config.use_missing_mask,
        )
        self.graph_encoder = ShortestPathGraphEncoderV4(
            node_dim=config.node_dim,
            hidden_dim=h,
            num_layers=config.num_graph_layers,
            num_heads=config.num_heads,
            num_node_types=config.num_node_types,
            dropout=config.dropout,
        )
        self.action_ir_encoder = ActionSubgraphIREncoderV4(
            in_dim=config.action_ir_dim,
            hidden_dim=h,
            dropout=config.dropout,
        )
        self.fusion = MaskedGatedCrossModalFusionV3(
            hidden_dim=h,
            dropout=config.dropout,
            modality_drop_prob=config.modality_drop_prob,
        )
        self.classifier = nn.Sequential(
            nn.Linear(h, h // 2),
            nn.LayerNorm(h // 2),
            nn.GELU(),
            nn.Dropout(config.dropout),
            nn.Linear(h // 2, 1),
        )
        self.tab_aux_head = nn.Linear(h, 1)
        self.graph_aux_head = nn.Linear(h, 1)
        self.ir_aux_head = nn.Linear(h, 1)

    def forward(
        self,
        tab_x: torch.Tensor,
        action_ir_x: torch.Tensor,
        action_ir_active: torch.Tensor,
        node_x_pad: torch.Tensor,
        node_type_pad: torch.Tensor,
        deg_pad: torch.Tensor,
        node_pad_mask: torch.Tensor,
        spd_pad: torch.Tensor,
        rel_pad: torch.Tensor,
        root_depth_pad: torch.Tensor,
        sink_dist_pad: torch.Tensor,
        summary_12: torch.Tensor,
    ) -> dict[str, torch.Tensor]:
        bsz = tab_x.shape[0]
        device = tab_x.device

        e_tab = self.tab_encoder(tab_x, None)
        e_graph, graph_present = self.graph_encoder(
            node_x_pad,
            node_type_pad,
            deg_pad,
            node_pad_mask,
            spd_pad,
            rel_pad,
            root_depth_pad,
            sink_dist_pad,
            summary_12,
        )
        e_ir = self.action_ir_encoder(action_ir_x)
        ir_present = action_ir_active.to(device=device, dtype=torch.bool)
        has_tab = torch.ones((bsz,), device=device, dtype=torch.bool)
        mod_mask = torch.stack((has_tab, graph_present, ir_present), dim=-1)

        fused, weights = self.fusion((e_tab, e_graph, e_ir), mod_mask)
        logits = self.classifier(fused).squeeze(-1)
        return {
            "logits": logits,
            "weights": weights,
            "modality_mask": mod_mask,
            "fused": fused,
            "tab_aux_logits": self.tab_aux_head(e_tab).squeeze(-1),
            "graph_aux_logits": self.graph_aux_head(e_graph).squeeze(-1),
            "ir_aux_logits": self.ir_aux_head(e_ir).squeeze(-1),
        }


def build_padded_graph_tensors(
    graphs: list[
        tuple[
            np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray
        ]
        | None
    ],
    device: torch.device,
) -> tuple[torch.Tensor, ...]:
    """Collate variable-size DAG structural encodings into padded batch tensors."""
    bsz = len(graphs)
    max_n = max((len(g[0]) for g in graphs if g is not None and len(g[0]) > 0), default=0)
    node_dim = 23
    nx_pad = np.zeros((bsz, max_n, node_dim), dtype=np.float32)
    nt_pad = np.zeros((bsz, max_n), dtype=np.int64)
    deg_pad = np.zeros((bsz, max_n, 2), dtype=np.float32)
    mask_pad = np.zeros((bsz, max_n), dtype=bool)
    spd_pad = np.full((bsz, max_n, max_n), SPD_UNREACHABLE, dtype=np.int64)
    rel_pad = np.zeros((bsz, max_n, max_n), dtype=np.int64)
    rd_pad = np.full((bsz, max_n), SPD_UNREACHABLE, dtype=np.int64)
    sd_pad = np.full((bsz, max_n), SPD_UNREACHABLE, dtype=np.int64)
    sum_12 = np.zeros((bsz, GRAPH_SUMMARY_DIM), dtype=np.float32)

    for b_i, g in enumerate(graphs):
        if g is None or len(g[0]) == 0:
            continue
        nx, nt, es, ed, er, spd, direct_rel, rd, sd = g
        n = len(nx)
        nx_pad[b_i, :n] = nx
        nt_pad[b_i, :n] = nt
        mask_pad[b_i, :n] = True
        spd_pad[b_i, :n, :n] = spd
        rel_pad[b_i, :n, :n] = direct_rel
        rd_pad[b_i, :n] = rd
        sd_pad[b_i, :n] = sd
        out_deg = (
            np.bincount(es[(es >= 0) & (es < n)], minlength=n).astype(np.float32)
            if len(es) > 0
            else np.zeros(n, dtype=np.float32)
        )
        in_deg = (
            np.bincount(ed[(ed >= 0) & (ed < n)], minlength=n).astype(np.float32)
            if len(ed) > 0
            else np.zeros(n, dtype=np.float32)
        )
        deg_pad[b_i, :n, 0] = np.log1p(out_deg)
        deg_pad[b_i, :n, 1] = np.log1p(in_deg)
        sum_12[b_i] = extract_graph_summary_features(
            torch.from_numpy(nt),
            torch.stack((torch.from_numpy(es), torch.from_numpy(ed)), dim=0) if len(es) > 0 else None,
            torch.zeros(n, dtype=torch.long),
            batch_size=1,
        )[0].numpy()

    return (
        torch.from_numpy(nx_pad).to(device),
        torch.from_numpy(nt_pad).to(device),
        torch.from_numpy(deg_pad).to(device),
        torch.from_numpy(mask_pad).to(device),
        torch.from_numpy(spd_pad).to(device),
        torch.from_numpy(rel_pad).to(device),
        torch.from_numpy(rd_pad).to(device),
        torch.from_numpy(sd_pad).to(device),
        torch.from_numpy(sum_12).to(device),
    )


def subtree_monotonic_loss(
    clean_mal_logits: torch.Tensor, grafted_mal_logits: torch.Tensor, margin: float = 0.25
) -> torch.Tensor:
    """Enforce Chen et al. (USENIX '20) subtree-insertion monotonicity with bounded slack."""
    if clean_mal_logits.numel() == 0:
        return torch.zeros((), device=clean_mal_logits.device)
    violation = F.relu(clean_mal_logits.detach() - grafted_mal_logits + margin)
    return (violation * violation).mean()


def save_v4_weights_npz(model: PDFTransGraphV4, path: Any) -> None:
    arrays = {f"param::{name}": tensor.detach().cpu().numpy() for name, tensor in model.state_dict().items()}
    np.savez_compressed(path, **arrays)


def load_v4_weights_npz(model: PDFTransGraphV4, path: Any, *, map_location: str | torch.device = "cpu") -> None:
    state = {}
    with np.load(path, allow_pickle=False) as archive:
        for key in archive.files:
            if key.startswith("param::"):
                state[key[len("param::") :]] = torch.from_numpy(np.array(archive[key], copy=True)).to(map_location)
    model.load_state_dict(state, strict=True)

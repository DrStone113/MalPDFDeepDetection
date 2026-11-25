"""PDF-TransGraph v4: DAG Shortest-Path Graphormer + Pure Topological Action-IR + Subtree Monotonicity."""

from __future__ import annotations

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
)
from malpdf.models.v4_graph_numpy import (
    ACTION_IR_DIM as ACTION_IR_DIM,
)
from malpdf.models.v4_graph_numpy import (
    CANONICAL_NODE_TYPES as CANONICAL_NODE_TYPES,
)
from malpdf.models.v4_graph_numpy import (
    MAX_SPD_HOPS as MAX_SPD_HOPS,
)
from malpdf.models.v4_graph_numpy import (
    SINK_NODE_TYPES as SINK_NODE_TYPES,
)
from malpdf.models.v4_graph_numpy import (
    SPD_UNREACHABLE as SPD_UNREACHABLE,
)
from malpdf.models.v4_graph_numpy import (
    compute_dag_structural_encodings as compute_dag_structural_encodings,
)
from malpdf.models.v4_graph_numpy import (
    extract_single_graph_action_ir_np as extract_single_graph_action_ir_np,
)


class _CollisionFreeBiasLookup(torch.autograd.Function):
    """Avoid CUDA L2 atomicAdd serialization when millions of padded pairs hit the same small-table row."""

    @staticmethod
    def forward(ctx: Any, idx: torch.Tensor, weight: torch.Tensor) -> torch.Tensor:
        ctx.save_for_backward(idx)
        ctx.num_classes = int(weight.shape[0])
        ctx.weight_dtype = weight.dtype
        return F.embedding(idx, weight).permute(0, 3, 1, 2)

    @staticmethod
    def backward(ctx: Any, grad_out: torch.Tensor) -> tuple[None, torch.Tensor]:
        (idx,) = ctx.saved_tensors
        m = idx.numel()
        h = grad_out.shape[1]
        g_bf16 = grad_out.permute(1, 0, 2, 3).reshape(h, m).to(torch.bfloat16)
        oh_bf16 = F.one_hot(idx.reshape(m), ctx.num_classes).to(torch.bfloat16)
        grad_w = torch.matmul(oh_bf16.t(), g_bf16.t()).to(ctx.weight_dtype)
        return None, grad_w


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
    encoder_type: str = "graphormer_dag"
    enable_graph: bool = True
    enable_tab: bool = True
    enable_action_ir: bool = True
    enable_spd_bias: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def extract_observable_action_ir_np(
    raw_73: np.ndarray | None = None,
    regime_b_indices: np.ndarray | None = None,
    idx_map: dict[str, int] | None = None,
    *,
    node_x: np.ndarray | None,
    node_type: np.ndarray | None,
    node_ptr: np.ndarray,
    row_indices: np.ndarray,
    edge_index: np.ndarray | None = None,
    edge_rel: np.ndarray | None = None,
    edge_ptr: np.ndarray | None = None,
    graph_spd_depths: list[tuple[np.ndarray, np.ndarray] | None] | None = None,
    precomputed_graphs: list[tuple[np.ndarray, ...] | None] | None = None,
) -> tuple[np.ndarray, np.ndarray]:
    """Batch-extract pure 24D graph-topological ActionSubgraphIR across corpus rows."""
    _ = (raw_73, regime_b_indices, idx_map, graph_spd_depths)
    b = len(row_indices)
    ir = np.zeros((b, ACTION_IR_DIM), dtype=np.float32)
    ir[:, 12] = 1.0
    ir[:, 13] = 1.0
    active = np.zeros((b,), dtype=bool)

    for b_i, r_idx in enumerate(row_indices.tolist()):
        if precomputed_graphs is not None:
            g = precomputed_graphs[r_idx]
            if g is None or len(g[0]) == 0:
                continue
            nx, nt, es, ed, er, spd, _, rd, sd = g[:9]
            ir[b_i], active[b_i] = extract_single_graph_action_ir_np(nx, nt, es, ed, er, spd, rd, sd)
            continue

        n0, n1 = int(node_ptr[r_idx]), int(node_ptr[r_idx + 1])
        if node_x is None or node_type is None or n1 <= n0:
            continue
        nx_i = node_x[n0:n1]
        nt_i = node_type[n0:n1]
        if edge_index is not None and edge_rel is not None and edge_ptr is not None:
            e0, e1 = int(edge_ptr[r_idx]), int(edge_ptr[r_idx + 1])
            es_i = edge_index[0, e0:e1] - n0
            ed_i = edge_index[1, e0:e1] - n0
            er_i = edge_rel[e0:e1]
        else:
            es_i = np.zeros((0,), dtype=np.int64)
            ed_i = np.zeros((0,), dtype=np.int64)
            er_i = np.zeros((0,), dtype=np.int64)
        ir[b_i], active[b_i] = extract_single_graph_action_ir_np(nx_i, nt_i, es_i, ed_i, er_i)
    return ir, active


class GraphormerDAGLayerV4(nn.Module):
    """Pre-LN multi-head self-attention with optional shortest-path and relation biases."""

    def __init__(self, hidden_dim: int, num_heads: int, dropout: float, *, enable_spd_bias: bool = True) -> None:
        super().__init__()
        self.hidden_dim = hidden_dim
        self.num_heads = num_heads
        self.head_dim = hidden_dim // num_heads
        self.enable_spd_bias = enable_spd_bias
        if hidden_dim % num_heads != 0:
            raise ValueError("hidden_dim_must_be_divisible_by_num_heads")

        self.norm1 = nn.LayerNorm(hidden_dim)
        self.qkv = nn.Linear(hidden_dim, hidden_dim * 3)
        self.out_proj = nn.Linear(hidden_dim, hidden_dim)
        if enable_spd_bias:
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
        *,
        precomputed_oh: tuple[torch.Tensor, torch.Tensor] | None = None,
    ) -> tuple[torch.Tensor, torch.Tensor]:
        bsz, n_max, hdim = h.shape
        x = self.norm1(h)
        qkv = self.qkv(x).view(bsz, n_max, 3, self.num_heads, self.head_dim)
        q = qkv[:, :, 0].transpose(1, 2)
        k = qkv[:, :, 1].transpose(1, 2)
        v = qkv[:, :, 2].transpose(1, 2)

        scores = torch.matmul(q, k.transpose(-2, -1)) / (self.head_dim**0.5)
        if self.enable_spd_bias:
            if precomputed_oh is not None:
                oh_spd, oh_rel = precomputed_oh
                dt = oh_spd.dtype
                bias = (
                    torch.matmul(oh_spd, self.spd_fwd_bias.weight.to(dt)).permute(0, 3, 1, 2)
                    + torch.matmul(oh_spd, self.spd_rev_bias.weight.to(dt)).permute(0, 3, 2, 1)
                    + torch.matmul(oh_rel, self.rel_bias.weight.to(dt)).permute(0, 3, 1, 2)
                ).to(scores.dtype)
            elif torch.is_grad_enabled() and h.is_cuda and not torch.onnx.is_in_onnx_export():
                safe_spd = spd.clamp(0, SPD_UNREACHABLE)
                safe_rel = direct_rel.clamp(0, NUM_BASE_RELATIONS)
                bias = (
                    _CollisionFreeBiasLookup.apply(safe_spd, self.spd_fwd_bias.weight)
                    + _CollisionFreeBiasLookup.apply(safe_spd.transpose(1, 2).contiguous(), self.spd_rev_bias.weight)
                    + _CollisionFreeBiasLookup.apply(safe_rel, self.rel_bias.weight)
                )
            else:
                safe_spd = spd.clamp(0, SPD_UNREACHABLE)
                safe_rel = direct_rel.clamp(0, NUM_BASE_RELATIONS)
                bias = (
                    self.spd_fwd_bias(safe_spd).permute(0, 3, 1, 2)
                    + self.spd_rev_bias(safe_spd.transpose(1, 2)).permute(0, 3, 1, 2)
                    + self.rel_bias(safe_rel).permute(0, 3, 1, 2)
                )
            scores = scores + bias

        key_mask = node_pad_mask.unsqueeze(1).unsqueeze(2)
        scores = torch.where(key_mask, scores, torch.full_like(scores, -1e9))
        attn_raw = F.softmax(scores, dim=-1)
        query_mask = node_pad_mask.unsqueeze(1).unsqueeze(-1).to(attn_raw.dtype)
        attn_clean = attn_raw * query_mask
        attn = self.drop(attn_clean)
        out = torch.matmul(attn, v).transpose(1, 2).contiguous().view(bsz, n_max, hdim)
        h = h + self.drop(self.out_proj(out))
        return h + self.ffn(self.norm2(h)), attn_clean.mean(dim=1)


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
        *,
        enable_spd_bias: bool = True,
    ) -> None:
        super().__init__()
        self.node_dim = node_dim
        self.hidden_dim = hidden_dim
        self.num_node_types = num_node_types
        self.enable_spd_bias = enable_spd_bias

        self.mask_node_token = nn.Parameter(torch.zeros(node_dim))
        self.input_proj = nn.Linear(node_dim + 2, hidden_dim)
        self.type_emb = nn.Embedding(num_node_types, hidden_dim)
        if enable_spd_bias:
            self.root_depth_emb = nn.Embedding(SPD_UNREACHABLE + 1, hidden_dim)
            self.sink_dist_emb = nn.Embedding(SPD_UNREACHABLE + 1, hidden_dim)
        self.input_norm = nn.LayerNorm(hidden_dim)
        self.drop = nn.Dropout(dropout)

        self.layers = nn.ModuleList(
            [
                GraphormerDAGLayerV4(hidden_dim, num_heads, dropout, enable_spd_bias=enable_spd_bias)
                for _ in range(num_layers)
            ]
        )
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

    def encode_padded_nodes(
        self,
        node_x_pad: torch.Tensor,
        node_type_pad: torch.Tensor,
        deg_pad: torch.Tensor,
        node_pad_mask: torch.Tensor,
        spd_pad: torch.Tensor,
        rel_pad: torch.Tensor,
        root_depth_pad: torch.Tensor,
        sink_dist_pad: torch.Tensor,
        *,
        ssl_node_mask: torch.Tensor | None = None,
    ) -> tuple[torch.Tensor, torch.Tensor]:
        x = node_x_pad
        if ssl_node_mask is not None:
            x = torch.where(ssl_node_mask.unsqueeze(-1), self.mask_node_token.view(1, 1, -1).expand_as(x), x)

        safe_types = node_type_pad.clamp(0, self.num_node_types - 1)
        h = self.input_proj(torch.cat((x, deg_pad), dim=-1)) + self.type_emb(safe_types)
        if self.enable_spd_bias:
            safe_rd = root_depth_pad.clamp(0, SPD_UNREACHABLE)
            safe_sd = sink_dist_pad.clamp(0, SPD_UNREACHABLE)
            h = h + self.root_depth_emb(safe_rd) + self.sink_dist_emb(safe_sd)

        mask_f = node_pad_mask.unsqueeze(-1).to(h.dtype)
        h = self.drop(self.input_norm(h)) * mask_f
        pre_oh: tuple[torch.Tensor, torch.Tensor] | None = None
        if self.enable_spd_bias and torch.is_grad_enabled() and h.is_cuda and not torch.onnx.is_in_onnx_export():
            oh_dt = torch.bfloat16 if torch.is_autocast_enabled() else h.dtype
            safe_spd = spd_pad.clamp(0, SPD_UNREACHABLE)
            safe_rel = rel_pad.clamp(0, NUM_BASE_RELATIONS)
            pre_oh = (
                (safe_spd.unsqueeze(-1) == torch.arange(SPD_UNREACHABLE + 1, device=h.device)).to(oh_dt),
                (safe_rel.unsqueeze(-1) == torch.arange(NUM_BASE_RELATIONS + 1, device=h.device)).to(oh_dt),
            )
        last_attn = torch.zeros(
            (node_x_pad.shape[0], node_x_pad.shape[1], node_x_pad.shape[1]),
            device=node_x_pad.device,
            dtype=h.dtype,
        )
        for layer in self.layers:
            h, last_attn = layer(h, node_pad_mask, spd_pad, rel_pad, precomputed_oh=pre_oh)
        return self.final_norm(h) * mask_f, last_attn

    def pool_encoded_nodes(
        self,
        h: torch.Tensor,
        node_pad_mask: torch.Tensor,
        summary_12: torch.Tensor,
    ) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        present = node_pad_mask.any(dim=1)
        gate_raw = self.attn_gate(h).squeeze(-1)
        gate_logits = torch.where(node_pad_mask, gate_raw, torch.full_like(gate_raw, -1e9))
        gate_w = F.softmax(gate_logits, dim=-1) * node_pad_mask.to(h.dtype)
        attn_pool = (h * gate_w.unsqueeze(-1)).sum(dim=1)

        neg_inf = torch.full_like(h, -1e9)
        max_pool = torch.where(node_pad_mask.unsqueeze(-1), h, neg_inf).max(dim=1).values
        max_pool = torch.where(present.unsqueeze(-1), max_pool, torch.zeros_like(max_pool))

        pooled = self.pool_proj(torch.cat((attn_pool, max_pool, summary_12), dim=-1))
        pooled = torch.where(present.unsqueeze(-1), pooled, torch.zeros_like(pooled))
        return pooled, present, gate_w

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
        *,
        return_details: bool = False,
    ) -> tuple[torch.Tensor, torch.Tensor] | tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        bsz, n_max, _ = node_x_pad.shape
        device = node_x_pad.device
        if n_max == 0:
            empty_pool = torch.zeros((bsz, self.hidden_dim), device=device, dtype=torch.float32)
            empty_pres = torch.zeros((bsz,), device=device, dtype=torch.bool)
            if return_details:
                return (
                    empty_pool,
                    empty_pres,
                    torch.zeros((bsz, 0), device=device, dtype=torch.float32),
                    torch.zeros((bsz, 0, 0), device=device, dtype=torch.float32),
                )
            return empty_pool, empty_pres

        h, pair_attn = self.encode_padded_nodes(
            node_x_pad,
            node_type_pad,
            deg_pad,
            node_pad_mask,
            spd_pad,
            rel_pad,
            root_depth_pad,
            sink_dist_pad,
        )
        pooled, present, gate_w = self.pool_encoded_nodes(h, node_pad_mask, summary_12)
        if return_details:
            return pooled, present, gate_w, pair_attn
        return pooled, present


class _GINRelationLayerV4(nn.Module):
    """Relation-aware Weisfeiler-Lehman Graph Isomorphism Network layer for GNN baseline comparison."""

    def __init__(self, hidden_dim: int, dropout: float) -> None:
        super().__init__()
        self.eps = nn.Parameter(torch.zeros(1))
        self.rel_emb = nn.Embedding(NUM_BASE_RELATIONS + 1, hidden_dim, padding_idx=0)
        self.mlp = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim * 2),
            nn.LayerNorm(hidden_dim * 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
        )

    def forward(self, h: torch.Tensor, node_pad_mask: torch.Tensor, direct_rel: torch.Tensor) -> torch.Tensor:
        safe_rel = direct_rel.clamp(0, NUM_BASE_RELATIONS)
        valid_pair = node_pad_mask.unsqueeze(1) & node_pad_mask.unsqueeze(2)
        adj_f = ((safe_rel > 0) & valid_pair).to(h.dtype)
        nei_sum = torch.matmul(adj_f.transpose(1, 2), h)
        rel_counts = torch.stack(
            [((safe_rel == r) & valid_pair).sum(dim=1) for r in range(1, NUM_BASE_RELATIONS + 1)],
            dim=-1,
        ).to(h.dtype)
        rel_sum = torch.matmul(rel_counts, self.rel_emb.weight[1 : NUM_BASE_RELATIONS + 1])
        agg = (1.0 + self.eps) * h + nei_sum + rel_sum
        return (h + self.mlp(agg)) * node_pad_mask.unsqueeze(-1).to(h.dtype)


class GINGraphEncoderV4(nn.Module):
    """Standard GIN graph encoder operating on identical padded inputs for clean ablation benchmarking."""

    def __init__(
        self,
        node_dim: int = 23,
        hidden_dim: int = 128,
        num_layers: int = 3,
        num_node_types: int = NUM_NODE_TYPES,
        dropout: float = 0.15,
    ) -> None:
        super().__init__()
        self.node_dim = node_dim
        self.hidden_dim = hidden_dim
        self.num_node_types = num_node_types

        self.mask_node_token = nn.Parameter(torch.zeros(node_dim))
        self.input_proj = nn.Linear(node_dim + 2, hidden_dim)
        self.type_emb = nn.Embedding(num_node_types, hidden_dim)
        self.input_norm = nn.LayerNorm(hidden_dim)
        self.drop = nn.Dropout(dropout)
        self.layers = nn.ModuleList([_GINRelationLayerV4(hidden_dim, dropout) for _ in range(num_layers)])
        self.final_norm = nn.LayerNorm(hidden_dim)
        self.pool_proj = nn.Sequential(
            nn.Linear(hidden_dim * 2 + GRAPH_SUMMARY_DIM, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
        )

    def encode_padded_nodes(
        self,
        node_x_pad: torch.Tensor,
        node_type_pad: torch.Tensor,
        deg_pad: torch.Tensor,
        node_pad_mask: torch.Tensor,
        spd_pad: torch.Tensor,
        rel_pad: torch.Tensor,
        root_depth_pad: torch.Tensor,
        sink_dist_pad: torch.Tensor,
        *,
        ssl_node_mask: torch.Tensor | None = None,
    ) -> tuple[torch.Tensor, torch.Tensor]:
        _ = (spd_pad, root_depth_pad, sink_dist_pad)
        x = node_x_pad
        if ssl_node_mask is not None:
            x = torch.where(ssl_node_mask.unsqueeze(-1), self.mask_node_token.view(1, 1, -1).expand_as(x), x)
        safe_types = node_type_pad.clamp(0, self.num_node_types - 1)
        mask_f = node_pad_mask.unsqueeze(-1).to(x.dtype)
        h = self.drop(self.input_norm(self.input_proj(torch.cat((x, deg_pad), dim=-1)) + self.type_emb(safe_types)))
        h = h * mask_f
        for layer in self.layers:
            h = layer(h, node_pad_mask, rel_pad)
        pair_attn = (rel_pad > 0).to(h.dtype)
        return self.final_norm(h) * mask_f, pair_attn

    def pool_encoded_nodes(
        self,
        h: torch.Tensor,
        node_pad_mask: torch.Tensor,
        summary_12: torch.Tensor,
    ) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        present = node_pad_mask.any(dim=1)
        mask_f = node_pad_mask.to(h.dtype)
        denom = mask_f.sum(dim=1, keepdim=True).clamp(min=1.0)
        mean_pool = (h * mask_f.unsqueeze(-1)).sum(dim=1) / denom
        gate_w = mask_f / denom

        neg_inf = torch.full_like(h, -1e9)
        max_pool = torch.where(node_pad_mask.unsqueeze(-1), h, neg_inf).max(dim=1).values
        max_pool = torch.where(present.unsqueeze(-1), max_pool, torch.zeros_like(max_pool))

        pooled = self.pool_proj(torch.cat((mean_pool, max_pool, summary_12), dim=-1))
        pooled = torch.where(present.unsqueeze(-1), pooled, torch.zeros_like(pooled))
        return pooled, present, gate_w

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
        *,
        return_details: bool = False,
    ) -> tuple[torch.Tensor, torch.Tensor] | tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        bsz, n_max, _ = node_x_pad.shape
        device = node_x_pad.device
        if n_max == 0:
            empty_pool = torch.zeros((bsz, self.hidden_dim), device=device, dtype=torch.float32)
            empty_pres = torch.zeros((bsz,), device=device, dtype=torch.bool)
            if return_details:
                return (
                    empty_pool,
                    empty_pres,
                    torch.zeros((bsz, 0), device=device, dtype=torch.float32),
                    torch.zeros((bsz, 0, 0), device=device, dtype=torch.float32),
                )
            return empty_pool, empty_pres

        h, pair_attn = self.encode_padded_nodes(
            node_x_pad,
            node_type_pad,
            deg_pad,
            node_pad_mask,
            spd_pad,
            rel_pad,
            root_depth_pad,
            sink_dist_pad,
        )
        pooled, present, gate_w = self.pool_encoded_nodes(h, node_pad_mask, summary_12)
        if return_details:
            return pooled, present, gate_w, pair_attn
        return pooled, present


class ActionSubgraphIREncoderV4(nn.Module):
    """Pure topological Action-IR encoder free of tabular lexical shortcuts."""

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
    """Global Shortest-Path Graphormer + Tabular + Pure Topological Action-IR Multimodal Detector."""

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
        if config.encoder_type == "gin":
            self.graph_encoder: nn.Module = GINGraphEncoderV4(
                node_dim=config.node_dim,
                hidden_dim=h,
                num_layers=config.num_graph_layers,
                num_node_types=config.num_node_types,
                dropout=config.dropout,
            )
        elif config.encoder_type == "graphormer_dag":
            self.graph_encoder = ShortestPathGraphEncoderV4(
                node_dim=config.node_dim,
                hidden_dim=h,
                num_layers=config.num_graph_layers,
                num_heads=config.num_heads,
                num_node_types=config.num_node_types,
                dropout=config.dropout,
                enable_spd_bias=config.enable_spd_bias,
            )
        else:
            raise ValueError(f"unsupported_v4_encoder_type:{config.encoder_type}")

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

        self.ssl_tab_mask_token = nn.Parameter(torch.zeros(config.tab_dim))
        self.ssl_tab_head = nn.Linear(h, config.tab_dim)
        self.ssl_node_feat_head = nn.Linear(h, config.node_dim)
        self.ssl_node_type_head = nn.Linear(h, config.num_node_types)
        self.ssl_tab_proj = nn.Linear(h, h)
        self.ssl_graph_proj = nn.Linear(h, h)

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
        *,
        return_graph_details: bool = False,
    ) -> dict[str, torch.Tensor]:
        bsz = tab_x.shape[0]
        device = tab_x.device

        if self.config.enable_tab:
            e_tab = self.tab_encoder(tab_x, None)
            has_tab = torch.ones((bsz,), device=device, dtype=torch.bool)
        else:
            e_tab = torch.zeros((bsz, self.config.hidden_dim), device=device, dtype=tab_x.dtype)
            has_tab = torch.zeros((bsz,), device=device, dtype=torch.bool)

        if self.config.enable_graph:
            if return_graph_details:
                e_graph, graph_present, node_gate_w, pair_attn = self.graph_encoder(
                    node_x_pad,
                    node_type_pad,
                    deg_pad,
                    node_pad_mask,
                    spd_pad,
                    rel_pad,
                    root_depth_pad,
                    sink_dist_pad,
                    summary_12,
                    return_details=True,
                )
            else:
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
                node_gate_w = None
                pair_attn = None
        else:
            e_graph = torch.zeros((bsz, self.config.hidden_dim), device=device, dtype=tab_x.dtype)
            graph_present = torch.zeros((bsz,), device=device, dtype=torch.bool)
            node_gate_w = torch.zeros((bsz, node_x_pad.shape[1]), device=device, dtype=tab_x.dtype)
            pair_attn = torch.zeros((bsz, node_x_pad.shape[1], node_x_pad.shape[1]), device=device, dtype=tab_x.dtype)

        if self.config.enable_action_ir:
            e_ir = self.action_ir_encoder(action_ir_x)
            ir_present = action_ir_active.to(device=device, dtype=torch.bool) & graph_present
        else:
            e_ir = torch.zeros((bsz, self.config.hidden_dim), device=device, dtype=tab_x.dtype)
            ir_present = torch.zeros((bsz,), device=device, dtype=torch.bool)

        mod_mask = torch.stack((has_tab, graph_present, ir_present), dim=-1)
        fused, weights = self.fusion((e_tab, e_graph, e_ir), mod_mask)
        logits = self.classifier(fused).squeeze(-1)
        out = {
            "logits": logits,
            "weights": weights,
            "modality_mask": mod_mask,
            "fused": fused,
            "tab_emb": e_tab,
            "graph_emb": e_graph,
            "ir_emb": e_ir,
            "tab_aux_logits": self.tab_aux_head(e_tab).squeeze(-1),
            "graph_aux_logits": self.graph_aux_head(e_graph).squeeze(-1),
            "ir_aux_logits": self.ir_aux_head(e_ir).squeeze(-1),
        }
        if return_graph_details and node_gate_w is not None and pair_attn is not None:
            out["node_gate_weights"] = node_gate_w
            out["pair_attn"] = pair_attn
        return out

    def ssl_loss(
        self,
        tab_x_clean: torch.Tensor,
        tab_mask: torch.Tensor,
        node_x_pad: torch.Tensor,
        node_type_pad: torch.Tensor,
        deg_pad: torch.Tensor,
        node_pad_mask: torch.Tensor,
        spd_pad: torch.Tensor,
        rel_pad: torch.Tensor,
        root_depth_pad: torch.Tensor,
        sink_dist_pad: torch.Tensor,
        summary_12: torch.Tensor,
        node_ssl_mask: torch.Tensor,
    ) -> torch.Tensor:
        """Self-supervised pretraining loss over unlabeled + labeled PDFs (TabMAE + GraphMAE + Contrastive)."""
        tab_corrupt = torch.where(tab_mask, self.ssl_tab_mask_token.unsqueeze(0).expand_as(tab_x_clean), tab_x_clean)
        e_tab = self.tab_encoder(tab_corrupt, None)
        pred_tab = self.ssl_tab_head(e_tab)
        if tab_mask.any():
            loss_tab = F.smooth_l1_loss(pred_tab[tab_mask], tab_x_clean[tab_mask].clamp(-10.0, 10.0))
        else:
            loss_tab = pred_tab.sum() * 0.0

        if not self.config.enable_graph or node_x_pad.shape[1] == 0 or not node_pad_mask.any():
            return loss_tab

        active_node_mask = node_ssl_mask & node_pad_mask
        h_nodes, _ = self.graph_encoder.encode_padded_nodes(  # type: ignore[operator]
            node_x_pad,
            node_type_pad,
            deg_pad,
            node_pad_mask,
            spd_pad,
            rel_pad,
            root_depth_pad,
            sink_dist_pad,
            ssl_node_mask=active_node_mask,
        )
        if active_node_mask.any():
            pred_nx = self.ssl_node_feat_head(h_nodes[active_node_mask])
            pred_nt = self.ssl_node_type_head(h_nodes[active_node_mask])
            loss_nf = F.smooth_l1_loss(pred_nx, node_x_pad[active_node_mask].clamp(-10.0, 10.0))
            loss_nt = F.cross_entropy(pred_nt, node_type_pad[active_node_mask].clamp(0, self.config.num_node_types - 1))
        else:
            loss_nf = h_nodes.sum() * 0.0
            loss_nt = h_nodes.sum() * 0.0

        e_graph, graph_present, _ = self.graph_encoder.pool_encoded_nodes(h_nodes, node_pad_mask, summary_12)  # type: ignore[operator]
        if int(graph_present.sum().item()) >= 4:
            zt = F.normalize(self.ssl_tab_proj(e_tab[graph_present]), dim=-1)
            zg = F.normalize(self.ssl_graph_proj(e_graph[graph_present]), dim=-1)
            sim = torch.matmul(zt, zg.t()) / 0.15
            targets = torch.arange(zt.shape[0], device=zt.device)
            loss_cl = 0.5 * (F.cross_entropy(sim, targets) + F.cross_entropy(sim.t(), targets))
        else:
            loss_cl = e_graph.sum() * 0.0

        return loss_tab + loss_nf + 0.5 * loss_nt + 0.35 * loss_cl


def build_padded_graph_tensors(
    graphs: list[tuple[np.ndarray, ...] | None],
    device: torch.device,
    *,
    min_nodes: int = 0,
) -> tuple[torch.Tensor, ...]:
    """Collate variable-size DAG structural encodings into padded batch tensors."""
    bsz = len(graphs)
    max_n = max(
        min_nodes,
        max((len(g[0]) for g in graphs if g is not None and len(g[0]) > 0), default=0),
    )
    node_dim = 23
    nx_pad = np.zeros((bsz, max_n, node_dim), dtype=np.float32)
    nt_pad = np.zeros((bsz, max_n), dtype=np.uint8)
    deg_pad = np.zeros((bsz, max_n, 2), dtype=np.float32)
    mask_pad = np.zeros((bsz, max_n), dtype=bool)
    spd_pad = np.full((bsz, max_n, max_n), SPD_UNREACHABLE, dtype=np.uint8)
    rel_pad = np.zeros((bsz, max_n, max_n), dtype=np.uint8)
    rd_pad = np.full((bsz, max_n), SPD_UNREACHABLE, dtype=np.uint8)
    sd_pad = np.full((bsz, max_n), SPD_UNREACHABLE, dtype=np.uint8)
    sum_12 = np.zeros((bsz, GRAPH_SUMMARY_DIM), dtype=np.float32)

    for b_i, g in enumerate(graphs):
        if g is None or len(g[0]) == 0:
            continue
        nx, nt, es, ed, _er, spd, direct_rel, rd, sd = g[:9]
        n = len(nx)
        nx_pad[b_i, :n] = nx
        nt_pad[b_i, :n] = nt
        mask_pad[b_i, :n] = True
        spd_pad[b_i, :n, :n] = spd
        rel_pad[b_i, :n, :n] = direct_rel
        rd_pad[b_i, :n] = rd
        sd_pad[b_i, :n] = sd
        if len(g) >= 11:
            deg_pad[b_i, :n] = g[9]
            sum_12[b_i] = g[10]
        else:
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

    return (
        torch.from_numpy(nx_pad).to(device),
        torch.from_numpy(nt_pad).to(device=device, dtype=torch.long),
        torch.from_numpy(deg_pad).to(device),
        torch.from_numpy(mask_pad).to(device),
        torch.from_numpy(spd_pad).to(device=device, dtype=torch.long),
        torch.from_numpy(rel_pad).to(device=device, dtype=torch.long),
        torch.from_numpy(rd_pad).to(device=device, dtype=torch.long),
        torch.from_numpy(sd_pad).to(device=device, dtype=torch.long),
        torch.from_numpy(sum_12).to(device),
    )


def subtree_monotonic_loss(
    clean_mal_logits: torch.Tensor, grafted_mal_logits: torch.Tensor, margin: float = 0.0
) -> torch.Tensor:
    """Enforce Chen et al. (USENIX '20) probability-space subtree-insertion monotonicity without logit ratcheting."""
    if clean_mal_logits.numel() == 0:
        return torch.zeros((), device=clean_mal_logits.device)
    p_clean = torch.sigmoid(clean_mal_logits.detach().float())
    p_graft = torch.sigmoid(grafted_mal_logits.float())
    violation = F.relu(p_clean - p_graft + margin)
    return (violation * violation).mean()


def benign_graft_stability_loss(
    clean_ben_logits: torch.Tensor, grafted_ben_logits: torch.Tensor, margin: float = 0.0
) -> torch.Tensor:
    """Prevent benign subtree grafting from inflating benign probabilities upward."""
    if clean_ben_logits.numel() == 0:
        return torch.zeros((), device=clean_ben_logits.device)
    p_clean = torch.sigmoid(clean_ben_logits.detach().float())
    p_graft = torch.sigmoid(grafted_ben_logits.float())
    violation = F.relu(p_graft - p_clean - margin)
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

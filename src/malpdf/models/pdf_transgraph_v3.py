"""PDF-TransGraph v3: anti-shortcut bidirectional multimodal detector with masked fusion and SSL."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import math
from typing import Any

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

NUM_NODE_TYPES = 9
NUM_BASE_RELATIONS = 8
GRAPH_SUMMARY_DIM = 12


@dataclass(frozen=True)
class TransGraphV3Config:
    """Architecture hyperparameters persisted alongside weight arrays."""

    tab_dim: int
    ast_dim: int = 26
    node_dim: int = 23
    hidden_dim: int = 128
    num_graph_layers: int = 2
    num_node_types: int = NUM_NODE_TYPES
    num_base_relations: int = NUM_BASE_RELATIONS
    num_freq_bins: int = 4
    dropout: float = 0.15
    modality_drop_prob: float = 0.10
    use_missing_mask: bool = True
    enable_graph: bool = True
    enable_tab: bool = True
    enable_ast: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _segment_softmax(logits: torch.Tensor, segment_ids: torch.Tensor, num_segments: int) -> torch.Tensor:
    """Compute numerically stable softmax over arbitrary segment indices without PyG."""
    if logits.numel() == 0:
        return logits
    seg_max = torch.full((num_segments,), -1e9, device=logits.device, dtype=logits.dtype)
    seg_max.scatter_reduce_(0, segment_ids, logits, reduce="amax", include_self=True)
    shifted = (logits - seg_max[segment_ids]).clamp(max=20.0)
    exp_vals = torch.exp(shifted)
    seg_sum = torch.zeros((num_segments,), device=logits.device, dtype=logits.dtype)
    seg_sum.scatter_add_(0, segment_ids, exp_vals)
    return exp_vals / (seg_sum[segment_ids] + 1e-8)


def extract_graph_summary_features(
    node_type: torch.Tensor | None,
    edge_index: torch.Tensor | None,
    graph_batch: torch.Tensor | None,
    batch_size: int,
    *,
    num_node_types: int = NUM_NODE_TYPES,
    device: torch.device | None = None,
) -> torch.Tensor:
    """Build 12D log1p structural summary: 9 node-type counts, nodes, edges, orphans."""
    out_device = device or (node_type.device if node_type is not None else torch.device("cpu"))
    counts = torch.zeros((batch_size, num_node_types + 3), device=out_device, dtype=torch.float32)
    if node_type is None or graph_batch is None or node_type.numel() == 0:
        return counts

    num_nodes = node_type.shape[0]
    clipped_type = node_type.clamp(0, num_node_types - 1)
    type_one_hot = F.one_hot(clipped_type, num_classes=num_node_types).to(torch.float32)
    counts[:, :num_node_types].index_add_(0, graph_batch, type_one_hot)

    ones = torch.ones((num_nodes,), device=out_device, dtype=torch.float32)
    counts[:, num_node_types].index_add_(0, graph_batch, ones)

    degree = torch.zeros((num_nodes,), device=out_device, dtype=torch.float32)
    if edge_index is not None and edge_index.numel() > 0:
        src = edge_index[0]
        dst = edge_index[1]
        edge_batch = graph_batch[src]
        edge_ones = torch.ones((src.shape[0],), device=out_device, dtype=torch.float32)
        counts[:, num_node_types + 1].index_add_(0, edge_batch, edge_ones)
        degree.index_add_(0, src, edge_ones)
        degree.index_add_(0, dst, edge_ones)

    orphan = (degree == 0).to(torch.float32)
    counts[:, num_node_types + 2].index_add_(0, graph_batch, orphan)
    return torch.log1p(counts)


class _BidirectionalRelationLayerV3(nn.Module):
    """Pre-LN bidirectional relation-aware graph attention + residual FFN layer."""

    def __init__(self, hidden_dim: int, num_relations: int, dropout: float) -> None:
        super().__init__()
        self.norm1 = nn.LayerNorm(hidden_dim)
        self.rel_emb = nn.Embedding(num_relations, hidden_dim)
        self.msg_proj = nn.Linear(hidden_dim, hidden_dim)
        self.attn_proj = nn.Linear(hidden_dim * 3, 1)
        self.out_proj = nn.Linear(hidden_dim, hidden_dim)
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
        edge_index: torch.Tensor | None,
        edge_rel: torch.Tensor | None,
    ) -> torch.Tensor:
        if h.shape[0] == 0:
            return h
        h_norm = self.norm1(h)
        if edge_index is not None and edge_rel is not None and edge_index.numel() > 0:
            src, dst = edge_index[0], edge_index[1]
            r = self.rel_emb(edge_rel)
            h_src = h_norm[src]
            h_dst = h_norm[dst]
            logits = self.attn_proj(torch.cat((h_dst, h_src, r), dim=-1)).squeeze(-1)
            alpha = _segment_softmax(logits, dst, h.shape[0])
            msg = self.drop(alpha).unsqueeze(-1) * (self.msg_proj(h_src) + r)
            agg = torch.zeros_like(h_norm)
            agg.index_add_(0, dst, msg)
            h = h + self.drop(self.out_proj(agg))
        else:
            h = h + self.drop(self.out_proj(torch.zeros_like(h_norm)))
        return h + self.ffn(self.norm2(h))


class BidirectionalHeteroGraphEncoderV3(nn.Module):
    """Dynamic-degree bidirectional graph encoder with multi-scale empty-safe pooling."""

    def __init__(
        self,
        node_dim: int = 23,
        hidden_dim: int = 128,
        num_layers: int = 2,
        num_node_types: int = NUM_NODE_TYPES,
        num_base_relations: int = NUM_BASE_RELATIONS,
        dropout: float = 0.15,
    ) -> None:
        super().__init__()
        self.node_dim = node_dim
        self.hidden_dim = hidden_dim
        self.num_node_types = num_node_types
        self.num_base_relations = num_base_relations

        self.mask_node_token = nn.Parameter(torch.zeros(node_dim))
        self.input_proj = nn.Linear(node_dim + 2, hidden_dim)
        self.type_emb = nn.Embedding(num_node_types, hidden_dim)
        self.input_norm = nn.LayerNorm(hidden_dim)
        self.drop = nn.Dropout(dropout)

        self.layers = nn.ModuleList(
            [
                _BidirectionalRelationLayerV3(hidden_dim, num_base_relations * 2, dropout)
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

    def encode_nodes(
        self,
        node_x: torch.Tensor,
        node_type: torch.Tensor,
        edge_index: torch.Tensor | None,
        edge_rel: torch.Tensor | None,
        node_mask: torch.Tensor | None = None,
    ) -> torch.Tensor:
        if node_x.shape[0] == 0:
            return torch.zeros((0, self.hidden_dim), device=node_x.device, dtype=torch.float32)

        x = node_x
        if node_mask is not None and node_mask.any():
            x = torch.where(node_mask.unsqueeze(-1), self.mask_node_token.expand_as(node_x), node_x)

        out_deg = torch.zeros((x.shape[0],), device=x.device, dtype=torch.float32)
        in_deg = torch.zeros((x.shape[0],), device=x.device, dtype=torch.float32)
        bi_index: torch.Tensor | None = None
        bi_rel: torch.Tensor | None = None
        if edge_index is not None and edge_rel is not None and edge_index.numel() > 0:
            src, dst = edge_index[0], edge_index[1]
            ones = torch.ones((src.shape[0],), device=x.device, dtype=torch.float32)
            out_deg.index_add_(0, src, ones)
            in_deg.index_add_(0, dst, ones)
            bi_index = torch.cat((edge_index, torch.stack((dst, src), dim=0)), dim=1)
            clipped_rel = edge_rel.clamp(0, self.num_base_relations - 1)
            bi_rel = torch.cat((clipped_rel, clipped_rel + self.num_base_relations), dim=0)

        deg_feats = torch.stack((torch.log1p(out_deg), torch.log1p(in_deg)), dim=-1)
        clipped_types = node_type.clamp(0, self.num_node_types - 1)
        h = self.input_proj(torch.cat((x, deg_feats), dim=-1)) + self.type_emb(clipped_types)
        h = self.drop(self.input_norm(h))
        for layer in self.layers:
            h = layer(h, bi_index, bi_rel)
        return self.final_norm(h)

    def forward(
        self,
        node_x: torch.Tensor | None,
        node_type: torch.Tensor | None,
        edge_index: torch.Tensor | None,
        edge_rel: torch.Tensor | None,
        graph_batch: torch.Tensor | None,
        batch_size: int,
        *,
        node_mask: torch.Tensor | None = None,
        return_node_embeddings: bool = False,
    ) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor] | tuple[torch.Tensor, torch.Tensor]:
        device = next(self.parameters()).device
        summary = extract_graph_summary_features(
            node_type, edge_index, graph_batch, batch_size, num_node_types=self.num_node_types, device=device
        )
        if node_x is None or node_type is None or graph_batch is None or node_x.shape[0] == 0:
            empty_emb = torch.zeros((batch_size, self.hidden_dim), device=device, dtype=torch.float32)
            empty_present = torch.zeros((batch_size,), device=device, dtype=torch.bool)
            if return_node_embeddings:
                empty_nodes = torch.zeros((0, self.hidden_dim), device=device, dtype=torch.float32)
                return empty_emb, empty_present, empty_nodes
            return empty_emb, empty_present

        node_counts = torch.bincount(graph_batch, minlength=batch_size)
        present = node_counts > 0
        h_nodes = self.encode_nodes(node_x, node_type, edge_index, edge_rel, node_mask=node_mask)

        attn_logits = self.attn_gate(h_nodes).squeeze(-1)
        attn_weights = _segment_softmax(attn_logits, graph_batch, batch_size).unsqueeze(-1)
        attn_pool = torch.zeros((batch_size, self.hidden_dim), device=device, dtype=torch.float32)
        attn_pool.index_add_(0, graph_batch, attn_weights * h_nodes)

        # Safe max-pooling: zero empty graphs instead of retaining negative sentinel fill values.
        max_pool = torch.full((batch_size, self.hidden_dim), -1e9, device=device, dtype=torch.float32)
        max_pool.scatter_reduce_(0, graph_batch.unsqueeze(-1).expand_as(h_nodes), h_nodes, reduce="amax", include_self=True)
        max_pool = torch.where(present.unsqueeze(-1), max_pool, torch.zeros_like(max_pool))

        pooled = self.pool_proj(torch.cat((attn_pool, max_pool, summary), dim=-1))
        pooled = torch.where(present.unsqueeze(-1), pooled, torch.zeros_like(pooled))
        if return_node_embeddings:
            return pooled, present, h_nodes
        return pooled, present


class _ResidualBlock(nn.Module):
    def __init__(self, hidden_dim: int, dropout: float) -> None:
        super().__init__()
        self.norm = nn.LayerNorm(hidden_dim)
        self.net = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim * 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.Dropout(dropout),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return x + self.net(self.norm(x))


class TabularEncoderV3(nn.Module):
    """Periodic + linear numerical tokenizer with optional missingness indicator pathway."""

    def __init__(
        self,
        in_dim: int,
        hidden_dim: int = 128,
        num_freq_bins: int = 4,
        dropout: float = 0.15,
        *,
        use_missing_mask: bool = True,
    ) -> None:
        super().__init__()
        self.in_dim = in_dim
        self.hidden_dim = hidden_dim
        self.num_freq_bins = num_freq_bins
        self.use_missing_mask = use_missing_mask

        self.freqs = nn.Parameter(torch.randn(in_dim, num_freq_bins) * 0.5)
        self.feature_mask_token = nn.Parameter(torch.zeros(in_dim))
        per_feat_dim = 1 + 2 * num_freq_bins
        self.tok_weight = nn.Parameter(torch.empty(in_dim, per_feat_dim, 8))
        self.tok_bias = nn.Parameter(torch.zeros(in_dim, 8))
        nn.init.xavier_uniform_(self.tok_weight)

        self.proj = nn.Linear(in_dim * 8, hidden_dim)
        self.miss_proj = nn.Linear(in_dim, hidden_dim) if use_missing_mask else None
        self.in_norm = nn.LayerNorm(hidden_dim)
        self.blocks = nn.ModuleList([_ResidualBlock(hidden_dim, dropout), _ResidualBlock(hidden_dim, dropout)])
        self.out_norm = nn.LayerNorm(hidden_dim)

    def forward(
        self,
        tab_x: torch.Tensor,
        tab_missing: torch.Tensor | None = None,
        ssl_mask: torch.Tensor | None = None,
    ) -> torch.Tensor:
        x = tab_x
        if ssl_mask is not None and ssl_mask.any():
            x = torch.where(ssl_mask, self.feature_mask_token.unsqueeze(0).expand_as(tab_x), tab_x)

        angles = 2.0 * math.pi * x.unsqueeze(-1) * self.freqs.unsqueeze(0)
        periodic = torch.cat((x.unsqueeze(-1), torch.sin(angles), torch.cos(angles)), dim=-1)
        tokens = torch.einsum("bid,idh->bih", periodic, self.tok_weight) + self.tok_bias
        h = self.proj(tokens.reshape(x.shape[0], -1))
        if self.use_missing_mask and self.miss_proj is not None and tab_missing is not None:
            h = h + self.miss_proj(tab_missing.to(torch.float32))
        h = self.in_norm(h)
        for block in self.blocks:
            h = block(h)
        return self.out_norm(h)


class ASTSemanticEncoderV3(nn.Module):
    """Compact MLP encoder over continuous Contract v3 AST features + availability flags."""

    def __init__(self, ast_dim: int = 26, hidden_dim: int = 128, dropout: float = 0.15) -> None:
        super().__init__()
        self.ast_dim = ast_dim
        self.net = nn.Sequential(
            nn.Linear(ast_dim * 2, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout),
        )
        self.block = _ResidualBlock(hidden_dim, dropout)
        self.norm = nn.LayerNorm(hidden_dim)

    def forward(self, ast_x: torch.Tensor, ast_missing: torch.Tensor) -> torch.Tensor:
        x = torch.cat((ast_x, ast_missing.to(torch.float32)), dim=-1)
        return self.norm(self.block(self.net(x)))


class MaskedGatedCrossModalFusionV3(nn.Module):
    """Exact zero-weight and zero-gradient fusion for inactive modalities."""

    def __init__(self, hidden_dim: int = 128, dropout: float = 0.15, modality_drop_prob: float = 0.10) -> None:
        super().__init__()
        self.hidden_dim = hidden_dim
        self.modality_drop_prob = modality_drop_prob

        self.norms = nn.ModuleList([nn.LayerNorm(hidden_dim) for _ in range(3)])
        self.gate_net = nn.Sequential(
            nn.Linear(hidden_dim * 3 + 3, hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, 3),
        )
        self.pair_proj = nn.Linear(hidden_dim, hidden_dim)
        self.out_proj = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout),
        )

    def _effective_mask(self, modality_mask: torch.Tensor) -> torch.Tensor:
        if not self.training or self.modality_drop_prob <= 0.0:
            return modality_mask
        active_counts = modality_mask.sum(dim=-1, keepdim=True)
        # Drop secondary modalities only when >= 2 modalities are active on that row.
        drop_draw = (torch.rand_like(modality_mask, dtype=torch.float32) < self.modality_drop_prob) & modality_mask
        # Never drop tabular if it would leave 0 active modalities.
        updated = modality_mask & (~drop_draw)
        fallback = updated.sum(dim=-1, keepdim=True) == 0
        eff = torch.where(fallback, modality_mask, updated)
        return torch.where(active_counts <= 1, modality_mask, eff)

    def forward(
        self,
        embeddings: tuple[torch.Tensor, torch.Tensor, torch.Tensor],
        modality_mask: torch.Tensor,
    ) -> tuple[torch.Tensor, torch.Tensor]:
        eff_mask = self._effective_mask(modality_mask)
        masked_embs = [
            norm(emb) * eff_mask[:, idx : idx + 1].to(torch.float32)
            for idx, (norm, emb) in enumerate(zip(self.norms, embeddings, strict=True))
        ]
        stacked = torch.stack(masked_embs, dim=1)

        gate_in = torch.cat((*masked_embs, eff_mask.to(torch.float32)), dim=-1)
        raw_logits = self.gate_net(gate_in)
        any_active = eff_mask.any(dim=-1, keepdim=True)
        masked_logits = torch.where(eff_mask, raw_logits, torch.full_like(raw_logits, -1e9))
        soft = F.softmax(masked_logits, dim=-1) * eff_mask.to(torch.float32)
        weights = torch.where(any_active, soft / (soft.sum(dim=-1, keepdim=True) + 1e-8), torch.zeros_like(soft))

        weighted_sum = (stacked * weights.unsqueeze(-1)).sum(dim=1)

        pair_acc = torch.zeros_like(weighted_sum)
        pair_count = torch.zeros((weighted_sum.shape[0], 1), device=weighted_sum.device, dtype=torch.float32)
        for i in range(3):
            for j in range(i + 1, 3):
                both = (eff_mask[:, i] & eff_mask[:, j]).to(torch.float32).unsqueeze(-1)
                pair_acc = pair_acc + both * self.pair_proj(masked_embs[i] * masked_embs[j])
                pair_count = pair_count + both
        pair_feat = pair_acc / pair_count.clamp(min=1.0)
        fused = self.out_proj(torch.cat((weighted_sum, pair_feat), dim=-1))
        fused = fused * any_active.to(torch.float32)
        return fused, weights


class GraphMAEDecoderV3(nn.Module):
    """Reconstruct masked 23D structural node features from contextualized graph embeddings."""

    def __init__(self, hidden_dim: int = 128, node_dim: int = 23) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.GELU(),
            nn.Linear(hidden_dim, node_dim),
        )

    def forward(self, h_nodes: torch.Tensor) -> torch.Tensor:
        return self.net(h_nodes)


class TabularMAEDecoderV3(nn.Module):
    """Reconstruct masked normalized tabular features from tabular latent state."""

    def __init__(self, hidden_dim: int = 128, tab_dim: int = 32) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.GELU(),
            nn.Linear(hidden_dim, tab_dim),
        )

    def forward(self, h_tab: torch.Tensor) -> torch.Tensor:
        return self.net(h_tab)


class PDFTransGraphV3(nn.Module):
    """Multimodal tabular + bidirectional graph + AST detector with SSL heads."""

    def __init__(self, config: TransGraphV3Config) -> None:
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
        self.graph_encoder = BidirectionalHeteroGraphEncoderV3(
            node_dim=config.node_dim,
            hidden_dim=h,
            num_layers=config.num_graph_layers,
            num_node_types=config.num_node_types,
            num_base_relations=config.num_base_relations,
            dropout=config.dropout,
        )
        self.ast_encoder = ASTSemanticEncoderV3(
            ast_dim=config.ast_dim,
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

        # SSL projection and reconstruction heads (excluded from supervised inference params if desired).
        self.tab_ssl_proj = nn.Sequential(nn.Linear(h, h), nn.LayerNorm(h))
        self.graph_ssl_proj = nn.Sequential(nn.Linear(h, h), nn.LayerNorm(h))
        self.tab_mae_decoder = TabularMAEDecoderV3(h, config.tab_dim)
        self.graph_mae_decoder = GraphMAEDecoderV3(h, config.node_dim)

    def resolve_modality_mask(
        self,
        batch_size: int,
        graph_present: torch.Tensor,
        ast_missing: torch.Tensor | None,
        explicit_mask: torch.Tensor | None,
        device: torch.device,
    ) -> torch.Tensor:
        if explicit_mask is not None:
            mask = explicit_mask.to(device=device, dtype=torch.bool).clone()
        else:
            has_tab = torch.ones((batch_size,), device=device, dtype=torch.bool)
            has_ast = (
                ~ast_missing.to(torch.bool).all(dim=-1)
                if ast_missing is not None
                else torch.zeros((batch_size,), device=device, dtype=torch.bool)
            )
            mask = torch.stack((has_tab, graph_present.to(torch.bool), has_ast), dim=-1)
        mask[:, 0] &= self.config.enable_tab
        mask[:, 1] &= self.config.enable_graph
        mask[:, 2] &= self.config.enable_ast
        return mask

    def forward(
        self,
        tab_x: torch.Tensor,
        tab_missing: torch.Tensor | None = None,
        ast_x: torch.Tensor | None = None,
        ast_missing: torch.Tensor | None = None,
        node_x: torch.Tensor | None = None,
        node_type: torch.Tensor | None = None,
        edge_index: torch.Tensor | None = None,
        edge_rel: torch.Tensor | None = None,
        graph_batch: torch.Tensor | None = None,
        modality_mask: torch.Tensor | None = None,
    ) -> dict[str, torch.Tensor]:
        batch_size = tab_x.shape[0]
        device = tab_x.device

        if self.config.enable_tab:
            e_tab = self.tab_encoder(tab_x, tab_missing if self.config.use_missing_mask else None)
        else:
            e_tab = torch.zeros((batch_size, self.config.hidden_dim), device=device, dtype=torch.float32)

        if self.config.enable_graph:
            e_graph, graph_present = self.graph_encoder(
                node_x, node_type, edge_index, edge_rel, graph_batch, batch_size
            )
        else:
            e_graph = torch.zeros((batch_size, self.config.hidden_dim), device=device, dtype=torch.float32)
            graph_present = torch.zeros((batch_size,), device=device, dtype=torch.bool)

        if self.config.enable_ast and ast_x is not None and ast_missing is not None:
            e_ast = self.ast_encoder(ast_x, ast_missing)
        else:
            e_ast = torch.zeros((batch_size, self.config.hidden_dim), device=device, dtype=torch.float32)

        eff_mask = self.resolve_modality_mask(batch_size, graph_present, ast_missing, modality_mask, device)
        fused, weights = self.fusion((e_tab, e_graph, e_ast), eff_mask)
        logits = self.classifier(fused).squeeze(-1)
        return {
            "logits": logits,
            "weights": weights,
            "modality_mask": eff_mask,
            "fused": fused,
            "tab_emb": e_tab,
            "graph_emb": e_graph,
            "ast_emb": e_ast,
            "tab_aux_logits": self.tab_aux_head(e_tab).squeeze(-1),
            "graph_aux_logits": self.graph_aux_head(e_graph).squeeze(-1),
        }

    def ssl_loss(
        self,
        tab_x: torch.Tensor,
        tab_missing: torch.Tensor | None = None,
        node_x: torch.Tensor | None = None,
        node_type: torch.Tensor | None = None,
        edge_index: torch.Tensor | None = None,
        edge_rel: torch.Tensor | None = None,
        graph_batch: torch.Tensor | None = None,
        *,
        tab_mask_ratio: float = 0.25,
        node_mask_ratio: float = 0.25,
        temperature: float = 0.2,
    ) -> dict[str, torch.Tensor]:
        """Self-supervised Tabular MAE + GraphMAE + cross-modal InfoNCE loss."""
        batch_size = tab_x.shape[0]
        device = tab_x.device

        # 1. Tabular MAE (reconstruct observed masked tabular entries)
        if self.config.enable_tab:
            observed = (~tab_missing.to(torch.bool)) if tab_missing is not None else torch.ones_like(tab_x, dtype=torch.bool)
            tab_ssl_mask = (torch.rand_like(tab_x) < tab_mask_ratio) & observed
            e_tab_masked = self.tab_encoder(
                tab_x,
                tab_missing if self.config.use_missing_mask else None,
                ssl_mask=tab_ssl_mask,
            )
            tab_recon = self.tab_mae_decoder(e_tab_masked)
            if tab_ssl_mask.any():
                loss_tab_mae = F.smooth_l1_loss(tab_recon[tab_ssl_mask], tab_x[tab_ssl_mask])
            else:
                loss_tab_mae = torch.zeros((), device=device)
        else:
            e_tab_masked = torch.zeros((batch_size, self.config.hidden_dim), device=device)
            loss_tab_mae = torch.zeros((), device=device)

        # 2. GraphMAE (reconstruct masked 23D structural node vectors)
        if self.config.enable_graph and node_x is not None and node_type is not None and graph_batch is not None and node_x.shape[0] > 0:
            node_mask = torch.rand((node_x.shape[0],), device=device) < node_mask_ratio
            e_graph_masked, graph_present, h_nodes = self.graph_encoder(
                node_x,
                node_type,
                edge_index,
                edge_rel,
                graph_batch,
                batch_size,
                node_mask=node_mask,
                return_node_embeddings=True,
            )
            if node_mask.any():
                node_recon = self.graph_mae_decoder(h_nodes[node_mask])
                loss_graph_mae = F.smooth_l1_loss(node_recon, node_x[node_mask])
            else:
                loss_graph_mae = torch.zeros((), device=device)
        else:
            e_graph_masked = torch.zeros((batch_size, self.config.hidden_dim), device=device)
            graph_present = torch.zeros((batch_size,), device=device, dtype=torch.bool)
            loss_graph_mae = torch.zeros((), device=device)

        # 3. Cross-modal InfoNCE when both tabular and graph are active
        loss_clip = torch.zeros((), device=device)
        if self.config.enable_tab and self.config.enable_graph and int(graph_present.sum()) >= 2:
            zt = F.normalize(self.tab_ssl_proj(e_tab_masked[graph_present]), dim=-1)
            zg = F.normalize(self.graph_ssl_proj(e_graph_masked[graph_present]), dim=-1)
            sim = (zt @ zg.T) / temperature
            labels = torch.arange(sim.shape[0], device=device)
            loss_clip = 0.5 * (F.cross_entropy(sim, labels) + F.cross_entropy(sim.T, labels))

        total = loss_tab_mae + loss_graph_mae + 0.5 * loss_clip
        return {
            "total": total,
            "tab_mae": loss_tab_mae,
            "graph_mae": loss_graph_mae,
            "clip": loss_clip,
        }


def save_v3_weights_npz(model: PDFTransGraphV3, path: Any) -> None:
    """Persist PyTorch state_dict cleanly as compressed NumPy arrays (no pickle)."""
    arrays: dict[str, np.ndarray] = {}
    for name, tensor in model.state_dict().items():
        arrays[f"param::{name}"] = tensor.detach().cpu().numpy()
    np.savez_compressed(path, **arrays)


def load_v3_weights_npz(model: PDFTransGraphV3, path: Any, *, map_location: str | torch.device = "cpu") -> None:
    """Load compressed NumPy weights strictly with allow_pickle=False."""
    state = {}
    with np.load(path, allow_pickle=False) as archive:
        for key in archive.files:
            if not key.startswith("param::"):
                continue
            param_name = key[len("param::") :]
            state[param_name] = torch.from_numpy(np.array(archive[key], copy=True)).to(map_location)
    model.load_state_dict(state, strict=True)

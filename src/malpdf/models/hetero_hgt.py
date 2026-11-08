import torch
import torch.nn as nn
import torch.nn.functional as F
def global_mean_pool(x: torch.Tensor, batch: torch.Tensor) -> torch.Tensor:
    num_graphs = int(batch.max().item()) + 1 if batch.numel() > 0 else 1
    out = torch.zeros(num_graphs, x.size(-1), device=x.device, dtype=x.dtype)
    counts = torch.zeros(num_graphs, 1, device=x.device, dtype=x.dtype)
    out.index_add_(0, batch, x)
    counts.index_add_(0, batch, torch.ones_like(x[:, :1]))
    return out / counts.clamp(min=1.0)


def global_max_pool(x: torch.Tensor, batch: torch.Tensor) -> torch.Tensor:
    num_graphs = int(batch.max().item()) + 1 if batch.numel() > 0 else 1
    out = torch.full((num_graphs, x.size(-1)), -float("inf"), device=x.device, dtype=x.dtype)
    expanded_batch = batch.unsqueeze(-1).expand_as(x)
    return out.scatter_reduce(0, expanded_batch, x, reduce="amax", include_self=False)


class RelationAwareMessagePassing(nn.Module):
    def __init__(self, in_dim: int, out_dim: int, num_relations: int = 8, num_heads: int = 4):
        super().__init__()
        self.in_dim = in_dim
        self.out_dim = out_dim
        self.num_relations = num_relations
        self.num_heads = num_heads
        self.head_dim = out_dim // num_heads
        self.q_proj = nn.Linear(in_dim, out_dim)
        self.k_proj = nn.Linear(in_dim, out_dim)
        self.v_proj = nn.Linear(in_dim, out_dim)
        self.rel_emb = nn.Embedding(num_relations, out_dim)
        self.out_proj = nn.Linear(out_dim, out_dim)
        self.norm = nn.LayerNorm(out_dim)
        self.last_edge_alpha: torch.Tensor | None = None

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor, edge_rel: torch.Tensor) -> torch.Tensor:
        if edge_index.numel() == 0:
            self.last_edge_alpha = torch.zeros((0, self.num_heads), device=x.device)
            return self.norm(x)
        src, dst = edge_index[0], edge_index[1]
        q = self.q_proj(x).view(-1, self.num_heads, self.head_dim)
        k = self.k_proj(x).view(-1, self.num_heads, self.head_dim)
        v = self.v_proj(x).view(-1, self.num_heads, self.head_dim)
        r = self.rel_emb(edge_rel).view(-1, self.num_heads, self.head_dim)
        k_msg = k[src] + r
        v_msg = v[src] + r
        score = (q[dst] * k_msg).sum(dim=-1) / (self.head_dim**0.5)
        score = torch.clamp(score, -10.0, 10.0)
        attn = torch.exp(score)
        norm_factor = torch.zeros(x.size(0), self.num_heads, device=x.device).index_add_(0, dst, attn) + 1e-6
        alpha = attn / norm_factor[dst]
        self.last_edge_alpha = alpha.detach()
        weighted_v = v_msg * alpha.unsqueeze(-1)
        aggr = torch.zeros(x.size(0), self.num_heads, self.head_dim, device=x.device).index_add_(0, dst, weighted_v)
        aggr_flat = aggr.view(-1, self.out_dim)
        out = self.out_proj(aggr_flat)
        return self.norm(x + F.silu(out))


class HeteroGraphTransformer(nn.Module):
    def __init__(self, node_in_dim: int = 19, hidden_dim: int = 128, num_node_types: int = 9, num_relations: int = 8):
        super().__init__()
        self.hidden_dim = hidden_dim
        self.node_type_emb = nn.Embedding(num_node_types, hidden_dim)
        self.node_feat_proj = nn.Linear(node_in_dim, hidden_dim)
        self.input_norm = nn.LayerNorm(hidden_dim)
        self.layer1 = RelationAwareMessagePassing(hidden_dim, hidden_dim, num_relations=num_relations)
        self.layer2 = RelationAwareMessagePassing(hidden_dim, hidden_dim, num_relations=num_relations)
        self.pool_proj = nn.Linear(hidden_dim * 2, hidden_dim)
        self.out_norm = nn.LayerNorm(hidden_dim)

    def forward(
        self,
        node_features: torch.Tensor,
        node_types: torch.Tensor,
        edge_index: torch.Tensor,
        edge_rel: torch.Tensor,
        batch: torch.Tensor,
    ) -> torch.Tensor:
        feat_emb = self.node_feat_proj(node_features)
        type_emb = self.node_type_emb(node_types)
        x = self.input_norm(feat_emb + type_emb)
        x = self.layer1(x, edge_index, edge_rel)
        x = self.layer2(x, edge_index, edge_rel)
        mean_p = global_mean_pool(x, batch)
        max_p = global_max_pool(x, batch)
        pooled = torch.cat([mean_p, max_p], dim=-1)
        out = self.pool_proj(pooled)
        return self.out_norm(F.silu(out))


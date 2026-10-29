import torch
import torch.nn as nn
import torch.nn.functional as F


class CrossModalAttentionFusion(nn.Module):
    def __init__(self, hidden_dim: int = 128, num_heads: int = 4):
        super().__init__()
        self.hidden_dim = hidden_dim
        self.num_heads = num_heads
        self.q_proj = nn.Linear(hidden_dim, hidden_dim)
        self.k_proj = nn.Linear(hidden_dim, hidden_dim)
        self.v_proj = nn.Linear(hidden_dim, hidden_dim)
        self.mha = nn.MultiheadAttention(embed_dim=hidden_dim, num_heads=num_heads, batch_first=True)
        self.fusion_mlp = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim * 2),
            nn.LayerNorm(hidden_dim * 2),
            nn.SiLU(),
            nn.Dropout(0.1),
            nn.Linear(hidden_dim * 2, hidden_dim * 2),
        )
        self.out_norm = nn.LayerNorm(hidden_dim * 2)

    def forward(
        self, h_graph: torch.Tensor, h_seq: torch.Tensor, h_tab: torch.Tensor
    ) -> tuple[torch.Tensor, torch.Tensor]:
        q = self.q_proj(h_tab).unsqueeze(1)
        kv_context = torch.stack([h_graph, h_seq], dim=1)
        k = self.k_proj(kv_context)
        v = self.v_proj(kv_context)
        attn_out, attn_weights = self.mha(q, k, v)
        attn_out = attn_out.squeeze(1)
        combined = torch.cat([h_tab, attn_out], dim=-1)
        fused = self.out_norm(combined + self.fusion_mlp(combined))
        return fused, attn_weights


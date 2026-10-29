import math
import torch
import torch.nn as nn
import torch.nn.functional as F


class RotaryPositionalEmbedding(nn.Module):
    def __init__(self, dim: int, max_seq_len: int = 256):
        super().__init__()
        inv_freq = 1.0 / (10000 ** (torch.arange(0, dim, 2).float() / dim))
        self.register_buffer("inv_freq", inv_freq)
        self.max_seq_len = max_seq_len

    def forward(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        seq_len = x.size(1)
        t = torch.arange(seq_len, device=x.device).type_as(self.inv_freq)
        freqs = torch.einsum("i,j->ij", t, self.inv_freq)
        emb = torch.cat((freqs, freqs), dim=-1)
        return emb.cos(), emb.sin()


def apply_rotary_pos_emb(x: torch.Tensor, cos: torch.Tensor, sin: torch.Tensor) -> torch.Tensor:
    d = x.size(-1) // 2
    x1, x2 = x[..., :d], x[..., d:]
    rotate_half = torch.cat((-x2, x1), dim=-1)
    return (x * cos.unsqueeze(0)) + (rotate_half * sin.unsqueeze(0))


class ASTSequenceTransformer(nn.Module):
    def __init__(self, vocab_size: int = 64, hidden_dim: int = 128, num_layers: int = 2, max_len: int = 256):
        super().__init__()
        self.hidden_dim = hidden_dim
        self.token_emb = nn.Embedding(vocab_size, hidden_dim)
        self.rope = RotaryPositionalEmbedding(hidden_dim, max_seq_len=max_len)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=hidden_dim,
            nhead=4,
            dim_feedforward=hidden_dim * 2,
            dropout=0.1,
            activation="gelu",
            batch_first=True,
            norm_first=True,
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.pool_attn = nn.Linear(hidden_dim, 1)
        self.norm = nn.LayerNorm(hidden_dim)

    def forward(self, tokens: torch.Tensor) -> torch.Tensor:
        if tokens.dim() == 1:
            tokens = tokens.unsqueeze(0)
        h = self.token_emb(tokens)
        cos, sin = self.rope(h)
        h_rope = apply_rotary_pos_emb(h, cos, sin)
        encoded = self.encoder(h_rope)
        attn_weights = F.softmax(self.pool_attn(encoded), dim=1)
        pooled = (encoded * attn_weights).sum(dim=1)
        return self.norm(pooled)

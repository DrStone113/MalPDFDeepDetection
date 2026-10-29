import torch
import torch.nn as nn
import torch.nn.functional as F


class TabularResidualBlock(nn.Module):
    def __init__(self, hidden_dim: int, dropout: float = 0.2):
        super().__init__()
        self.fc1 = nn.Linear(hidden_dim, hidden_dim)
        self.norm1 = nn.LayerNorm(hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, hidden_dim)
        self.norm2 = nn.LayerNorm(hidden_dim)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        residual = x
        h = F.silu(self.norm1(self.fc1(x)))
        h = self.dropout(h)
        h = self.norm2(self.fc2(h))
        return F.silu(residual + h)


class TabularResNet(nn.Module):
    def __init__(self, in_features: int = 35, hidden_dim: int = 128, num_blocks: int = 2, dropout: float = 0.2):
        super().__init__()
        self.input_layer = nn.Linear(in_features, hidden_dim)
        self.input_norm = nn.LayerNorm(hidden_dim)
        self.blocks = nn.ModuleList([TabularResidualBlock(hidden_dim, dropout=dropout) for _ in range(num_blocks)])
        self.out_norm = nn.LayerNorm(hidden_dim)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        h = F.silu(self.input_norm(self.input_layer(x)))
        for block in self.blocks:
            h = block(h)
        return self.out_norm(h)
